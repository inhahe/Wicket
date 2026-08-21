"""User state management, message routing between upstream and downstream."""

from __future__ import annotations
import asyncio
import collections
import logging
import time
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Optional

from irc_parser import IRCMessage
from cap import UPSTREAM_REQUIRED_CAPS
from config import UserConfig, NetworkConfig, hash_password, set_user_password, update_autojoin
from database import Database

if TYPE_CHECKING:
    from upstream import UpstreamConnection
    from downstream import DownstreamConnection

logger = logging.getLogger(__name__)

# How long a reply route stays valid before expiring (seconds).
# If the server hasn't replied by then, subsequent numerics are broadcast.
ROUTE_TIMEOUT_SECS = 300

# Maps a client command to (reply_numerics, end_numerics, error_numerics).
# When a client sends one of these commands, the bouncer registers a pending
# route. Replies matching reply_numerics are sent only to the originating
# client. The route is cleared when an end_numeric or error_numeric arrives.
ROUTED_REPLIES: dict[str, tuple[set[str], set[str], set[str]]] = {
    "WHOIS": (
        {"311", "312", "313", "317", "319", "301", "330", "338", "671", "307", "320", "276"},
        {"318"},  # RPL_ENDOFWHOIS
        {"263", "401", "402"},  # 263 = ERR_TRYAGAIN; ERR_NOSUCHNICK, ERR_NOSUCHSERVER
    ),
    "WHOWAS": (
        {"314", "312"},
        {"369"},  # RPL_ENDOFWHOWAS
        {"406"},  # ERR_WASNOSUCHNICK
    ),
    "WHO": (
        {"352", "354"},  # RPL_WHOREPLY, RPL_WHOSPCRPL (for WHOX)
        {"315"},  # RPL_ENDOFWHO
        {"263", "401", "402"},  # 263 = ERR_TRYAGAIN (rate-limited)
    ),
    "LIST": (
        {"322"},  # RPL_LIST
        {"323"},  # RPL_LISTEND
        {"263"},  # 263 = ERR_TRYAGAIN (rate-limited)
    ),
    "NAMES": (
        {"353"},  # RPL_NAMREPLY
        {"366"},  # RPL_ENDOFNAMES
        set(),
    ),
    "BANLIST": (  # MODE #chan +b
        {"367"},  # RPL_BANLIST
        {"368"},  # RPL_ENDOFBANLIST
        {"401", "403", "442", "482"},
    ),
    "LINKS": (
        {"364"},  # RPL_LINKS
        {"365"},  # RPL_ENDOFLINKS
        {"263"},  # 263 = ERR_TRYAGAIN (rate-limited)
    ),
    "INFO": (
        {"371"},  # RPL_INFO
        {"374"},  # RPL_ENDOFINFO
        set(),
    ),
    "STATS": (
        {"211", "212", "213", "214", "215", "216", "217", "218", "240", "241", "242", "243", "244", "249"},
        {"219"},  # RPL_ENDOFSTATS
        {"402", "481"},
    ),
    "LUSERS": (
        {"251", "252", "253", "254", "255", "265", "266"},
        set(),  # No end marker; single burst, routed on first non-match
        set(),
    ),
    "MOTD": (
        {"375", "372"},
        {"376"},  # RPL_ENDOFMOTD
        {"422"},  # ERR_NOMOTD
    ),
    "VERSION": (
        {"351"},
        set(),
        {"402"},
    ),
    "TIME": (
        {"391"},
        set(),
        {"402"},
    ),
    "TRACE": (
        {"200", "201", "202", "203", "204", "205", "206", "207", "208", "209", "261"},
        {"262"},  # RPL_TRACEEND
        {"402"},
    ),
    "HELP": (
        {"704", "705"},
        {"706"},  # RPL_ENDOFHELP
        {"524"},  # ERR_HELPNOTFOUND
    ),
    "ISON": (
        {"303"},
        set(),
        set(),
    ),
    "USERHOST": (
        {"302"},
        set(),
        set(),
    ),
    "MODE": (
        # Plain MODE #chan query returns 324 (+ sometimes 329)
        # User mode query returns 221
        # Consumed on first reply since there's no reliable end marker
        {"324", "329", "221"},
        set(),
        {"401", "403", "442", "482", "472", "501", "502"},
    ),
    "TOPIC": (
        {"332", "333"},
        set(),
        {"331", "401", "403", "442", "482"},  # 331 = RPL_NOTOPIC (also a valid response)
    ),
    "INVITE": (
        {"341"},  # RPL_INVITING
        set(),
        {"401", "403", "442", "443", "482"},
    ),
}

# Build a reverse index: numeric -> set of commands that expect it.
# Used to quickly check if a numeric should be routed.
_NUMERIC_TO_COMMANDS: dict[str, set[str]] = {}
for _cmd, (_replies, _ends, _errors) in ROUTED_REPLIES.items():
    for _num in _replies | _ends | _errors:
        _NUMERIC_TO_COMMANDS.setdefault(_num, set()).add(_cmd)


@dataclass
class PendingEcho:
    """A message a client sent, awaiting the upstream's echo-message copy.

    On a network with echo-message the echo is the authoritative copy: it
    carries the server's msgid and server-time, and it is what every other
    network participant saw. Wicket therefore stores *only* the echo, and this
    records what to expect so the echo can be matched back to its sender.

    `message` is Wicket's own reconstruction of the line, used as a fallback if
    the echo never arrives, so a dropped echo costs a little latency rather
    than the message's place in history.
    """

    target: str  # lowercased
    text: str
    message: IRCMessage
    sender: Optional["DownstreamConnection"]
    created_at: float


@dataclass
class ChannelState:
    name: str
    topic: Optional[str] = None
    topic_set_by: Optional[str] = None
    topic_set_at: Optional[float] = None
    members: dict[str, str] = field(default_factory=dict)  # nick -> prefix (e.g., "@", "+")
    joined: bool = True


class User:
    def __init__(self, config: UserConfig, db: Database, server_name: str, config_path: str = ""):
        self.config = config
        self.username = config.username
        self.db = db
        self.server_name = server_name
        self.config_path = config_path  # Path to YAML config for password updates

        # Per-network state
        self.upstreams: dict[str, UpstreamConnection] = {}
        self.channels: dict[str, dict[str, ChannelState]] = {}  # network -> {channel -> state}
        self.downstreams: dict[str, list[DownstreamConnection]] = {}  # network -> [downstream]
        self._pending_keys: dict[str, dict[str, str]] = {}  # network -> {channel_lower -> key}
        # Messages a client sent that we are waiting for the upstream to echo
        # back (networks with echo-message). We deliberately do not store or
        # forward at send time on those networks -- the echo is the single
        # authoritative copy, carrying the server's msgid and server-time.
        # Storing both is what made every own message appear twice.
        #
        # The sender is remembered only so the echo can be withheld from a
        # client that did its own local echo (i.e. one without echo-message).
        self._pending_echoes: dict[str, collections.deque[PendingEcho]] = {}

        # Reply routing: maps network -> deque of (downstream, command, reply_nums, end_nums, error_nums, created_at)
        # Uses a deque so we process in FIFO order (oldest pending route first).
        # Routes expire after ROUTE_TIMEOUT_SECS; expired replies are broadcast to all clients.
        self._pending_routes: dict[str, collections.deque[tuple[
            DownstreamConnection, str, set[str], set[str], set[str], float
        ]]] = {}

        # Background task that periodically persists read positions for connected
        # clients (see _read_flush_loop). Read positions used to advance only on a
        # clean disconnect, which is lost when a system restart kills both the
        # bouncer and the client -- the cause of the whole backlog replaying on
        # every start.
        self._read_flush_task: Optional[asyncio.Task] = None

    def get_delivery_source(self) -> str:
        """Get the source for bouncer-generated messages."""
        if self.config.delivery_source == "server":
            return self.server_name
        nick = self.config.delivery_source
        return f"{nick}!{nick}@{self.server_name}"

    def get_delivery_command(self) -> str:
        return "NOTICE" if self.config.delivery == "notice" else "PRIVMSG"

    def deliver_bouncer_message(self, ds: DownstreamConnection, text: str) -> None:
        """Send a bouncer status message to a specific downstream client."""
        source = self.get_delivery_source()
        cmd = self.get_delivery_command()
        # When using PRIVMSG from the server name, prefix so the user knows
        # it's bouncer-generated and not a real message from another user.
        if cmd == "PRIVMSG" and self.config.delivery_source == "server":
            text = f"[wicket] {text}"
        msg = IRCMessage(
            command=cmd,
            params=[ds.nick, text],
            source=source,
        )
        asyncio.ensure_future(ds.send(msg))

    def deliver_channel_bouncer_message(
        self, ds: DownstreamConnection, channel: str, text: str
    ) -> None:
        """Send a bouncer-generated message into a channel window.

        Used by activity replay so events appear in context. Always sent as
        PRIVMSG (not NOTICE) regardless of the user's `delivery` setting,
        because NOTICE in a channel renders awkwardly in most clients and
        some treat it as an external/server message.
        """
        source = self.get_delivery_source()
        msg = IRCMessage(
            command="PRIVMSG",
            params=[channel, text],
            source=source,
        )
        asyncio.ensure_future(ds.send(msg))

    async def attach_downstream(
        self, ds: DownstreamConnection, network: str, identifier: str
    ) -> bool:
        """Attach a downstream client to a network. Returns True on success."""
        if network not in self.upstreams:
            return False

        upstream = self.upstreams[network]
        if network not in self.downstreams:
            self.downstreams[network] = []
        self.downstreams[network].append(ds)

        ds.user = self
        ds.network = network
        ds.identifier = identifier
        ds.upstream = upstream

        capped: dict[str, int] = {}
        try:
            # Send welcome (degraded if upstream is disconnected)
            await self._send_welcome(ds, upstream)

            if upstream.connected and upstream.registered:
                # Replay channel state
                if network in self.channels:
                    for chan_name, chan_state in self.channels[network].items():
                        if chan_state.joined:
                            await self._replay_channel(ds, upstream, chan_state)

                # Replay backscroll
                capped = await self._replay_backscroll(ds, network, identifier)

                # Auto-replay activity if enabled
                nc = self.config.networks.get(network)
                if nc and nc.replay_activity:
                    await self._replay_activity(ds, network, identifier, nc)

                self.deliver_bouncer_message(ds, f"Connected to {network}")
            else:
                self.deliver_bouncer_message(
                    ds, f"Attached to {network} (upstream is not connected — "
                        f"use CONNECT {network} to connect)")

                # Still replay backscroll from previous sessions
                capped = await self._replay_backscroll(ds, network, identifier)

                nc = self.config.networks.get(network)
                if nc and nc.replay_activity:
                    await self._replay_activity(ds, network, identifier, nc)
        except Exception:
            logger.exception("Error during attach for %s/%s", self.username, network)
            return False

        # Mark everything we just replayed as read so the same backscroll isn't
        # replayed again on the next connect. Read positions previously advanced
        # only on a clean disconnect (which the client rarely gets to do -- a
        # system restart kills it first), so they froze and the last few days of
        # messages replayed on every start.
        try:
            await self._update_read_positions(ds, capped=capped)
        except Exception:
            logger.exception("Error marking replay read for %s/%s", self.username, network)
        # Ask for confirmation of everything just replayed. Until the PONG comes
        # back nothing is marked read, so a client that dies mid-replay gets the
        # same backscroll again rather than losing it.
        try:
            await ds.send_confirm_ping()
        except Exception:
            logger.exception("Error pinging %s/%s after replay", self.username, network)
        # Keep read positions current for the life of this connection so an
        # unclean shutdown loses at most one flush interval, not days.
        self._ensure_read_flush_task()

        return True

    async def detach_downstream(self, ds: DownstreamConnection) -> None:
        """Detach a downstream client."""
        if ds.network and ds.network in self.downstreams:
            try:
                self.downstreams[ds.network].remove(ds)
            except ValueError:
                pass


        # Messages this client sent may still be awaiting their echo. Keep
        # them -- they still have to be stored -- but forget the sender.
        self._forget_pending_echoes(ds)

        # Update read positions for all targets
        if ds.network and ds.identifier:
            try:
                await self._update_read_positions(ds)
            except Exception:
                logger.exception("Error updating read positions for %s", ds.nick)

    def _confirmed_watermark(
        self, network: str, identifier: str, including: DownstreamConnection
    ) -> int:
        """Lowest confirmed-delivery id across every socket sharing an identifier.

        Read positions are keyed by identifier, not by socket, so a position may
        only advance as far as the least caught-up socket using that identifier.
        Taking the maximum would mark messages read for a second, lagging client
        that never received them.
        """
        watermarks = [
            other.confirmed_id
            for other in self.downstreams.get(network, [])
            if other.identifier == identifier
        ]
        if including not in self.downstreams.get(network, []):
            # Detaching client: already removed from the list, still counts.
            watermarks.append(including.confirmed_id)
        return min(watermarks) if watermarks else 0

    async def _update_read_positions(
        self, ds: DownstreamConnection, capped: dict[str, int] | None = None
    ) -> None:
        """Persist read positions as far as the client has *confirmed* delivery.

        This deliberately does not use the latest stored id. Being attached is
        not evidence of receipt: a phone that loses its network keeps a socket
        that accepts writes for minutes before the OS reports the failure, and
        everything written into it in the meantime is lost. Advancing to the
        latest id on a timer marked those messages read, so they were never
        replayed and were gone for good.

        `ds.confirmed_id` only moves when a PONG proves the client parsed past
        that point, so anything unacknowledged stays unread and replays on the
        next attach.

        `capped` maps target -> highest id actually delivered for targets whose
        attach-time replay was truncated at REPLAY_LIMIT.
        """
        network = ds.network
        if not network:
            return

        confirmed = self._confirmed_watermark(network, ds.identifier, ds)
        if confirmed <= 0:
            # Nothing confirmed yet (client just attached and has not answered a
            # ping). Writing anything here would be a guess.
            logger.debug("No confirmed delivery yet for %s/%s/%s; not advancing",
                         self.username, network, ds.identifier)
            return

        targets = await self.db.get_all_targets(self.username, network)
        logger.debug("Saving read positions for %s/%s/%s: %d targets (confirmed=%d)",
                      self.username, network, ds.identifier, len(targets), confirmed)
        for target in targets:
            latest = await self.db.get_latest_message_id(self.username, network, target)
            if latest is None:
                continue
            # Ids are globally ordered, so anything stored for this target at or
            # below the confirmed watermark reached the client.
            new_pos = min(latest, confirmed)
            if capped and target.lower() in capped:
                new_pos = min(new_pos, capped[target.lower()])
            if new_pos <= 0:
                continue
            existing = await self.db.get_read_position(
                self.username, network, ds.identifier, target
            )
            if existing is not None and new_pos <= existing:
                continue  # never move a read position backwards
            await self.db.set_read_position(
                self.username, network, ds.identifier, target, new_pos
            )
            logger.debug("  read position %s/%s/%s/%s = %d",
                         self.username, network, ds.identifier, target, new_pos)

    # How often to persist read positions for connected clients (seconds). This
    # bounds how much backlog can replay after an unclean shutdown (e.g. a system
    # restart that kills the bouncer and client before either can save cleanly).
    READ_FLUSH_INTERVAL = 30

    def _ensure_read_flush_task(self) -> None:
        """Start the periodic read-position flush task if it isn't running."""
        if self._read_flush_task is None or self._read_flush_task.done():
            self._read_flush_task = asyncio.create_task(self._read_flush_loop())

    async def _read_flush_loop(self) -> None:
        """Periodically persist read positions for every connected downstream.

        Persisting on a timer means an unclean shutdown loses at most one
        interval of backscroll instead of everything since the last clean
        disconnect (which, in practice, never happened -- so the backlog grew
        for days and replayed on every start).

        Note what this loop must NOT do: assume that being attached means the
        client received anything. It once advanced every target to the latest
        stored id, which silently consumed messages written into sockets that
        were already dead. _update_read_positions now advances only to the
        PONG-confirmed watermark; this loop just drives the flush."""
        try:
            while True:
                await asyncio.sleep(self.READ_FLUSH_INTERVAL)
                # Piggyback the echo-timeout sweep: a message whose echo never
                # came back has to be stored eventually or it is lost.
                try:
                    await self._expire_pending_echoes()
                except Exception:
                    logger.exception("Error expiring pending echoes for %s", self.username)
                # Dedupe by (network, identifier): read positions are keyed that
                # way, so two sockets sharing an identifier need only one flush.
                seen: set[tuple[str, str]] = set()
                any_connected = False
                for dss in list(self.downstreams.values()):
                    for ds in list(dss):
                        if not ds.network or not ds.identifier:
                            continue
                        any_connected = True
                        key = (ds.network, ds.identifier)
                        if key in seen:
                            continue
                        seen.add(key)
                        try:
                            await self._update_read_positions(ds)
                        except Exception:
                            logger.exception(
                                "Error flushing read positions for %s/%s",
                                ds.network, ds.identifier)
                if not any_connected and not any(self._pending_echoes.values()):
                    # No clients attached and nothing owed to the database --
                    # stop; attach_downstream restarts us. Messages still
                    # waiting on an echo keep the loop alive, because they are
                    # unstored: dropping the loop here would lose them if no
                    # client ever reattached.
                    break
        except asyncio.CancelledError:
            pass
        finally:
            self._read_flush_task = None

    async def _send_welcome(self, ds: DownstreamConnection, upstream: UpstreamConnection) -> None:
        """Send IRC welcome sequence to downstream client."""
        nick = upstream.nick or ds.nick or self.config.nick or self.username
        ds.nick = nick  # Sync so deliver_bouncer_message targets the right nick
        upstream_online = upstream.connected and upstream.registered

        # Retract caps that require upstream support but upstream doesn't have
        if upstream_online:
            unsupported = UPSTREAM_REQUIRED_CAPS - upstream.cap.enabled
        else:
            # Upstream is down — retract all upstream-dependent caps
            unsupported = UPSTREAM_REQUIRED_CAPS
        retract = unsupported & ds.cap.enabled
        if retract:
            await ds.send(IRCMessage(
                command="CAP", params=[nick, "DEL", " ".join(sorted(retract))],
                source=self.server_name,
            ))
            for cap in retract:
                ds.cap.enabled.discard(cap)

        # 001-003
        network_display = upstream.isupport.get("NETWORK") or upstream.network_name or self.server_name
        await ds.send(IRCMessage(
            command="001", params=[nick, f"Welcome to {network_display}, {nick}"],
            source=self.server_name,
        ))
        await ds.send(IRCMessage(
            command="002", params=[nick, f"Your host is {self.server_name}, running Wicket"],
            source=self.server_name,
        ))
        await ds.send(IRCMessage(
            command="003", params=[nick, "This server was created just for you"],
            source=self.server_name,
        ))

        # 004
        await ds.send(IRCMessage(
            command="004", params=[nick, self.server_name, "wicket-1.0", "iowrsz", "opsitnmlbvk"],
            source=self.server_name,
        ))

        # Replay 005 ISUPPORT
        if upstream.isupport:
            tokens = []
            for key, val in upstream.isupport.items():
                if val is not None:
                    tokens.append(f"{key}={val}")
                else:
                    tokens.append(key)
            # Send in groups of 13 (standard limit)
            for i in range(0, len(tokens), 13):
                batch = tokens[i : i + 13]
                await ds.send(IRCMessage(
                    command="005",
                    params=[nick] + batch + ["are supported by this server"],
                    source=self.server_name,
                ))

        # MOTD (minimal)
        await ds.send(IRCMessage(
            command="375", params=[nick, f"- {self.server_name} Message of the Day -"],
            source=self.server_name,
        ))
        await ds.send(IRCMessage(
            command="372", params=[nick, f"- Welcome to Wicket"],
            source=self.server_name,
        ))
        await ds.send(IRCMessage(
            command="376", params=[nick, "End of /MOTD command."],
            source=self.server_name,
        ))

    async def _replay_channel(
        self, ds: DownstreamConnection, upstream: UpstreamConnection, chan: ChannelState
    ) -> None:
        """Replay channel JOIN, TOPIC, and NAMES to a downstream client."""
        nick = upstream.nick
        source = f"{nick}!{upstream.username}@{self.server_name}"

        # JOIN
        await ds.send(IRCMessage(
            command="JOIN", params=[chan.name], source=source,
        ))

        # TOPIC
        if chan.topic:
            await ds.send(IRCMessage(
                command="332", params=[nick, chan.name, chan.topic],
                source=self.server_name,
            ))
            if chan.topic_set_by:
                ts = str(int(chan.topic_set_at)) if chan.topic_set_at else "0"
                await ds.send(IRCMessage(
                    command="333", params=[nick, chan.name, chan.topic_set_by, ts],
                    source=self.server_name,
                ))

        # NAMES
        names = []
        for member_nick, prefix in chan.members.items():
            names.append(f"{prefix}{member_nick}")
        if names:
            # Send in batches
            for i in range(0, len(names), 50):
                batch = names[i : i + 50]
                await ds.send(IRCMessage(
                    command="353", params=[nick, "=", chan.name, " ".join(batch)],
                    source=self.server_name,
                ))
        await ds.send(IRCMessage(
            command="366", params=[nick, chan.name, "End of /NAMES list."],
            source=self.server_name,
        ))

    # Messages replayed for a target this client identifier has never been
    # synced against (no read_positions row). See Database.get_replay_start_id.
    INITIAL_REPLAY_LINES = 200

    # Hard cap on messages replayed per target in a single attach. Anything
    # beyond this stays unread and replays on the next attach rather than being
    # silently skipped -- see the `capped` bookkeeping below.
    REPLAY_LIMIT = 4096

    async def _replay_backscroll(
        self, ds: DownstreamConnection, network: str, identifier: str
    ) -> dict[str, int]:
        """Replay unread messages to a downstream client.

        Returns a map of target -> highest replayed message id for targets whose
        replay hit REPLAY_LIMIT. The caller must not advance those read positions
        past the returned id, or the untransmitted remainder would be marked read
        and lost.
        """
        targets = await self.db.get_all_targets(self.username, network)
        has_batch = ds.cap.supports("batch")
        has_time = ds.cap.supports("server-time")
        capped: dict[str, int] = {}

        batch_id = None
        if has_batch:
            batch_id = f"backscroll-{int(time.time() * 1000)}"
            await ds.send(IRCMessage(
                command="BATCH", params=[f"+{batch_id}", "chathistory"],
                source=self.server_name,
            ))

        replayed = 0
        for target in targets:
            read_pos = await self.db.get_read_position(
                self.username, network, identifier, target
            )
            if read_pos is None:
                # No row at all: this identifier has never been synced against
                # this target, so every stored message looks unread. Replaying
                # from 0 would dump the whole archive for the target, which is
                # what made a first-time PM partner (or a fresh identifier)
                # replay thousands of lines. Bound it to a recent window.
                after_id = await self.db.get_replay_start_id(
                    self.username, network, target, self.INITIAL_REPLAY_LINES
                )
            else:
                after_id = read_pos
            messages = await self.db.get_messages_after(
                self.username, network, target, after_id, limit=self.REPLAY_LIMIT
            )
            if len(messages) >= self.REPLAY_LIMIT:
                # Truncated. Remember where we actually stopped so the caller
                # doesn't mark the untransmitted tail as read.
                capped[target.lower()] = messages[-1][0]
            logger.debug("Replay %s/%s/%s/%s: read_pos=%s, after_id=%d, found=%d msgs",
                         self.username, network, identifier, target,
                         read_pos, after_id, len(messages))
            for msg_id, timestamp, raw_line in messages:
                try:
                    replay_msg = IRCMessage.parse(raw_line)
                except (ValueError, IndexError):
                    continue

                # Only replay messages that don't conflict with channel state
                if replay_msg.command not in ("PRIVMSG", "NOTICE", "TOPIC"):
                    continue

                # Add server-time tag
                if has_time:
                    from datetime import datetime, timezone
                    dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    replay_msg.tags["time"] = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

                # Add batch tag
                if batch_id:
                    replay_msg.tags["batch"] = batch_id

                await ds.send(replay_msg)
                ds.note_written(msg_id)
                replayed += 1

        if batch_id:
            await ds.send(IRCMessage(
                command="BATCH", params=[f"-{batch_id}"],
                source=self.server_name,
            ))

        if replayed > 0:
            self.deliver_bouncer_message(ds, f"Replayed {replayed} messages")

        return capped

    async def _replay_activity(
        self, ds: DownstreamConnection, network: str, identifier: str,
        nc: NetworkConfig,
    ) -> None:
        """Auto-replay activity events (JOIN/PART/KICK/MODE/NICK/QUIT) on connect."""
        from datetime import datetime, timezone

        all_targets = await self.db.get_all_targets(self.username, network)
        if "*" not in all_targets:
            all_targets.append("*")

        # Filter targets by channel_replay_activity overrides
        targets = []
        for target in all_targets:
            if target == "*":
                # Always include NICK/QUIT global target
                targets.append(target)
            elif self._is_channel(target):
                # Check per-channel override, fall back to network-level setting
                if nc.channel_replay_activity.get(target.lower(), True):
                    targets.append(target)
            # Skip non-channel non-* targets (PM nicks don't have activity)

        if not targets:
            return

        # Get read positions
        after_ids: dict[str, int] = {}
        for target in targets:
            read_pos = await self.db.get_read_position(
                self.username, network, identifier, target
            )
            after_ids[target] = read_pos or 0

        rows = await self.db.get_activity_after(
            self.username, network, targets, after_ids
        )
        if not rows:
            return

        deliver_to_channel = (nc.replay_activity_target or "channel").lower() == "channel"

        count = 0
        for _msg_id, target, timestamp, raw_line in rows:
            try:
                msg = IRCMessage.parse(raw_line)
            except (ValueError, IndexError):
                continue

            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            time_str = dt.strftime("%H:%M:%S")
            source_nick = msg.source.split("!")[0] if msg.source else "?"
            cmd = msg.command
            chan_for_delivery: str | None = None

            if cmd == "JOIN":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                text = f"[{time_str}] {source_nick} joined {chan}"
            elif cmd == "PART":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                reason = msg.params[1] if len(msg.params) > 1 else ""
                text = f"[{time_str}] {source_nick} left {chan}"
                if reason:
                    text += f" ({reason})"
            elif cmd == "KICK":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                kicked = msg.params[1] if len(msg.params) > 1 else "?"
                reason = msg.params[2] if len(msg.params) > 2 else ""
                text = f"[{time_str}] {source_nick} kicked {kicked} from {chan}"
                if reason:
                    text += f" ({reason})"
            elif cmd == "MODE":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                mode_str = " ".join(msg.params[1:]) if len(msg.params) > 1 else ""
                text = f"[{time_str}] {source_nick} set mode {mode_str} on {chan}"
            elif cmd == "NICK":
                # Global event — no channel context, always goes to bouncer window.
                new_nick = msg.params[0] if msg.params else "?"
                text = f"[{time_str}] {source_nick} is now known as {new_nick}"
            elif cmd == "QUIT":
                # Global event — no channel context, always goes to bouncer window.
                reason = msg.params[0] if msg.params else ""
                text = f"[{time_str}] {source_nick} quit"
                if reason:
                    text += f" ({reason})"
            else:
                continue

            if deliver_to_channel and chan_for_delivery and self._is_channel(chan_for_delivery):
                self.deliver_channel_bouncer_message(ds, chan_for_delivery, text)
            else:
                self.deliver_bouncer_message(ds, text)
            count += 1

        if count > 0:
            self.deliver_bouncer_message(ds, f"-- {count} activity events --")

    async def route_upstream_message(self, network: str, msg: IRCMessage) -> None:
        """Route a message from upstream to all downstream clients and storage."""
        try:
            await self._route_upstream_message(network, msg)
        except Exception:
            logger.exception("Error routing upstream message on %s: %s", network, msg.command)

    async def _route_upstream_message(self, network: str, msg: IRCMessage) -> None:
        cmd = msg.command
        upstream = self.upstreams.get(network)

        # Store messages in database (before _update_state for QUIT/NICK
        # since that removes/renames members we need to look up)
        ts = time.time()
        if "time" in msg.tags and isinstance(msg.tags["time"], str):
            ts = self._parse_server_time(msg.tags["time"]) or ts

        stored_id: int | None = None

        if cmd in ("PRIVMSG", "NOTICE") and msg.params:
            target = msg.params[0]
            # For PMs directed at us, store under the sender's nick
            if upstream and not self._is_channel(target):
                if msg.source:
                    sender = IRCMessage.parse_prefix(msg.source)[0]
                    if sender.lower() != upstream.nick.lower():
                        target = sender
            stored_id = await self.db.store_message(self.username, network, target, msg, ts)

        elif cmd in ("JOIN", "PART", "KICK", "MODE", "TOPIC") and msg.params:
            # Channel events — store under the channel
            target = msg.params[0]
            if self._is_channel(target):
                stored_id = await self.db.store_message(self.username, network, target, msg, ts)

        elif cmd in ("QUIT", "NICK") and msg.source:
            # QUIT and NICK are global (no channel) — store once under "*"
            stored_id = await self.db.store_message(self.username, network, "*", msg, ts)

        # Update channel state (after storing QUIT/NICK)
        await self._update_state(network, msg)

        # Check if this numeric should be routed to a specific client
        routed_ds = self._check_reply_route(network, cmd)
        if routed_ds is not None:
            await self._forward_to_downstream(routed_ds, msg, stored_id)
            return

        # Forward to all connected downstreams
        if network in self.downstreams:
            # Detect echo: PRIVMSG/NOTICE from our own nick
            is_echo = False
            upstream = self.upstreams.get(network)
            if cmd in ("PRIVMSG", "NOTICE") and msg.source and upstream:
                sender = IRCMessage.parse_prefix(msg.source)[0]
                if sender.lower() == upstream.nick.lower():
                    is_echo = True

            # An echo is our own message coming back. It goes to every client
            # except, possibly, the one that typed it -- see _deliver_own_copy.
            origin_ds = self._match_pending_echo(network, msg) if is_echo else None

            for ds in list(self.downstreams[network]):
                if is_echo:
                    await self._deliver_own_copy(ds, msg, stored_id, origin_ds)
                else:
                    await self._forward_to_downstream(ds, msg, stored_id)

    async def _deliver_own_copy(
        self,
        ds: DownstreamConnection,
        msg: IRCMessage,
        msg_id: int | None,
        origin_ds: Optional[DownstreamConnection],
    ) -> None:
        """Hand one client a copy of a message we sent.

        Every client gets it except the one that typed it *without* negotiating
        echo-message -- that client already displayed the line itself, so a
        second copy would read as a duplicate. A client that did negotiate
        echo-message has turned its local echo off and is relying on us.

        The withheld case still advances the delivery watermark: the client has
        the message, just not from us, and leaving the id unconfirmed would
        stall its read position on a message it is never going to be sent.
        """
        if ds is origin_ds and not ds.cap.supports("echo-message"):
            ds.note_written(msg_id)
            return
        await self._forward_to_downstream(ds, msg, msg_id)

    # How long a sent message waits for its echo before Wicket stores its own
    # reconstruction instead. Generous, because the round trip includes the
    # upstream rate limiter's queue, which can be seconds deep during a flood.
    ECHO_WAIT_SECS = 60

    def _register_pending_echo(
        self, ds: DownstreamConnection, network: str, target: str,
        text: str, our_msg: IRCMessage,
    ) -> None:
        """Note that we expect the upstream to echo this message back."""
        pending = self._pending_echoes.setdefault(network, collections.deque())
        pending.append(PendingEcho(
            target=target.lower(), text=text, message=our_msg,
            sender=ds, created_at=time.time(),
        ))

    def _match_pending_echo(
        self, network: str, msg: IRCMessage
    ) -> Optional[DownstreamConnection]:
        """Find which client sent the message this echo is a copy of.

        Matching is on target plus exact text, oldest first. That is the only
        handle we have: the echo comes back with the server's own tags, and
        nothing in it identifies which of our attached clients typed it.
        Returns None when nothing matches -- including the ordinary case of a
        network without echo-message, where we register no expectations and the
        "echo" is really some other message from our own nick.
        """
        pending = self._pending_echoes.get(network)
        if not pending or len(msg.params) < 2:
            return None
        target = msg.params[0].lower()
        text = msg.params[1]
        for i, entry in enumerate(pending):
            if entry.target == target and entry.text == text:
                del pending[i]
                return entry.sender
        return None

    async def _expire_pending_echoes(self) -> None:
        """Store messages whose echo never came back.

        Without this, a message the upstream silently dropped (or echoed in a
        form we failed to match) would be missing from history entirely --
        worse than the duplicate this whole mechanism exists to remove. So
        after ECHO_WAIT_SECS we fall back to the behaviour used on networks
        without echo-message: store our own reconstruction and deliver it.
        """
        cutoff = time.time() - self.ECHO_WAIT_SECS
        for network, pending in list(self._pending_echoes.items()):
            while pending and pending[0].created_at < cutoff:
                entry = pending.popleft()
                logger.warning(
                    "No echo from %s for our %s after %ds; storing our own copy",
                    network, entry.target, self.ECHO_WAIT_SECS,
                )
                try:
                    msg_id = await self.db.store_message(
                        self.username, network, entry.target, entry.message,
                        entry.created_at,
                    )
                except Exception:
                    logger.exception("Error storing unechoed message for %s", network)
                    continue
                for ds in list(self.downstreams.get(network, [])):
                    await self._deliver_own_copy(ds, entry.message, msg_id, entry.sender)
            if not pending:
                self._pending_echoes.pop(network, None)

    def _forget_pending_echoes(self, ds: DownstreamConnection) -> None:
        """Drop a detaching client's claim on its pending echoes.

        The entries stay -- the messages were still sent and still need storing
        when the echo arrives -- but with no sender, so the echo is delivered to
        everyone rather than withheld from a socket that no longer exists.
        """
        for pending in self._pending_echoes.values():
            for i, entry in enumerate(pending):
                if entry.sender is ds:
                    pending[i] = replace(entry, sender=None)

    async def _forward_to_downstream(
        self, ds: DownstreamConnection, msg: IRCMessage, msg_id: int | None = None
    ) -> None:
        """Forward a message to a downstream, adjusting for its cap set.

        `msg_id` is the stored message's row id, when it has one. It records a
        delivery watermark on the connection so read positions can later be
        advanced only as far as the client actually confirmed.
        """
        # Track nick changes for this client
        if msg.command == "NICK" and msg.source and msg.params:
            old_nick = IRCMessage.parse_prefix(msg.source)[0]
            if old_nick.lower() == ds.nick.lower():
                ds.nick = msg.params[0]

        forward = msg.copy()

        # Strip extended-join params for clients that didn't negotiate it.
        # Extended JOIN: "JOIN <chan> <account> :<realname>" — plain clients
        # would parse the extra params as additional channels.
        if forward.command == "JOIN" and len(forward.params) > 1:
            if not ds.cap.supports("extended-join"):
                forward.params = [forward.params[0]]

        # Filter tags based on client caps
        if forward.tags:
            filtered_tags = {}
            for key, val in forward.tags.items():
                if self._should_forward_tag(ds, key):
                    filtered_tags[key] = val
            forward.tags = filtered_tags

        # Don't forward typing to clients that don't support it
        if msg.command == "TAGMSG":
            if not ds.cap.supports("message-tags"):
                return
            # Check if it's only typing tags
            typing_tags = {"typing", "+typing", "draft/typing", "+draft/typing"}
            if set(msg.tags.keys()) <= typing_tags | {"time", "msgid", "account", "batch"}:
                if not (ds.cap.supports("draft/typing") or ds.cap.supports("typing")):
                    return

        try:
            await ds.send(forward)
            ds.note_written(msg_id)
        except (ConnectionError, OSError):
            pass
        except Exception:
            logger.exception("Error forwarding %s to downstream %s",
                             forward.command, ds.nick)

    def _should_forward_tag(self, ds: DownstreamConnection, tag: str) -> bool:
        """Check if a tag should be forwarded to a downstream client."""
        cap_tag_map = {
            "time": "server-time",
            "account": "account-tag",
            "batch": "batch",
            "label": "labeled-response",
            "msgid": "message-tags",
            "+typing": "draft/typing",
            "+draft/typing": "draft/typing",
            "typing": "typing",
        }
        required_cap = cap_tag_map.get(tag)
        if required_cap:
            return ds.cap.supports(required_cap)
        # Client-only tags (prefixed with +) need message-tags
        if tag.startswith("+"):
            return ds.cap.supports("message-tags")
        return True

    async def _update_state(self, network: str, msg: IRCMessage) -> None:
        """Update channel/user state based on upstream messages."""
        if network not in self.channels:
            self.channels[network] = {}
        channels = self.channels[network]
        upstream = self.upstreams.get(network)
        if not upstream:
            return

        cmd = msg.command

        if cmd == "JOIN" and msg.source and msg.params:
            nick = IRCMessage.parse_prefix(msg.source)[0]
            chan_name = msg.params[0]
            chan_key = chan_name.lower()

            if nick.lower() == upstream.nick.lower():
                # We joined a channel
                if chan_key not in channels:
                    channels[chan_key] = ChannelState(name=chan_name)
                channels[chan_key].joined = True
                self._persist_autojoin(network, chan_name, add=True)
            elif chan_key in channels:
                channels[chan_key].members[nick] = ""

        elif cmd == "PART" and msg.source and msg.params:
            nick = IRCMessage.parse_prefix(msg.source)[0]
            chan_name = msg.params[0]
            chan_key = chan_name.lower()
            if nick.lower() == upstream.nick.lower():
                if chan_key in channels:
                    channels[chan_key].joined = False
                self._persist_autojoin(network, chan_name, add=False)
            elif chan_key in channels:
                channels[chan_key].members.pop(nick, None)

        elif cmd == "KICK" and msg.source and len(msg.params) >= 2:
            chan_key = msg.params[0].lower()
            chan_name = msg.params[0]
            kicked = msg.params[1]
            if kicked.lower() == upstream.nick.lower():
                if chan_key in channels:
                    channels[chan_key].joined = False
                self._persist_autojoin(network, chan_name, add=False)
            elif chan_key in channels:
                channels[chan_key].members.pop(kicked, None)

        elif cmd == "QUIT" and msg.source:
            nick = IRCMessage.parse_prefix(msg.source)[0]
            for chan in channels.values():
                chan.members.pop(nick, None)

        elif cmd == "NICK" and msg.source and msg.params:
            old_nick = IRCMessage.parse_prefix(msg.source)[0]
            new_nick = msg.params[0]
            for chan in channels.values():
                if old_nick in chan.members:
                    prefix = chan.members.pop(old_nick)
                    chan.members[new_nick] = prefix

        elif cmd == "332" and len(msg.params) >= 3:
            # RPL_TOPIC
            chan_key = msg.params[1].lower()
            if chan_key in channels:
                channels[chan_key].topic = msg.params[2]

        elif cmd == "333" and len(msg.params) >= 4:
            # RPL_TOPICWHOTIME
            chan_key = msg.params[1].lower()
            if chan_key in channels:
                channels[chan_key].topic_set_by = msg.params[2]
                try:
                    channels[chan_key].topic_set_at = float(msg.params[3])
                except ValueError:
                    pass

        elif cmd == "TOPIC" and msg.source and msg.params:
            chan_key = msg.params[0].lower()
            if chan_key in channels:
                channels[chan_key].topic = msg.params[1] if len(msg.params) > 1 else None
                channels[chan_key].topic_set_by = IRCMessage.parse_prefix(msg.source)[0]
                channels[chan_key].topic_set_at = time.time()

        elif cmd == "353" and len(msg.params) >= 4:
            # RPL_NAMREPLY
            chan_key = msg.params[2].lower()
            if chan_key in channels:
                for entry in msg.params[3].split():
                    prefix = ""
                    nick = entry
                    while nick and nick[0] in upstream.nick_prefixes:
                        prefix += nick[0]
                        nick = nick[1:]
                    # Strip userhost-in-names suffix (nick!user@host -> nick)
                    if "!" in nick:
                        nick = nick.split("!")[0]
                    if nick:
                        channels[chan_key].members[nick] = prefix

        elif cmd == "366" and len(msg.params) >= 2:
            # RPL_ENDOFNAMES - channel join complete
            pass

        # Forward 001 numerics if we haven't done the initial join yet
        if cmd == "376" or cmd == "422":
            # End of MOTD or no MOTD - join channels now
            await upstream.join_channels()
            # Notify any pre-attached clients that upstream is now online,
            # and push an updated 005 ISUPPORT so clients (e.g. mIRC) can pick
            # up the real NETWORK name now that we know it.
            for ds in self.downstreams.get(network, []):
                self.deliver_bouncer_message(ds, f"Upstream {network} is now connected")
                # If the upstream re-registered under a different nick (e.g. an
                # alt nick because our primary was still ghosted after a
                # disconnect), the client still thinks it has the old nick.
                # A re-registration doesn't generate a server NICK message, so
                # tell the client explicitly and resync ds.nick — otherwise the
                # client's idea of "my nick" stays wrong until it reconnects.
                if upstream.nick and ds.nick.lower() != upstream.nick.lower():
                    await ds.send(IRCMessage(
                        command="NICK", params=[upstream.nick],
                        source=f"{ds.nick}!{upstream.username}@{self.server_name}",
                    ))
                    ds.nick = upstream.nick
                if upstream.isupport:
                    tokens = []
                    for key, val in upstream.isupport.items():
                        if val is not None:
                            tokens.append(f"{key}={val}")
                        else:
                            tokens.append(key)
                    for i in range(0, len(tokens), 13):
                        batch = tokens[i : i + 13]
                        await ds.send(IRCMessage(
                            command="005",
                            params=[ds.nick] + batch + ["are supported by this server"],
                            source=self.server_name,
                        ))

    async def route_downstream_message(
        self, ds: DownstreamConnection, msg: IRCMessage
    ) -> None:
        """Route a message from a downstream client to the appropriate upstream."""
        try:
            await self._route_downstream_message(ds, msg)
        except Exception:
            logger.exception("Error routing downstream message from %s: %s",
                             ds.nick, msg.command)

    async def _route_downstream_message(
        self, ds: DownstreamConnection, msg: IRCMessage
    ) -> None:
        if not ds.network:
            return

        upstream = self.upstreams.get(ds.network)
        cmd = msg.command

        # Handle bouncer commands even when upstream is disconnected.
        # Match against just the nick (or server_name if delivery_source is "server"),
        # not the full nick!user@host form.
        if cmd in ("PRIVMSG", "NOTICE") and msg.params:
            target = msg.params[0]
            if self.config.delivery_source == "server":
                bouncer_target = self.server_name
            else:
                bouncer_target = self.config.delivery_source
            if target.lower() == bouncer_target.lower():
                await self._handle_bouncer_command(ds, msg.params[1] if len(msg.params) > 1 else "")
                return

        if not upstream or not upstream.connected:
            self.deliver_bouncer_message(ds, f"Not connected to {ds.network}")
            return

        # Record our own messages so every device sees them, not just the one
        # they were typed on.
        if cmd in ("PRIVMSG", "NOTICE") and msg.params:
            target = msg.params[0]
            text = msg.params[1] if len(msg.params) > 1 else ""
            # Create a message that looks like it's from us
            our_msg = msg.copy(source=f"{upstream.nick}!{upstream.username}@{self.server_name}")

            if upstream.cap.supports("echo-message"):
                # The upstream will send this back with its own msgid and
                # server-time, and that copy is what everyone else on the
                # network saw. Wait for it rather than storing a second,
                # slightly-different copy of the same line -- doing both is
                # what made every message you sent appear twice in backscroll.
                self._register_pending_echo(ds, ds.network, target, text, our_msg)
            else:
                # No echo is coming, so our reconstruction is the only copy
                # there will ever be. Store and deliver it now.
                own_id = await self.db.store_message(
                    self.username, ds.network, target, our_msg
                )
                for other_ds in list(self.downstreams.get(ds.network, [])):
                    await self._deliver_own_copy(other_ds, our_msg, own_id, ds)

        # PING/PONG are handled in DownstreamConnection._handle_message, before
        # routing gets here. They must be, because this function returns early
        # with "Not connected to <network>" when the upstream is down, which
        # would answer a client's keepalive with an error and drop the PONG that
        # advances the delivery watermark.

        # JOIN - remember keys so we can persist them when upstream confirms
        if cmd == "JOIN" and msg.params:
            channels = msg.params[0].split(",")
            keys = msg.params[1].split(",") if len(msg.params) > 1 else []
            if ds.network not in self._pending_keys:
                self._pending_keys[ds.network] = {}
            for i, chan in enumerate(channels):
                key = keys[i] if i < len(keys) else None
                if key:
                    self._pending_keys[ds.network][chan.lower()] = key

        if cmd == "PART" and msg.params:
            pass  # Will be tracked when upstream confirms

        # QUIT from client = disconnect from bouncer, not from network
        if cmd == "QUIT":
            await ds.close()
            return

        # Register reply routing for commands that produce numeric sequences
        route_cmd = cmd
        if cmd == "MODE" and msg.params and self._is_channel(msg.params[0]):
            if len(msg.params) == 2 and msg.params[1] in ("+b", "+e", "+I", "b", "e", "I"):
                # Ban/exception list query — route under BANLIST
                route_cmd = "BANLIST"
                self._register_reply_route(ds.network, ds, route_cmd)
            elif len(msg.params) == 1:
                # Plain channel mode query — route under MODE
                route_cmd = "MODE"
                self._register_reply_route(ds.network, ds, route_cmd)
            # Other MODE changes (setting modes) don't produce reply sequences
        elif route_cmd in ROUTED_REPLIES:
            self._register_reply_route(ds.network, ds, route_cmd)

        # Don't forward TAGMSG if upstream doesn't support message-tags
        if cmd == "TAGMSG" and not upstream.cap.supports("message-tags"):
            return

        # Forward everything else to upstream
        # Strip tags that are client-only unless upstream supports them
        forward = msg.copy(source=None, tags={})
        if msg.tags:
            for key, val in msg.tags.items():
                if key.startswith("+") and upstream.cap.supports("message-tags"):
                    forward.tags[key] = val
                elif key == "label" and upstream.cap.supports("labeled-response"):
                    forward.tags[key] = val
                elif key in ("+typing", "+draft/typing"):
                    if upstream.cap.supports("draft/typing") or upstream.cap.supports("typing"):
                        forward.tags[key] = val

        await upstream.send(forward)

    async def _handle_bouncer_command(self, ds: DownstreamConnection, text: str) -> None:
        """Handle commands sent to the bouncer nick."""
        parts = text.strip().split()
        if not parts:
            return
        cmd = parts[0].upper()

        if cmd == "HELP":
            self.deliver_bouncer_message(ds, "Available commands: HELP, STATUS, LISTNETWORKS, "
                                         "CONNECT <network>, DISCONNECT <network>, "
                                         "SETPASSWORD <newpass>, REHASH, "
                                         "ACTIVITY [channel|bouncer] [#chan1 #chan2 ...]")
        elif cmd == "STATUS":
            for net_name, up in self.upstreams.items():
                n_clients = len(self.downstreams.get(net_name, []))
                self.deliver_bouncer_message(
                    ds, f"  {net_name}: {self._network_state(up)} ({n_clients} clients)"
                )
        elif cmd == "LISTNETWORKS":
            for net_name in self.config.networks:
                up = self.upstreams.get(net_name)
                state = self._network_state(up) if up else "not configured"
                self.deliver_bouncer_message(ds, f"  {net_name}: {state}")
        elif cmd == "CONNECT":
            await self._handle_connect(ds, parts[1:])
        elif cmd == "DISCONNECT":
            await self._handle_disconnect(ds, parts[1:])
        elif cmd == "SETPASSWORD":
            await self._handle_set_password(ds, parts[1:])
        elif cmd == "REHASH":
            await self._handle_rehash(ds)
        elif cmd == "ACTIVITY":
            await self._handle_activity(ds, parts[1:])
        else:
            self.deliver_bouncer_message(ds, f"Unknown command: {cmd}")

    @staticmethod
    def _network_state(upstream: "UpstreamConnection") -> str:
        """One-word state for STATUS / LISTNETWORKS.

        "disconnected" alone can't be acted on: it covers both a network that
        is about to retry on its own and one that has been told to stay down,
        and those want opposite things from the user.
        """
        if upstream.connected and upstream.registered:
            return "connected"
        if upstream.connected:
            return "registering"
        if upstream.reconnect_pending:
            return "reconnecting"
        if not upstream.reconnect_enabled:
            return "disconnected (staying down)"
        return "disconnected"

    async def _handle_connect(self, ds: DownstreamConnection, args: list[str]) -> None:
        """Handle the CONNECT bouncer command."""
        if not args:
            self.deliver_bouncer_message(ds, "Usage: CONNECT <network>")
            return
        net_name = args[0]
        if net_name not in self.upstreams:
            available = ", ".join(self.config.networks.keys())
            self.deliver_bouncer_message(ds, f"Unknown network '{net_name}'. Available: {available}")
            return
        upstream = self.upstreams[net_name]
        if upstream.connected:
            self.deliver_bouncer_message(ds, f"Already connected to {net_name}")
            return
        # Cancel any in-flight reconnect to avoid duplicate connections.
        if upstream._reconnect_task and not upstream._reconnect_task.done():
            upstream._reconnect_task.cancel()
            try:
                await upstream._reconnect_task
            except asyncio.CancelledError:
                pass
            upstream._reconnect_task = None
        self.deliver_bouncer_message(ds, f"Connecting to {net_name}...")
        upstream._should_reconnect = True
        # Reset all backoff state for a user-initiated connect.
        upstream._reconnect_delay = 1.0
        upstream._min_reconnect_delay = 0.0
        upstream._consecutive_bans = 0
        await upstream.connect()

    async def _handle_disconnect(self, ds: DownstreamConnection, args: list[str]) -> None:
        """Handle the DISCONNECT bouncer command."""
        if not args:
            self.deliver_bouncer_message(ds, "Usage: DISCONNECT <network>")
            return
        net_name = args[0]
        if net_name not in self.upstreams:
            available = ", ".join(self.config.networks.keys())
            self.deliver_bouncer_message(ds, f"Unknown network '{net_name}'. Available: {available}")
            return
        upstream = self.upstreams[net_name]
        # DISCONNECT means "stay down", so it must work while the network is
        # DOWN and retrying -- which is the state you are in when you most want
        # to stop it. This used to bail out with "Not connected" whenever
        # `connected` was False, i.e. throughout every reconnect backoff, so a
        # network in a retry loop could not be stopped at all.
        if upstream.connected:
            self.deliver_bouncer_message(ds, f"Disconnecting from {net_name}...")
        elif upstream.reconnect_pending:
            self.deliver_bouncer_message(ds, f"Cancelling reconnection to {net_name}...")
        elif not upstream.reconnect_enabled:
            self.deliver_bouncer_message(ds, f"Already disconnected from {net_name}")
            return
        else:
            self.deliver_bouncer_message(ds, f"Not connected to {net_name}; disabling reconnection")
        await upstream.disconnect("Disconnected by user")
        self.deliver_bouncer_message(
            ds,
            f"Disconnected from {net_name}. It will stay down until you send "
            f"CONNECT {net_name}, or until Wicket restarts -- set "
            f"auto_connect: false for {net_name} in config.yaml to keep it down "
            f"across restarts.",
        )

    async def _handle_set_password(self, ds: DownstreamConnection, args: list[str]) -> None:
        """Handle the SETPASSWORD bouncer command."""
        if not args:
            self.deliver_bouncer_message(ds, "Usage: SETPASSWORD <new_password>")
            return

        new_password = args[0]
        if len(new_password) < 4:
            self.deliver_bouncer_message(ds, "Password too short (minimum 4 characters)")
            return

        # Hash and update in-memory config
        hashed = hash_password(new_password)
        self.config.password = hashed

        # Persist to config file if we have the path
        if self.config_path:
            try:
                set_user_password(self.config_path, self.username, new_password)
                self.deliver_bouncer_message(ds, "Password updated and saved to config file")
            except Exception as e:
                # In-memory update succeeded but file write failed
                self.deliver_bouncer_message(ds, f"Password updated in memory but failed to save to file: {e}")
                logger.error("Failed to save password to config for %s: %s", self.username, e)
        else:
            self.deliver_bouncer_message(ds, "Password updated (in memory only, no config path available)")

    async def _handle_rehash(self, ds: DownstreamConnection) -> None:
        """Handle the REHASH bouncer command."""
        bouncer = ds.bouncer
        self.deliver_bouncer_message(ds, "Reloading configuration...")
        messages = await bouncer.rehash(requesting_ds=ds)
        for msg in messages:
            self.deliver_bouncer_message(ds, f"  {msg}")
        self.deliver_bouncer_message(ds, "Rehash complete")

    async def _handle_activity(self, ds: DownstreamConnection, args: list[str]) -> None:
        """Handle the ACTIVITY bouncer command.

        Shows JOIN, PART, KICK, MODE, NICK, QUIT events from the backscroll.
        Optional channel arguments filter to those channels (plus global NICK/QUIT).
        Optional 'channel' or 'bouncer' arg picks where output is delivered;
        defaults to the network's replay_activity_target.
        """
        network = ds.network
        if not network:
            self.deliver_bouncer_message(ds, "Not connected to a network")
            return

        # Pull a 'channel'/'bouncer' arg if present; default to network setting.
        nc = self.config.networks.get(network)
        deliver_to_channel = ((nc.replay_activity_target if nc else "channel") or "channel").lower() == "channel"
        remaining_args = []
        for a in args:
            al = a.lower()
            if al == "channel":
                deliver_to_channel = True
            elif al in ("bouncer", "window"):
                deliver_to_channel = False
            else:
                remaining_args.append(a)
        args = remaining_args

        # Determine which targets to query
        filter_channels = [ch.lower() for ch in args if ch.startswith(("#", "&", "!", "+"))]

        if filter_channels:
            targets = filter_channels + ["*"]
        else:
            targets = await self.db.get_all_targets(self.username, network)
            if "*" not in targets:
                targets.append("*")

        # Get read positions for each target
        identifier = ds.identifier or "*"
        after_ids: dict[str, int] = {}
        for target in targets:
            read_pos = await self.db.get_read_position(
                self.username, network, identifier, target
            )
            after_ids[target] = read_pos or 0

        rows = await self.db.get_activity_after(
            self.username, network, targets, after_ids
        )

        if not rows:
            self.deliver_bouncer_message(ds, "No recent activity")
            return

        from datetime import datetime, timezone
        count = 0
        for _msg_id, target, timestamp, raw_line in rows:
            try:
                msg = IRCMessage.parse(raw_line)
            except (ValueError, IndexError):
                continue

            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            time_str = dt.strftime("%H:%M:%S")
            source_nick = msg.source.split("!")[0] if msg.source else "?"
            cmd = msg.command
            chan_for_delivery: str | None = None

            if cmd == "JOIN":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                text = f"[{time_str}] {source_nick} joined {chan}"
            elif cmd == "PART":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                reason = msg.params[1] if len(msg.params) > 1 else ""
                text = f"[{time_str}] {source_nick} left {chan}"
                if reason:
                    text += f" ({reason})"
            elif cmd == "KICK":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                kicked = msg.params[1] if len(msg.params) > 1 else "?"
                reason = msg.params[2] if len(msg.params) > 2 else ""
                text = f"[{time_str}] {source_nick} kicked {kicked} from {chan}"
                if reason:
                    text += f" ({reason})"
            elif cmd == "MODE":
                chan = msg.params[0] if msg.params else target
                chan_for_delivery = chan
                mode_str = " ".join(msg.params[1:]) if len(msg.params) > 1 else ""
                text = f"[{time_str}] {source_nick} set mode {mode_str} on {chan}"
            elif cmd == "NICK":
                new_nick = msg.params[0] if msg.params else "?"
                text = f"[{time_str}] {source_nick} is now known as {new_nick}"
            elif cmd == "QUIT":
                reason = msg.params[0] if msg.params else ""
                text = f"[{time_str}] {source_nick} quit"
                if reason:
                    text += f" ({reason})"
            else:
                continue

            if deliver_to_channel and chan_for_delivery and self._is_channel(chan_for_delivery):
                self.deliver_channel_bouncer_message(ds, chan_for_delivery, text)
            else:
                self.deliver_bouncer_message(ds, text)
            count += 1

        self.deliver_bouncer_message(ds, f"-- {count} activity events --")

    def _persist_autojoin(self, network: str, channel: str, add: bool) -> None:
        """Update the in-memory autojoin dict and persist to config file."""
        nc = self.config.networks.get(network)
        if not nc:
            return

        existing_lower = {c.lower() for c in nc.autojoin}

        if add and channel.lower() not in existing_lower:
            # Check if we have a pending key from the client's JOIN command
            key = None
            pending = self._pending_keys.get(network, {})
            if channel.lower() in pending:
                key = pending.pop(channel.lower())
            nc.autojoin[channel] = key
        elif not add and channel.lower() in existing_lower:
            nc.autojoin = {c: k for c, k in nc.autojoin.items() if c.lower() != channel.lower()}
        else:
            return  # No change needed

        if self.config_path:
            try:
                update_autojoin(self.config_path, self.username, network, nc.autojoin)
            except Exception as e:
                logger.warning("Failed to persist autojoin for %s/%s: %s",
                               self.username, network, e)

    def _register_reply_route(self, network: str, ds: DownstreamConnection, command: str) -> None:
        """Register that replies for `command` should be routed to `ds`."""
        if command not in ROUTED_REPLIES:
            return
        replies, ends, errors = ROUTED_REPLIES[command]
        if network not in self._pending_routes:
            self._pending_routes[network] = collections.deque()
        self._pending_routes[network].append((ds, command, replies, ends, errors, time.time()))

    def _check_reply_route(self, network: str, numeric: str) -> Optional[DownstreamConnection]:
        """Check if a numeric reply should be routed to a specific client.

        Returns the DownstreamConnection to route to, or None to broadcast
        to all clients (which is the fallback for stray/expired replies).
        """
        if network not in self._pending_routes:
            return None
        routes = self._pending_routes[network]
        if not routes:
            return None

        # Only consider numerics that could be routed
        if numeric not in _NUMERIC_TO_COMMANDS:
            return None

        now = time.time()

        # Drain expired and disconnected routes from the front
        while routes:
            ds, command, replies, ends, errors, created_at = routes[0]
            net_downstreams = self.downstreams.get(network, [])

            if ds not in net_downstreams:
                # Client disconnected, discard
                routes.popleft()
                continue

            if now - created_at > ROUTE_TIMEOUT_SECS:
                # Route expired — discard it so the numeric falls through
                # to broadcast below
                logger.debug("Reply route expired for %s (%.0fs old), discarding",
                             command, now - created_at)
                routes.popleft()
                continue

            break  # Front route is valid
        else:
            # All routes drained, broadcast
            return None

        ds, command, replies, ends, errors, created_at = routes[0]

        # End marker: route this final message, then consume the route
        if numeric in ends:
            routes.popleft()
            return ds

        # Error: route this error, then consume the route
        if numeric in errors:
            routes.popleft()
            return ds

        # Reply numeric: route to client
        if numeric in replies:
            # For commands with no end marker (VERSION, TIME, ISON, USERHOST,
            # TOPIC, INVITE), consume the route on the first matching reply
            if not ends:
                routes.popleft()
            return ds

        # Numeric is routable but doesn't match our front route — this is a
        # stray reply (e.g. unsolicited WHOIS from the server). Return None
        # to broadcast it to all clients.
        return None

    def _is_channel(self, target: str) -> bool:
        return target and target[0] in "#&!+"

    def _parse_server_time(self, ts: str) -> float | None:
        """Parse an IRCv3 server-time tag into a Unix timestamp."""
        from datetime import datetime, timezone
        try:
            # Format: 2024-01-15T12:34:56.789Z
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            return None

"""Upstream connection to an IRC server."""

from __future__ import annotations
import asyncio
import logging
import re
import ssl
import time
from typing import TYPE_CHECKING, Optional

from irc_parser import IRCMessage
from cap import CapNegotiator, CapState
from rate_limiter import RateLimiter
from sasl import get_sasl_payload
from ident import IdentServer

if TYPE_CHECKING:
    from user import User
    from config import NetworkConfig, ServerConfig

logger = logging.getLogger(__name__)
irc_log = logging.getLogger("irc_traffic")

# Reconnect backoff tuning.
# Ordinary disconnects (network blips, server restarts) use an exponential
# backoff capped at _NORMAL_BACKOFF_MAX.  Bans and connection throttling need
# their own, much longer backoff: networks like undernet/libera issue an
# automatic "excessive connections" G-line/K-line and then *renew/extend that
# ban on every subsequent connection attempt made while it's still active*.
# Reconnecting too soon therefore keeps the ban alive forever.
#
# Crucially, an excessive-connection G-line lasts up to ~24 hours, and because
# it renews on contact, EVERY retry made before it expires just pushes the
# expiry further out.  So for that specific ban we don't escalate slowly from a
# small value (which would renew it on each early retry) — we jump straight to a
# delay that comfortably exceeds a full day on the very first detection, so the
# ban gets a chance to expire untouched.  Generic bans of unknown duration
# (k-line, etc.) escalate from a smaller base.
_NORMAL_BACKOFF_MAX = 300.0      # 5 min — cap for ordinary reconnect backoff
_THROTTLE_BACKOFF = 120.0        # 2 min — server said we're (re)connecting too fast
_BAN_BACKOFF_INITIAL = 1800.0    # 30 min — first generic ban (unknown duration)
_EXCONN_BACKOFF_INITIAL = 90000.0  # 25 h — first "excessive connections" ban (lasts ~1 day, renews on contact)
_BAN_BACKOFF_MAX = 172800.0      # 48 h cap for repeated bans


def _span(seconds: float) -> str:
    """A duration the way a person says it: 45s, 12m, 25h, 2d."""
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m"
    if seconds < 172800:
        return f"{int(seconds // 3600)}h"
    return f"{int(seconds // 86400)}d"


class UpstreamConnection:
    def __init__(self, user: User, network_config: NetworkConfig, ident_server: IdentServer | None = None):
        self.user = user
        self.network_config = network_config
        self.network_name = network_config.name
        self._ident_server = ident_server
        self._ident_local_port: int | None = None

        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.rate_limiter: Optional[RateLimiter] = None
        # What one connection negotiates: the CAP state, the nick, user and
        # realname it registers with, the welcome it got.  See _start_fresh.
        self.cap: CapNegotiator
        self.nick: str
        self.username: str
        self.realname: str
        self.registered: bool
        self.welcome_msgs: list[IRCMessage]
        # Nick fallback: [primary, alt1, alt2, ...], then primary_, primary__, ...
        self._nick_candidates: list[str]
        self._nick_attempt_index: int
        self._start_fresh()
        self.connected: bool = False

        self.isupport: dict[str, str | None] = {}
        self.server_name: str = ""
        # PREFIX=(ov)@+ -- the two halves, in matching order, so that a mode
        # letter can be turned into the symbol it grants. Tracking the symbols
        # alone is enough to *parse* a NAMES reply but not to apply a MODE.
        self.prefix_modes: str = "ov"   # default, paired with nick_prefixes
        self.nick_prefixes: str = "@+"  # default
        # CHANMODES=A,B,C,D -- needed to know which mode letters consume an
        # argument, so the arguments line up with the letters that own them.
        self.chan_modes: str = ""
        self.casemapping: str = "rfc1459"

        # Server rotation
        self._server_index: int = 0

        self._read_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_delay: float = 1.0
        # Persistent floor applied to the next reconnect delay, used for bans
        # and throttling.  Unlike _reconnect_delay (which is re-capped to
        # _NORMAL_BACKOFF_MAX each cycle), this floor survives across reconnect
        # attempts and is only cleared by a successful registration or a
        # user-initiated CONNECT.  This is what keeps us from renewing an
        # "excessive connections" G-line by reconnecting too soon.
        self._min_reconnect_delay: float = 0.0
        # Number of consecutive ban-induced disconnects without a successful
        # registration in between; drives the ban backoff escalation.
        self._consecutive_bans: int = 0
        # Guard so a single disconnect (which may produce both a 465 numeric
        # and an ERROR line) only counts as one ban.
        self._ban_noted_this_conn: bool = False
        self._sasl_mechanism: Optional[str] = None
        # `auto_connect: false` means "stay down until I say otherwise", which
        # is the same state DISCONNECT produces -- so start there rather than
        # merely skipping the initial dial.  Starting True made the setting a
        # one-shot: anything that called connect() (a client attaching, a
        # failure handler) would find reconnects already enabled and drag the
        # network back up, and any failure would arm a backoff timer for a
        # network the user asked to leave alone.  It also made LISTNETWORKS
        # report a plain "disconnected" for a network that was staying down.
        self._should_reconnect: bool = network_config.auto_connect

        # Track pending SASL
        self._sasl_in_progress: bool = False

        # Retry queue for channels that got "target change too fast"
        # list of (channel, key_or_none, retry_after_timestamp)
        self._join_retry_queue: list[tuple[str, str | None, float]] = []
        # channel.lower() -> the key the last JOIN for it actually went out
        # with.  Deliberately outlives a reconnect: see _note_join.
        self._join_keys: dict[str, str] = {}
        self._join_retry_task: Optional[asyncio.Task] = None

        # Guard against concurrent connect() calls.  Without this, a second
        # connect() during the first's open_connection() await would orphan
        # the first connection (overwriting reader/writer/_read_task),
        # creating zombie connections that are never cleaned up.
        self._connecting: bool = False

        # For describe(): why the last attempt ended, as (time.monotonic(),
        # text), cleared by a successful registration; the server being
        # dialled or registered with; when the socket opened; and when the
        # scheduled reconnect fires.
        self.last_failure: Optional[tuple[float, str]] = None
        self._dialing: str = ""
        self._connected_at: Optional[float] = None
        self._reconnect_at: Optional[float] = None

    def _start_fresh(self) -> None:
        """Reset what one connection negotiates, from the config as it is now.

        Run before every attempt, whatever started it -- startup, a reconnect,
        CONNECT, a client attaching -- so a REHASH that changed the nick, user,
        realname, alt_nicks or caps reaches the next registration.  Kept as
        copies rather than read from the config at each use because `nick`
        changes during a session and the rest describe the registration the
        server accepted.
        """
        nc = self.network_config
        self.cap = CapNegotiator(
            is_upstream=True,
            extra_wanted=set(nc.caps_wanted),
            override_caps=set(nc.upstream_caps) if nc.upstream_caps is not None else None,
        )
        self.nick = nc.nick
        self.username = nc.user
        self.realname = nc.realname
        self.registered = False
        self.welcome_msgs = []
        self._nick_candidates = [nc.nick] + list(nc.alt_nicks)
        self._nick_attempt_index = 0

    @property
    def reconnect_pending(self) -> bool:
        """True if a reconnect attempt is scheduled or currently running.

        Distinguishes "down and about to come back" from "down and staying
        down", which is not visible from `connected` alone: both are False
        there, and the difference is the whole point of DISCONNECT.
        """
        return (self._reconnect_task is not None and not self._reconnect_task.done()) \
            or self._connecting

    @property
    def reconnect_enabled(self) -> bool:
        """True if a future failure would schedule another attempt."""
        return self._should_reconnect

    @property
    def reconnect_in(self) -> Optional[float]:
        """Seconds until the scheduled reconnect dials; None if none is waiting."""
        task = self._reconnect_task
        if task is None or task.done() or self._reconnect_at is None:
            return None
        return max(0.0, self._reconnect_at - time.monotonic())

    def describe(self) -> str:
        """Where this network stands, as a phrase for someone deciding what to do.

        "Not connected" alone cannot be acted on: it covers a network about to
        come back, one waiting out a backoff, one stuck registering, and one
        told to stay down.  This says which, and what to send to change it.
        """
        name = self.network_name
        if self.connected and self.registered:
            return "connected"
        if self.connected:
            since = time.monotonic() - (self._connected_at or time.monotonic())
            return f"registering with {self._dialing}, for {_span(since)} so far"
        if self._connecting:
            return f"connecting to {self._dialing}" if self._dialing else "connecting"
        wait = self.reconnect_in
        if wait is not None:
            return f"down, reconnecting in {_span(wait)}; CONNECT {name} to try now"
        if not self._should_reconnect:
            return f"down and staying down; CONNECT {name} to connect"
        # Armed with nothing scheduled: only before the first dial, which is
        # already on its way (startup, or the client attaching).
        return "connecting"

    def describe_last_failure(self) -> Optional[str]:
        """How the last attempt failed and how long ago, while not connected."""
        if self.last_failure is None or (self.connected and self.registered):
            return None
        at, text = self.last_failure
        return f"Last failure, {_span(time.monotonic() - at)} ago: {text}"

    def _note_failure(self, text: str) -> None:
        # Bounded: it is sent as one NOTICE, and a server's ERROR is free text.
        if len(text) > 300:
            text = text[:297] + "..."
        self.last_failure = (time.monotonic(), text)

    async def connect(self) -> None:
        """Connect to the IRC server, trying each configured server in order.

        Never raises, cancellation aside.  Every caller starts this as a task
        and none awaits it for a result, so an exception here would be reported
        by nobody; and one raised partway through registration would leave the
        socket open and half-registered until the server timed it out.  So a
        failure is logged, the connection torn down, and a reconnect scheduled
        as for any other failure.
        """
        if self._connecting:
            logger.debug("connect() already in progress for %s, skipping",
                         self.network_name)
            return
        self._connecting = True
        try:
            await self._connect_inner()
        except Exception as e:
            logger.exception("Connecting to %s failed", self.network_name)
            self._note_failure(f"internal error while connecting: "
                               f"{type(e).__name__}: {e} (details in the log)")
            await self._cleanup()
            self._schedule_reconnect()
        finally:
            self._connecting = False

    async def _connect_inner(self) -> None:
        """Inner connection logic (guarded by _connecting flag)."""
        servers = self.network_config.servers
        if not servers:
            logger.error("No servers configured for %s", self.network_name)
            return

        # Fresh connection attempt — allow this connection to register one ban.
        self._ban_noted_this_conn = False

        # Clean up any existing connection state to avoid orphaned sockets.
        # This is idempotent and harmless if already cleaned up.
        if self.connected or self.writer:
            await self._cleanup()
        self._start_fresh()

        # Try each server starting from the current index
        for attempt in range(len(servers)):
            idx = (self._server_index + attempt) % len(servers)
            sc = servers[idx]
            logger.info("Connecting to %s:%d (TLS: %s) for %s/%s",
                         sc.host, sc.port, sc.tls, self.user.username, self.network_name)
            self._dialing = f"{sc.host}:{sc.port}"

            ssl_ctx = None
            if sc.tls:
                ssl_ctx = ssl.create_default_context()
                if not sc.tls_verify:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
                # Load client cert for SASL EXTERNAL
                if self.network_config.sasl and self.network_config.sasl.cert_path:
                    ssl_ctx.load_cert_chain(self.network_config.sasl.cert_path)

            try:
                self.reader, self.writer = await asyncio.open_connection(
                    sc.host, sc.port, ssl=ssl_ctx,
                )
            except (OSError, ssl.SSLError) as e:
                logger.warning("Connection failed to %s:%d: %s", sc.host, sc.port, e)
                self._note_failure(f"{sc.host}:{sc.port}: {e}")
                continue  # Try next server

            # DISCONNECT may have arrived while we were dialing. Its cleanup ran
            # before this socket existed, so without this check nothing tears it
            # down and the network comes back up in spite of the command.
            if not self._should_reconnect:
                logger.info("Connect to %s aborted: disconnected while dialing",
                            self.network_name)
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
                self.reader = None
                self.writer = None
                return

            # Connected successfully (TCP level — registration may still fail)
            self._server_index = idx
            self.connected = True
            self._connected_at = time.monotonic()

            # Register with ident server
            if self._ident_server:
                sockname = self.writer.get_extra_info("sockname")
                if sockname:
                    self._ident_local_port = sockname[1]
                    ident_name = self.network_config.ident_username or self.username
                    self._ident_server.register(self._ident_local_port, ident_name)

            self.rate_limiter = RateLimiter(self.writer, self.network_config.rate_limit_ms)
            self.rate_limiter.start()

            self._read_task = asyncio.create_task(self._read_loop())
            await self._do_registration(sc)
            return

        # All servers failed
        logger.error("All servers failed for %s, scheduling reconnect", self.network_name)
        # Advance to next server for the reconnect attempt
        self._server_index = (self._server_index + 1) % len(servers)
        self._schedule_reconnect()

    async def disconnect(self, reason: str = "Disconnecting") -> None:
        """Gracefully disconnect from the server."""
        self._should_reconnect = False
        # Cancel any pending reconnect task first — otherwise a sleeping
        # reconnect wakes up after cleanup and opens a new connection.
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
            try:
                await self._reconnect_task
            except asyncio.CancelledError:
                pass
        self._reconnect_task = None
        if self.connected and self.writer:
            try:
                await self.send_now(IRCMessage(command="QUIT", params=[reason]))
            except (ConnectionError, OSError):
                pass
        await self._cleanup()

    async def update_rate_limit(self, interval_ms: int) -> None:
        """Update the rate limiter interval (requires recreating it)."""
        if self.rate_limiter and self.connected and self.writer:
            await self.rate_limiter.close()
            self.rate_limiter = RateLimiter(self.writer, interval_ms)
            self.rate_limiter.start()

    async def _cleanup(self) -> None:
        self.connected = False
        self.registered = False
        self._connected_at = None
        # Our channel membership belonged to the connection that just ended.
        # ChannelState.joined is set by our own JOIN echo and cleared by our
        # own PART or KICK -- all three are messages, and a dropped connection
        # sends none of them, so nothing else clears it.
        self.user.mark_network_parted(self.network_name)
        # Unregister from ident server
        if self._ident_server and self._ident_local_port is not None:
            self._ident_server.unregister(self._ident_local_port)
            self._ident_local_port = None
        if self.rate_limiter:
            await self.rate_limiter.close()
        if self._join_retry_task:
            self._join_retry_task.cancel()
            try:
                await self._join_retry_task
            except asyncio.CancelledError:
                pass
            self._join_retry_queue.clear()
        if self._read_task:
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                pass
        if self.writer:
            try:
                self.writer.close()
                # wait_closed() can hang indefinitely on TLS writers waiting
                # for the peer's close_notify. Bound it.
                await asyncio.wait_for(self.writer.wait_closed(), timeout=1.0)
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
        self.reader = None
        self.writer = None

    def _note_disconnect_reason(self, text: str) -> None:
        """Inspect a server ERROR / 465 reason and set an appropriate reconnect
        backoff floor.

        Bans (especially undernet's automatic "excessive connections" G-line)
        are renewed on every connection attempt made while still banned, so we
        must back off far longer than the ordinary reconnect cap and escalate
        if it keeps happening.  Throttling ("connecting too fast") gets a
        moderate floor.
        """
        # Normalise: undernet sends "G-lined", which does NOT contain the
        # substring "gline" because of the hyphen.  Strip all non-alphanumerics
        # so "G-lined" -> "glined", "K-line" -> "kline", etc. all match.
        compact = re.sub(r"[^a-z0-9]", "", text.lower())

        # "Excessive connections" auto-bans are a special case: they last up to
        # a day and renew on every contact, so they need a >24h backoff up front.
        is_exconn = "excessiveconnection" in compact
        is_ban = (
            is_exconn
            or "banned" in compact
            or "gline" in compact or "glined" in compact
            or "kline" in compact or "klined" in compact
            or "zline" in compact or "zlined" in compact
        )
        is_throttle = (
            "throttle" in compact
            or "toofast" in compact
            or "tryingtoreconnect" in compact
        )

        if is_ban:
            # Count at most one ban per connection (a single disconnect can
            # produce both a 465 numeric and an ERROR line).
            if not self._ban_noted_this_conn:
                self._ban_noted_this_conn = True
                self._consecutive_bans += 1
            # Excessive-connection bans start above a full day; generic bans of
            # unknown duration escalate from a smaller base.
            base = _EXCONN_BACKOFF_INITIAL if is_exconn else _BAN_BACKOFF_INITIAL
            floor = min(base * (2 ** (self._consecutive_bans - 1)), _BAN_BACKOFF_MAX)
            self._min_reconnect_delay = max(self._min_reconnect_delay, floor)
            logger.warning(
                "Banned from %s (reason: %r); backing off %.0fs (%.1fh) before "
                "next reconnect (ban #%d). Reconnecting sooner would renew the ban.",
                self.network_name, text.strip(), self._min_reconnect_delay,
                self._min_reconnect_delay / 3600.0, self._consecutive_bans,
            )
        elif is_throttle:
            self._min_reconnect_delay = max(self._min_reconnect_delay, _THROTTLE_BACKOFF)
            logger.warning(
                "Throttled on %s (reason: %r); backing off %.0fs before next reconnect.",
                self.network_name, text.strip(), self._min_reconnect_delay,
            )

    def _schedule_reconnect(self) -> None:
        if not self._should_reconnect:
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return  # A reconnect is already in progress
        # Capture the current delay for this attempt, then bump for next time.
        # The ban/throttle floor (_min_reconnect_delay) overrides the ordinary
        # exponential backoff so we don't renew a G-line by reconnecting early.
        delay = max(self._reconnect_delay, self._min_reconnect_delay)
        self._reconnect_delay = min(self._reconnect_delay * 2, _NORMAL_BACKOFF_MAX)
        self._reconnect_at = time.monotonic() + delay
        self._reconnect_task = asyncio.create_task(self._reconnect(delay))

    async def _reconnect(self, delay: float) -> None:
        await self._cleanup()
        if not self._should_reconnect:
            return
        logger.info("Reconnecting to %s in %.0fs", self.network_name, delay)
        await asyncio.sleep(delay)
        if not self._should_reconnect:
            return
        self._reconnect_task = None
        await self.connect()

    async def _read_loop(self) -> None:
        assert self.reader
        # Track whether the connection died uncleanly (a local socket/network
        # error) vs. a clean server-initiated close (EOF).  An unclean drop
        # leaves a "ghost" session on the server until its PING timeout; see
        # the reconnect-scheduling block below.
        unclean = False
        eof = False
        try:
            buf = b""
            while self.connected:
                data = await self.reader.read(4096)
                if not data:
                    eof = True
                    break  # clean EOF — the server closed the socket, so it
                           # knows we're gone and won't leave a ghost.
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    if not line:
                        continue
                    try:
                        msg = IRCMessage.parse(line)
                    except (ValueError, IndexError) as e:
                        logger.warning("Failed to parse: %r: %s", line, e)
                        continue
                    irc_log.debug("[%s/%s] <<< %s", self.user.username, self.network_name, line.decode("utf-8", errors="replace"))
                    try:
                        await self._handle_message(msg)
                    except Exception:
                        logger.exception("Error handling upstream message on %s: %s",
                                         self.network_name, line.decode("utf-8", errors="replace"))
        except (ConnectionError, OSError) as e:
            logger.warning("Connection lost to %s: %s", self.network_name, e)
            self._note_failure(f"connection to {self._dialing} lost: {e}")
            unclean = True
        except asyncio.CancelledError:
            return

        # The server closing the socket usually follows an ERROR, which said
        # more; keep that.  (The loop also ends when `connected` is cleared by
        # our own teardown, which has recorded its own reason.)
        said_why = (self.last_failure is not None and self._connected_at is not None
                    and self.last_failure[0] >= self._connected_at)
        if eof and not said_why:
            self._note_failure(f"{self._dialing} closed the connection")
        self.connected = False
        logger.info("Disconnected from %s", self.network_name)
        if self._should_reconnect:
            if unclean:
                # The socket died without the server's knowledge (e.g. a local
                # network abort).  The server keeps our old session alive as a
                # "ghost" until it times out the missing PINGs.  If we reconnect
                # before then, the ghost AND the new session both count against
                # the server's per-IP connection limit — which is exactly what
                # trips an "excessive connections" auto-ban (undernet ex-conn
                # G-line), especially when several clients on the same IP all
                # reconnect at once after a network blip.  Wait long enough for
                # the ghost to be reaped first.  (Clean EOF disconnects skip
                # this and reconnect promptly — there's no ghost.)
                ghost_delay = self.network_config.unclean_reconnect_delay
                if ghost_delay > 0:
                    self._min_reconnect_delay = max(self._min_reconnect_delay, ghost_delay)
                    logger.info(
                        "Unclean disconnect from %s; waiting %.0fs for the server "
                        "to reap the ghost session before reconnecting",
                        self.network_name, self._min_reconnect_delay,
                    )
            self._schedule_reconnect()

    def _note_join(self, msg: IRCMessage) -> None:
        """Remember the key a JOIN actually went out with.

        Every path that re-sends a JOIN -- the 439 retry loop and the rejoin
        after a reconnect -- used to ask the *autojoin config* for the key,
        which is a different question from "what did we join with".  A channel
        joined by hand may not be in that config at all, and one that is may be
        listed without its key (User._persist_autojoin dropped it), so the
        answer was None and the JOIN went out bare.  A +k channel answers a
        bare JOIN with 475 forever, however many times the user supplies the
        right key -- which is exactly what it looks like from the client: the
        key is typed once, works once, and is then apparently rejected.

        Recorded when the JOIN is handed to the socket rather than when its
        echo comes back, because the retry exists precisely for joins that
        have not succeeded yet.  A JOIN issued while we are down is recorded
        too, and deliberately: "the key we were last asked to use" is the
        answer the reconnect wants.
        """
        if msg.command != "JOIN" or not msg.params:
            return
        channels = msg.params[0].split(",")
        keys = msg.params[1].split(",") if len(msg.params) > 1 else []
        for i, chan in enumerate(channels):
            if not chan or chan == "0":     # "JOIN 0" means part everything
                continue
            key = keys[i] if i < len(keys) else ""
            if key:
                self._join_keys[chan.lower()] = key
            else:
                # A deliberate keyless join is an answer too: it says the
                # channel no longer needs one.
                self._join_keys.pop(chan.lower(), None)

    def remembered_key(self, channel: str) -> Optional[str]:
        """The key we last sent a JOIN for `channel` with, if any."""
        return self._join_keys.get(channel.lower())

    def key_for(self, channel: str) -> Optional[str]:
        """The key to use for `channel`: what we last joined with, else what
        the autojoin config says.  Names are compared case-insensitively, since
        the config carries whatever spelling the user typed."""
        key = self.remembered_key(channel)
        if key:
            return key
        for ch, k in self.network_config.autojoin.items():
            if ch.lower() == channel.lower() and k:
                return k
        return None

    async def send(self, msg: IRCMessage) -> None:
        """Send through rate limiter."""
        self._note_join(msg)
        if self.rate_limiter and self.connected:
            data = msg.serialize()
            irc_log.debug("[%s/%s] >>> %s", self.user.username, self.network_name, data.decode("utf-8", errors="replace").rstrip())
            await self.rate_limiter.send(data)

    async def send_now(self, msg: IRCMessage) -> None:
        """Send immediately, bypassing rate limiter."""
        self._note_join(msg)
        if self.writer and self.connected:
            data = msg.serialize()
            irc_log.debug("[%s/%s] >>> %s", self.user.username, self.network_name, data.decode("utf-8", errors="replace").rstrip())
            self.writer.write(data)
            await self.writer.drain()

    async def _do_registration(self, sc: ServerConfig | None = None) -> None:
        """Perform IRC registration: CAP LS, PASS, NICK, USER, SASL."""
        # Start capability negotiation
        await self.send_now(IRCMessage(command="CAP", params=["LS", "302"]))

        # Server password (server-level overrides network-level)
        server_pass = (sc.password if sc and sc.password else None) or self.network_config.password
        if server_pass:
            await self.send_now(IRCMessage(
                command="PASS", params=[server_pass]
            ))

        await self.send_now(IRCMessage(command="NICK", params=[self.nick]))
        await self.send_now(IRCMessage(
            command="USER", params=[self.username, "0", "*", self.realname]
        ))

    async def _handle_message(self, msg: IRCMessage) -> None:
        """Handle a message from the IRC server."""
        cmd = msg.command

        # ERROR from server — connection is about to close.  Adjust the
        # reconnect delay based on the reason so we don't hammer the server.
        if cmd == "ERROR":
            error_text = " ".join(msg.params)
            self._note_disconnect_reason(error_text)
            self._note_failure(f"{self._dialing} said: {error_text}")
            # Forward ERROR to downstream clients so the user sees it
            await self.user.route_upstream_message(self.network_name, msg)
            return

        # PING/PONG - respond immediately
        if cmd == "PING":
            await self.send_now(IRCMessage(command="PONG", params=msg.params))
            return

        # CAP negotiation
        if cmd == "CAP":
            await self._handle_cap(msg)
            return

        # AUTHENTICATE (SASL)
        if cmd == "AUTHENTICATE":
            await self._handle_authenticate(msg)
            return

        # SASL result
        if cmd in ("900", "903"):
            # SASL success
            self._sasl_in_progress = False
            logger.info("SASL authentication successful on %s", self.network_name)
            if self.cap.state == CapState.NEGOTIATING:
                await self.send_now(IRCMessage(command="CAP", params=["END"]))
                self.cap.state = CapState.DONE
            return

        if cmd in ("902", "904", "905", "906", "907"):
            # SASL failure
            self._sasl_in_progress = False
            logger.warning("SASL authentication failed on %s: %s", self.network_name, msg.params)
            if self.cap.state == CapState.NEGOTIATING:
                await self.send_now(IRCMessage(command="CAP", params=["END"]))
                self.cap.state = CapState.DONE
            return

        # ERR_YOUREBANNEDCREEP — the server is refusing us because we're banned
        # (e.g. undernet's automatic "excessive connections" G-line).  This
        # arrives just before the ERROR/closing-link line.  Note it for backoff,
        # then fall through so the user still sees the message.
        if cmd == "465":
            self._note_disconnect_reason(" ".join(msg.params))

        # Nick in use / collision - try fallback nicks
        if cmd in ("432", "433", "436") and not self.registered:
            await self._try_next_nick()
            return

        # Welcome numerics (001-005)
        if cmd in ("001", "002", "003", "004", "005"):
            self.welcome_msgs.append(msg)
            if cmd == "001":
                self.server_name = msg.source or ""
                # The nick we actually got
                if msg.params:
                    self.nick = msg.params[0]
                self.registered = True
                self.last_failure = None
                # Reset all backoff state on a successful registration.
                self._reconnect_delay = 1.0
                self._min_reconnect_delay = 0.0
                self._consecutive_bans = 0
                logger.info("Registered on %s as %s", self.network_name, self.nick)
            if cmd == "005":
                self._parse_isupport(msg)
            return

        # NICK change
        if cmd == "NICK" and msg.source:
            old_nick = IRCMessage.parse_prefix(msg.source)[0]
            new_nick = msg.params[0] if msg.params else old_nick
            if self._nick_eq(old_nick, self.nick):
                self.nick = new_nick

        # Successful JOIN by us — clear any pending retry for that channel
        if cmd == "JOIN" and msg.source and msg.params:
            joiner = IRCMessage.parse_prefix(msg.source)[0]
            if self._nick_eq(joiner, self.nick):
                joined = msg.params[0]
                self._join_retry_queue = [
                    e for e in self._join_retry_queue if e[0].lower() != joined.lower()
                ]

        # Target change too fast — schedule retry for JOIN
        if cmd in ("439", "480"):
            self._handle_target_too_fast(msg)
            # Still forward to user so clients see the error

        # Some servers send this as a 263 (RPL_TRYAGAIN)
        if cmd == "263":
            self._handle_target_too_fast(msg)

        # Forward to user for routing/storage
        await self.user.route_upstream_message(self.network_name, msg)

    async def _handle_cap(self, msg: IRCMessage) -> None:
        """Handle CAP subcommands."""
        if len(msg.params) < 2:
            return
        subcmd = msg.params[1].upper()

        if subcmd == "LS":
            # May have * as params[2] if multi-line
            is_multiline = len(msg.params) >= 3 and msg.params[2] == "*"
            cap_str = msg.params[3] if is_multiline else (msg.params[2] if len(msg.params) > 2 else "")
            self.cap.handle_ls(cap_str)

            if not is_multiline:
                # Request caps we want
                to_req = self.cap.get_caps_to_request()
                if to_req:
                    await self.send_now(IRCMessage(
                        command="CAP", params=["REQ", " ".join(to_req)]
                    ))
                else:
                    await self.send_now(IRCMessage(command="CAP", params=["END"]))
                    self.cap.state = CapState.DONE

        elif subcmd == "ACK":
            cap_str = msg.params[2] if len(msg.params) > 2 else ""
            newly_enabled = self.cap.handle_ack(cap_str)

            # If SASL was just enabled, start authentication
            if "sasl" in newly_enabled and self.network_config.sasl:
                self._sasl_in_progress = True
                mechanism = self.network_config.sasl.mechanism.upper()
                await self.send_now(IRCMessage(
                    command="AUTHENTICATE", params=[mechanism]
                ))
                return

            # Check if we need to request more caps
            more = self.cap.get_caps_to_request()
            if more:
                await self.send_now(IRCMessage(
                    command="CAP", params=["REQ", " ".join(more)]
                ))
            elif not self._sasl_in_progress and self.cap.state == CapState.NEGOTIATING:
                await self.send_now(IRCMessage(command="CAP", params=["END"]))
                self.cap.state = CapState.DONE

        elif subcmd == "NAK":
            cap_str = msg.params[2] if len(msg.params) > 2 else ""
            self.cap.handle_nak(cap_str)
            if not self._sasl_in_progress and self.cap.state == CapState.NEGOTIATING:
                await self.send_now(IRCMessage(command="CAP", params=["END"]))
                self.cap.state = CapState.DONE

        elif subcmd == "NEW":
            cap_str = msg.params[2] if len(msg.params) > 2 else ""
            to_req = self.cap.handle_new(cap_str)
            if to_req:
                await self.send_now(IRCMessage(
                    command="CAP", params=["REQ", " ".join(to_req)]
                ))

        elif subcmd == "DEL":
            cap_str = msg.params[2] if len(msg.params) > 2 else ""
            self.cap.handle_del(cap_str)

    async def _handle_authenticate(self, msg: IRCMessage) -> None:
        """Handle AUTHENTICATE challenge from server."""
        if not self.network_config.sasl:
            return
        if msg.params and msg.params[0] == "+":
            # Server is ready for our payload
            sasl = self.network_config.sasl
            chunks = get_sasl_payload(
                sasl.mechanism, sasl.username, sasl.password
            )
            for chunk in chunks:
                await self.send_now(IRCMessage(
                    command="AUTHENTICATE", params=[chunk]
                ))

    def _parse_isupport(self, msg: IRCMessage) -> None:
        """Parse RPL_ISUPPORT (005) tokens."""
        # Skip first param (nick) and last param (trailing text)
        for token in msg.params[1:-1]:
            if "=" in token:
                key, val = token.split("=", 1)
                self.isupport[key] = val
            else:
                self.isupport[token] = None

        if "PREFIX" in self.isupport:
            val = self.isupport["PREFIX"]
            if val and val.startswith("(") and ")" in val:
                # FORMAT: (ov)@+ -- letters and symbols pair up by position.
                modes, symbols = val[1:].split(")", 1)
                if modes and symbols and len(modes) == len(symbols):
                    self.prefix_modes = modes
                    self.nick_prefixes = symbols
                elif symbols:
                    # Malformed, but the symbols are still usable for parsing
                    # NAMES; leave the letters at their default rather than
                    # pairing them up wrongly.
                    self.nick_prefixes = symbols

        if "CHANMODES" in self.isupport:
            self.chan_modes = self.isupport["CHANMODES"] or ""

        if "CASEMAPPING" in self.isupport:
            self.casemapping = self.isupport["CASEMAPPING"] or "rfc1459"

    async def _try_next_nick(self) -> None:
        """Try the next nick candidate when the current one is taken."""
        self._nick_attempt_index += 1

        if self._nick_attempt_index < len(self._nick_candidates):
            # Use the next configured alt nick
            next_nick = self._nick_candidates[self._nick_attempt_index]
        else:
            # Exhausted all configured nicks, append underscores to the primary
            suffix_count = self._nick_attempt_index - len(self._nick_candidates) + 1
            next_nick = self.network_config.nick + ("_" * suffix_count)
            # Give up after 5 underscores
            if suffix_count > 5:
                logger.error("All nick attempts exhausted on %s", self.network_name)
                return

        logger.info("Nick in use on %s, trying: %s", self.network_name, next_nick)
        self.nick = next_nick
        await self.send_now(IRCMessage(command="NICK", params=[next_nick]))

    def _nick_eq(self, a: str, b: str) -> bool:
        """Case-insensitive nick comparison using server casemapping."""
        return a.lower() == b.lower()

    def _handle_target_too_fast(self, msg: IRCMessage) -> None:
        """Handle 'target change too fast' errors by scheduling a retry."""
        # Typical format: "439 nick #channel :Target change too fast. Please wait 67 seconds."
        # Or: "439 nick :Target change too fast. Please wait 67 seconds."
        if len(msg.params) < 2:
            return

        # Try to find the channel name in params
        target = None
        for param in msg.params[1:]:
            if param and param[0] in "#&!+":
                target = param
                break

        # Fallback: some ircds only mention the channel in the trailing text
        # (e.g. ":Target change too fast for #foo. Please wait 67 seconds.").
        if not target:
            text_match = re.search(r'([#&!+][^\s,:]+)', msg.params[-1])
            if text_match:
                target = text_match.group(1)

        if not target:
            logger.debug("439/480/263 received but no channel found: %s", msg.params)
            return

        # Try to parse delay from the message text
        delay = 10  # default retry delay
        last_param = msg.params[-1]
        match = re.search(r'(\d+)\s*seconds?', last_param, re.IGNORECASE)
        if match:
            delay = int(match.group(1)) + 2  # add a small buffer

        # The key we actually joined with, falling back to the config.  Asking
        # the config alone is what re-sent a bare JOIN to a +k channel.
        key = self.key_for(target)

        now = time.time()
        retry_at = now + delay

        # The server's target-change throttle is per-connection, not
        # per-channel.  When ANY join gets a 439, push ALL queued entries
        # forward so we don't immediately fire the next one and keep the
        # throttle timer from ever expiring.
        logger.debug("dedup target=%r queue=%r", target, [(e[0], round(e[2] - now, 1)) for e in self._join_retry_queue])

        found = False
        for i, (ch, k, old_at) in enumerate(self._join_retry_queue):
            if ch.lower() == target.lower():
                # The channel that just got 439: schedule it at retry_at
                self._join_retry_queue[i] = (ch, k if k is not None else key, retry_at)
                found = True
            elif old_at < retry_at:
                # Other channels scheduled before the cooldown expires:
                # push them back so they don't fire during the wait.
                # Spread them out by 2s each after retry_at so they
                # don't all fire at the same instant.
                self._join_retry_queue[i] = (ch, k, retry_at + 2 * (i + 1))

        if not found:
            self._join_retry_queue.append((target, key, retry_at))
            logger.info("Will retry JOIN %s on %s in %ds", target, self.network_name, delay)
        else:
            logger.info("439 for %s on %s — pushed ALL retries back by %ds", target, self.network_name, delay)

        # Start the retry task if not already running
        if self._join_retry_task is None or self._join_retry_task.done():
            self._join_retry_task = asyncio.create_task(self._join_retry_loop())

    async def _join_retry_loop(self) -> None:
        """Background task that retries queued JOINs after their delays."""
        try:
            while self._join_retry_queue and self.connected:
                # Find the earliest retry time
                self._join_retry_queue.sort(key=lambda x: x[2])
                channel, key, retry_at = self._join_retry_queue[0]
                now = time.time()
                if retry_at > now:
                    await asyncio.sleep(retry_at - now)
                if not self.connected:
                    break
                # Push retry_at far into the future as a placeholder so the
                # entry stays in the queue. If the server replies with another
                # 439, _handle_target_too_fast dedups onto this entry and
                # updates retry_at; if the JOIN succeeds, it'll be removed
                # from the queue when we see our own JOIN message.
                for i, (ch, k, _) in enumerate(self._join_retry_queue):
                    if ch.lower() == channel.lower():
                        self._join_retry_queue[i] = (ch, k, time.time() + 300)
                        break
                logger.info("Retrying JOIN %s on %s", channel, self.network_name)
                if key:
                    await self.send(IRCMessage(command="JOIN", params=[channel, key]))
                else:
                    await self.send(IRCMessage(command="JOIN", params=[channel]))
        except asyncio.CancelledError:
            pass

    async def join_channels(self) -> None:
        """Join all configured autojoin channels, with keys where specified."""
        if not self.network_config.autojoin:
            return
        # Separate channels with keys from those without, since JOIN
        # requires keys to correspond positionally to channels.
        # Send keyed channels first (IRC requires keys to match left-to-right).
        # key_for, not the raw config value: a channel joined by hand with a
        # key must be rejoined with it after a reconnect even when the config
        # was never told about it.
        pairs = [(ch, self.key_for(ch)) for ch in self.network_config.autojoin]
        keyed = [(ch, key) for ch, key in pairs if key]
        unkeyed = [ch for ch, key in pairs if not key]

        # Send keyed channels in batches
        for i in range(0, len(keyed), 4):
            batch = keyed[i : i + 4]
            chans = ",".join(ch for ch, _ in batch)
            keys = ",".join(k for _, k in batch)
            await self.send(IRCMessage(command="JOIN", params=[chans, keys]))

        # Send unkeyed channels in batches
        for i in range(0, len(unkeyed), 4):
            batch = unkeyed[i : i + 4]
            await self.send(IRCMessage(command="JOIN", params=[",".join(batch)]))

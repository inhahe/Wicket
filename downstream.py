"""Downstream connection from an IRC client to the bouncer."""

from __future__ import annotations
import asyncio
import hashlib
import logging
import re
import time
from collections import OrderedDict
from typing import TYPE_CHECKING, Optional

from irc_parser import IRCMessage
from cap import CapNegotiator, DOWNSTREAM_CAPS_AVAILABLE

if TYPE_CHECKING:
    from bouncer import Bouncer
    from user import User
    from upstream import UpstreamConnection

logger = logging.getLogger(__name__)
irc_log = logging.getLogger("irc_traffic")

# Password format: username@identifier/network:password
# @identifier is optional
PASS_RE = re.compile(
    r'^(?P<username>[^@/:\s]+)'
    r'(?:@(?P<identifier>[^/:\s]+))?'
    r'/(?P<network>[^:\s]+)'
    r':(?P<password>.+)$'
)


def parse_password(raw: str) -> tuple[str, str, str, str] | None:
    """Parse username@identifier/network:password.

    Returns (username, identifier, network, password) or None.
    Identifier defaults to '*' if not provided.
    """
    m = PASS_RE.match(raw)
    if not m:
        return None
    return (
        m.group("username"),
        m.group("identifier") or "*",
        m.group("network"),
        m.group("password"),
    )


def verify_password(given: str, stored: str) -> bool:
    """Verify a password against a stored hash or plaintext.

    Supports:
    - Plaintext comparison (if stored doesn't start with '$')
    - bcrypt hashes (if bcrypt is installed)
    """
    if stored.startswith("$2b$") or stored.startswith("$2a$"):
        try:
            import bcrypt
            return bcrypt.checkpw(given.encode("utf-8"), stored.encode("utf-8"))
        except ImportError:
            logger.warning("bcrypt not installed, cannot verify bcrypt hashes")
            return False
    # Plaintext fallback
    return given == stored


class DownstreamConnection:
    def __init__(self, bouncer: Bouncer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.bouncer = bouncer
        self.reader = reader
        self.writer = writer
        self.cap = CapNegotiator(is_upstream=False)
        self.extra_caps: set[str] = set()  # Pass-through caps from caps_wanted config
        self.downstream_caps_override: set[str] | None = None  # Full override from config

        self.user: Optional[User] = None
        self.upstream: Optional[UpstreamConnection] = None
        self.network: Optional[str] = None
        self.identifier: str = "*"
        self.nick: str = "*"
        self.username_str: str = "*"
        self.realname: str = ""

        self._raw_password: Optional[str] = None
        self._authenticated: bool = False
        self._registered: bool = False
        self._got_nick: bool = False
        self._got_user: bool = False
        self._cap_negotiating: bool = False
        self._closed: bool = False
        self._detached: bool = False
        self._read_task: Optional[asyncio.Task] = None
        self._ping_task: Optional[asyncio.Task] = None
        self._last_activity: float = time.monotonic()

        # Delivery watermark, used to persist read positions honestly.
        #
        # `last_written_id` is the highest stored message id we have handed to
        # writer.write(). That is NOT proof of delivery: a phone that has lost
        # its network keeps a socket that accepts writes for minutes before the
        # OS gives up, so bytes written to it can vanish.
        #
        # `confirmed_id` is the highest id the client has provably consumed. IRC
        # runs over a single ordered stream, so a client cannot parse our PING
        # without having already parsed everything written before it -- the
        # matching PONG therefore proves delivery of every message up to the
        # watermark captured when that PING was sent. Read positions advance to
        # `confirmed_id` and never past it.
        self.last_written_id: int = 0
        self.confirmed_id: int = 0
        self._pending_pings: "OrderedDict[str, int]" = OrderedDict()
        self._ping_seq: int = 0

    async def start(self) -> None:
        """Start handling this client connection."""
        peer = self.writer.get_extra_info("peername")
        logger.info("New client connection from %s", peer)
        await self._read_loop()

    async def _read_loop(self) -> None:
        try:
            buf = b""
            logger.debug("Read loop started for %s", self.writer.get_extra_info("peername"))
            while not self._closed:
                data = await self.reader.read(4096)
                if not data:
                    break
                self._last_activity = time.monotonic()
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.rstrip(b"\r")
                    if not line:
                        continue
                    try:
                        msg = IRCMessage.parse(line)
                    except (ValueError, IndexError) as e:
                        logger.debug("Failed to parse from client: %r: %s", line, e)
                        continue
                    irc_log.debug("[client %s/%s] <<< %s", self.nick, self.network or "?", line.decode("utf-8", errors="replace"))
                    try:
                        if not self._authenticated:
                            await self._handle_pre_auth(msg)
                        else:
                            await self._handle_message(msg)
                    except Exception:
                        logger.exception("Error handling client message from %s/%s: %s",
                                         self.nick, self.network or "?",
                                         line.decode("utf-8", errors="replace"))
        except (ConnectionError, OSError) as e:
            logger.debug("Client disconnected: %s", e)
        except asyncio.CancelledError:
            return
        finally:
            await self._on_disconnect()

    # How often the ping loop wakes to check liveness.
    _PING_CHECK_INTERVAL = 30
    # Send a PING once the client has been idle this long.
    _PING_IDLE = 60
    # Reap the connection once the client has been idle this long with no
    # response (covers unclean disconnects where reader.read() never returns).
    _PING_TIMEOUT = 180

    async def _ping_loop(self) -> None:
        """Periodically ping the client and reap dead connections.

        On an unclean client disconnect (e.g. a laptop sleeping or a network
        drop) the read loop stays blocked in ``reader.read()`` forever, so its
        ``finally`` never runs and read positions are never saved. This loop
        detects the dead connection via an activity timeout and forces the
        teardown (which persists read positions) explicitly.
        """
        try:
            while not self._closed:
                await asyncio.sleep(self._PING_CHECK_INTERVAL)
                if self._closed:
                    break
                idle = time.monotonic() - self._last_activity
                if idle >= self._PING_TIMEOUT:
                    logger.info(
                        "Client %s@%s/%s timed out (idle %.0fs); reaping",
                        self.nick, self.identifier, self.network or "?", idle,
                    )
                    await self._force_disconnect()
                    break
                # Ping when the client has gone quiet, and also whenever there is
                # unconfirmed data outstanding -- the PONG is what lets the read
                # position advance, so an active client still needs regular pings
                # or its backlog would be replayed again on every reconnect.
                if idle >= self._PING_IDLE or self.last_written_id > self.confirmed_id:
                    await self.send_confirm_ping()
                    if self._closed:
                        # send() detected a dead socket.
                        await self._force_disconnect()
                        break
        except asyncio.CancelledError:
            pass

    async def _force_disconnect(self) -> None:
        """Tear down an unresponsive/dead connection.

        Runs the idempotent ``_on_disconnect()`` (which saves read positions)
        and closes the writer to unblock any pending ``reader.read()`` in the
        read loop.
        """
        await self._on_disconnect()
        try:
            self.writer.close()
        except (OSError, ConnectionError):
            pass

    # Most pings we keep awaiting a PONG for. Clients answer in order, so a
    # handful is plenty; the cap just stops a silent client growing the dict.
    _MAX_PENDING_PINGS = 8

    def note_written(self, msg_id: int | None) -> None:
        """Record that a stored message was written to this client's socket.

        Only raises the watermark -- messages are written in id order per
        target, but replay interleaves targets, so ids can arrive out of order.
        """
        if msg_id and msg_id > self.last_written_id:
            self.last_written_id = msg_id

    async def send_confirm_ping(self) -> None:
        """Send a PING that, once answered, confirms delivery of everything
        written so far.

        The token carries no meaning beyond matching the reply; the guarantee
        comes from stream ordering, not the token itself.
        """
        self._ping_seq += 1
        token = f"wicket-{self._ping_seq}"
        self._pending_pings[token] = self.last_written_id
        while len(self._pending_pings) > self._MAX_PENDING_PINGS:
            self._pending_pings.popitem(last=False)
        await self.send(IRCMessage(command="PING", params=[token]))

    def handle_pong(self, msg: IRCMessage) -> None:
        """Promote the delivery watermark in response to a client PONG.

        Everything written before the matching PING has necessarily been parsed
        by the client, because it had to read past those bytes to see the PING.
        """
        if not self._pending_pings:
            return
        watermark: int | None = None
        for param in msg.params:
            if param in self._pending_pings:
                watermark = self._pending_pings.pop(param)
                break
        if watermark is None:
            # Some clients rewrite or drop the token (answering with the server
            # name instead). Fall back to the oldest outstanding ping: it is the
            # most conservative watermark still consistent with a reply.
            _, watermark = self._pending_pings.popitem(last=False)
        if watermark > self.confirmed_id:
            self.confirmed_id = watermark

    async def send(self, msg: IRCMessage) -> None:
        """Send a message to this client."""
        if self._closed:
            return
        try:
            data = msg.serialize()
            irc_log.debug("[client %s/%s] >>> %s", self.nick, self.network or "?", data.decode("utf-8", errors="replace").rstrip())
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError):
            self._closed = True

    async def send_raw(self, data: bytes) -> None:
        if self._closed:
            return
        try:
            self.writer.write(data)
            await self.writer.drain()
        except (ConnectionError, OSError):
            self._closed = True

    async def _handle_pre_auth(self, msg: IRCMessage) -> None:
        """Handle messages during pre-authentication phase."""
        cmd = msg.command

        if cmd == "CAP":
            await self._handle_cap(msg)
            return

        if cmd == "PASS" and msg.params:
            self._raw_password = msg.params[0]

        if cmd == "NICK" and msg.params:
            self.nick = msg.params[0]
            self._got_nick = True

        if cmd == "USER" and len(msg.params) >= 4:
            self.username_str = msg.params[0]
            self.realname = msg.params[3]
            self._got_user = True

        # Try to complete registration after any of PASS/NICK/USER
        if self._got_nick and self._got_user and self._raw_password and not self._cap_negotiating:
            await self._try_authenticate()

    async def _handle_cap(self, msg: IRCMessage) -> None:
        """Handle CAP commands from client."""
        if not msg.params:
            return

        subcmd = msg.params[0].upper()

        if subcmd == "LS":
            self._cap_negotiating = True
            version = msg.params[1] if len(msg.params) > 1 else "301"
            # Build available caps based on upstream
            upstream_caps = None
            # We don't know upstream yet during pre-auth, so advertise all
            cap_str = self.cap.build_advertise_string(
                upstream_caps,
                extra_caps=self.extra_caps or None,
                downstream_override=self.downstream_caps_override,
            )
            await self.send(IRCMessage(
                command="CAP", params=["*", "LS", cap_str],
                source=self.bouncer.config.server_name,
            ))

        elif subcmd == "REQ" and len(msg.params) > 1:
            requested = msg.params[1].split()
            ack = []
            nak = []
            for cap in requested:
                cap_name = cap.lstrip("-")
                if cap.startswith("-"):
                    self.cap.enabled.discard(cap_name)
                    ack.append(cap)
                elif cap_name in (self.downstream_caps_override if self.downstream_caps_override is not None else DOWNSTREAM_CAPS_AVAILABLE) or cap_name in self.extra_caps:
                    self.cap.enabled.add(cap_name)
                    ack.append(cap)
                else:
                    nak.append(cap)
            if ack:
                await self.send(IRCMessage(
                    command="CAP", params=["*", "ACK", " ".join(ack)],
                    source=self.bouncer.config.server_name,
                ))
            if nak:
                await self.send(IRCMessage(
                    command="CAP", params=["*", "NAK", " ".join(nak)],
                    source=self.bouncer.config.server_name,
                ))

        elif subcmd == "LIST":
            caps = " ".join(sorted(self.cap.enabled))
            await self.send(IRCMessage(
                command="CAP", params=[self.nick or "*", "LIST", caps],
                source=self.bouncer.config.server_name,
            ))

        elif subcmd == "END":
            self._cap_negotiating = False
            if self._got_nick and self._got_user:
                await self._try_authenticate()

    async def _try_authenticate(self) -> None:
        """Attempt to authenticate after receiving NICK, USER, and PASS."""
        if self._authenticated:
            return

        if not self._raw_password:
            await self._send_error("You must provide a password (PASS command)")
            await self.close()
            return

        parsed = parse_password(self._raw_password)
        if not parsed:
            await self._send_error(
                "Invalid password format. Expected: username@identifier/network:password "
                "or username/network:password"
            )
            await self.close()
            return

        username, identifier, network, password = parsed

        # Find user
        user = self.bouncer.users.get(username)
        if not user:
            await self._send_error("Unknown user")
            await self.close()
            return

        # Verify password
        if not verify_password(password, user.config.password):
            await self._send_error("Incorrect password")
            await self.close()
            return

        # Check network exists
        if network not in user.upstreams:
            available = ", ".join(user.config.networks.keys())
            await self._send_error(
                f"Unknown network '{network}'. Available networks: {available}"
            )
            await self.close()
            return

        # Kick off upstream connection in the background if not connected yet
        upstream = user.upstreams[network]
        if not upstream.connected and not upstream.registered:
            upstream._should_reconnect = True
            self._connect_task = asyncio.create_task(upstream.connect())
            # Store reference so it doesn't get GC'd
            self._connect_task.add_done_callback(lambda t: None)

        self._authenticated = True
        self.identifier = identifier

        # Populate caps overrides from network config
        nc = user.config.networks.get(network)
        if nc and nc.downstream_caps is not None:
            self.downstream_caps_override = set(nc.downstream_caps)
        if nc and nc.caps_wanted:
            upstream_enabled = upstream.cap.enabled if upstream.connected else set()
            for cap in nc.caps_wanted:
                if cap not in DOWNSTREAM_CAPS_AVAILABLE and (not upstream.connected or cap in upstream_enabled):
                    self.extra_caps.add(cap)
            # Notify client about newly available caps
            if self.extra_caps and not self._cap_negotiating:
                await self.send(IRCMessage(
                    command="CAP", params=[self.nick or "*", "NEW", " ".join(sorted(self.extra_caps))],
                    source=self.bouncer.config.server_name,
                ))

        # Attach to user/network
        success = await user.attach_downstream(self, network, identifier)
        if not success:
            await self._send_error(f"Failed to attach to network '{network}'")
            await self.close()
            return

        self._registered = True
        self._ping_task = asyncio.create_task(self._ping_loop())
        logger.info("Client authenticated: %s@%s/%s", username, identifier, network)

    async def _handle_message(self, msg: IRCMessage) -> None:
        """Handle messages from an authenticated client."""
        cmd = msg.command

        # CAP can be sent at any time
        if cmd == "CAP":
            await self._handle_cap(msg)
            return

        # PONG advances the delivery watermark. Handled here rather than in the
        # user router because that path returns early with "Not connected to X"
        # when the upstream is down, which would both spam the client and lose
        # the confirmation exactly when replay correctness matters most.
        if cmd == "PONG":
            self.handle_pong(msg)
            return

        # PING is answered locally, for the same reason.
        if cmd == "PING":
            await self.send(IRCMessage(
                command="PONG", params=msg.params,
                source=self.bouncer.config.server_name,
            ))
            return

        # Route through user
        if self.user:
            await self.user.route_downstream_message(self, msg)

    async def _send_error(self, text: str) -> None:
        await self.send(IRCMessage(
            command="ERROR", params=[text],
        ))

    # Longest we will wait for read positions to be persisted while tearing a
    # client down. The detach path is a handful of small SQLite round-trips, so
    # exceeding this means something is wedged -- and losing a read position
    # (which costs one extra replay) is far better than wedging the teardown,
    # which on 2026-08-21 held the whole bouncer open for nearly three minutes.
    _DETACH_TIMEOUT = 4.0

    async def _on_disconnect(self) -> None:
        """Handle client disconnection."""
        # Always detach (save read positions), even if close() was already called
        if not self._detached and self.user:
            self._detached = True
            # Run the detach as a separate task waited on with a deadline.
            # asyncio.wait (not wait_for) because wait_for cancels the inner
            # coroutine and then re-awaits it, which hangs forever if that
            # coroutine is itself stuck in something uncancellable -- exactly the
            # failure this deadline exists to bound. asyncio.wait always returns
            # when the timer fires, whatever the task is doing.
            detach = asyncio.create_task(self.user.detach_downstream(self))
            done, _pending = await asyncio.wait({detach}, timeout=self._DETACH_TIMEOUT)
            if not done:
                detach.cancel()  # best effort; deliberately not awaited
                logger.warning(
                    "Timed out saving read positions for %s@%s/%s; "
                    "some messages may replay on the next attach",
                    self.user.username, self.identifier, self.network or "?")
            elif not detach.cancelled() and detach.exception() is not None:
                logger.error("Error detaching %s@%s/%s: %s",
                             self.user.username, self.identifier,
                             self.network or "?", detach.exception())
            logger.info("Client disconnected: %s@%s/%s",
                        self.user.username, self.identifier, self.network)

        if self._closed:
            return
        self._closed = True

        self.stop_ping()

    def stop_ping(self) -> None:
        """Cancel the keepalive loop. Idempotent, and safe to call from anywhere.

        The ping task is created by the connection but owned by nobody else, so
        without an explicit stop it outlives its client: after shutdown cancelled
        the read loops on 2026-08-21 the ping loops kept PINGing dead sockets
        every 30s until their own 180s reap timer fired.
        """
        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()

    def abort(self) -> None:
        """Drop the socket immediately, without waiting for anything.

        Unlike ``close()``, this never awaits. ``close()`` awaits
        ``wait_closed()``, which on a half-open socket (a sleeping phone, a
        dropped mobile connection) blocks until the OS finally gives up -- so it
        is unusable on a shutdown path. ``transport.abort()`` sends an RST and
        tears the transport down synchronously, which is also what unblocks a
        ``reader.read()`` or ``drain()`` that cancellation alone did not reach.
        """
        self._closed = True
        self.stop_ping()
        try:
            transport = self.writer.transport
        except AttributeError:  # pragma: no cover - non-stream writer in tests
            transport = None
        try:
            if transport is not None and hasattr(transport, "abort"):
                transport.abort()
            else:
                self.writer.close()
        except (OSError, ConnectionError):
            pass

    async def close(self) -> None:
        """Close the connection."""
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (OSError, ConnectionError):
            pass
        self.stop_ping()

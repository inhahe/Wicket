"""Downstream connection from an IRC client to the bouncer."""

from __future__ import annotations
import asyncio
import hashlib
import logging
import re
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

    async def _ping_loop(self) -> None:
        """Periodically ping the client to detect disconnections."""
        try:
            while not self._closed:
                await asyncio.sleep(60)
                if self._closed:
                    break
                try:
                    await self.send(IRCMessage(
                        command="PING", params=[self.bouncer.config.server_name],
                    ))
                except (ConnectionError, OSError):
                    break
        except asyncio.CancelledError:
            pass

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

        # Route through user
        if self.user:
            await self.user.route_downstream_message(self, msg)

    async def _send_error(self, text: str) -> None:
        await self.send(IRCMessage(
            command="ERROR", params=[text],
        ))

    async def _on_disconnect(self) -> None:
        """Handle client disconnection."""
        # Always detach (save read positions), even if close() was already called
        if not self._detached and self.user:
            self._detached = True
            await self.user.detach_downstream(self)
            logger.info("Client disconnected: %s@%s/%s",
                        self.user.username, self.identifier, self.network)

        if self._closed:
            return
        self._closed = True

        if self._ping_task:
            self._ping_task.cancel()

    async def close(self) -> None:
        """Close the connection."""
        self._closed = True
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except (OSError, ConnectionError):
            pass
        if self._ping_task:
            self._ping_task.cancel()

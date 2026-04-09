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
        self.cap: CapNegotiator = CapNegotiator(
            is_upstream=True,
            extra_wanted=set(network_config.caps_wanted),
            override_caps=set(network_config.upstream_caps) if network_config.upstream_caps is not None else None,
        )

        self.nick: str = network_config.nick
        self.username: str = network_config.user
        self.realname: str = network_config.realname
        self.registered: bool = False
        self.connected: bool = False

        self.isupport: dict[str, str | None] = {}
        self.server_name: str = ""
        self.nick_prefixes: str = "@+"  # default
        self.chan_modes: str = ""
        self.casemapping: str = "rfc1459"

        # Registration numerics to replay to clients
        self.welcome_msgs: list[IRCMessage] = []

        # Nick fallback: build list of [primary, alt1, alt2, ..., primary_, primary__, ...]
        self._nick_candidates: list[str] = [network_config.nick] + list(network_config.alt_nicks)
        self._nick_attempt_index: int = 0

        # Server rotation
        self._server_index: int = 0

        self._read_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._reconnect_delay: float = 1.0
        self._sasl_mechanism: Optional[str] = None
        self._should_reconnect: bool = True

        # Track pending SASL
        self._sasl_in_progress: bool = False

        # Retry queue for channels that got "target change too fast"
        # list of (channel, key_or_none, retry_after_timestamp)
        self._join_retry_queue: list[tuple[str, str | None, float]] = []
        self._join_retry_task: Optional[asyncio.Task] = None

    async def connect(self) -> None:
        """Connect to the IRC server, trying each configured server in order."""
        servers = self.network_config.servers
        if not servers:
            logger.error("No servers configured for %s", self.network_name)
            return

        # Try each server starting from the current index
        for attempt in range(len(servers)):
            idx = (self._server_index + attempt) % len(servers)
            sc = servers[idx]
            logger.info("Connecting to %s:%d (TLS: %s) for %s/%s",
                         sc.host, sc.port, sc.tls, self.user.username, self.network_name)

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
                continue  # Try next server

            # Connected successfully
            self._server_index = idx
            self.connected = True
            self._reconnect_delay = 1.0

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

    def _schedule_reconnect(self) -> None:
        if self._should_reconnect and self._reconnect_task is None:
            self._reconnect_task = asyncio.create_task(self._reconnect())

    async def _reconnect(self) -> None:
        await self._cleanup()
        logger.info("Reconnecting to %s in %.0fs", self.network_name, self._reconnect_delay)
        await asyncio.sleep(self._reconnect_delay)
        self._reconnect_delay = min(self._reconnect_delay * 2, 300)
        self._reconnect_task = None
        # Reset state for new connection
        self.cap = CapNegotiator(
            is_upstream=True,
            extra_wanted=set(self.network_config.caps_wanted),
        )
        self.welcome_msgs = []
        self.registered = False
        self.nick = self.network_config.nick
        self._nick_attempt_index = 0
        await self.connect()

    async def _read_loop(self) -> None:
        assert self.reader
        try:
            buf = b""
            while self.connected:
                data = await self.reader.read(4096)
                if not data:
                    break
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
        except asyncio.CancelledError:
            return

        self.connected = False
        logger.info("Disconnected from %s", self.network_name)
        if self._should_reconnect:
            self._schedule_reconnect()

    async def send(self, msg: IRCMessage) -> None:
        """Send through rate limiter."""
        if self.rate_limiter and self.connected:
            data = msg.serialize()
            irc_log.debug("[%s/%s] >>> %s", self.user.username, self.network_name, data.decode("utf-8", errors="replace").rstrip())
            await self.rate_limiter.send(data)

    async def send_now(self, msg: IRCMessage) -> None:
        """Send immediately, bypassing rate limiter."""
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
            if val and ")" in val:
                # FORMAT: (ov)@+
                self.nick_prefixes = val.split(")")[1]

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

        if not target:
            return

        # Try to parse delay from the message text
        delay = 10  # default retry delay
        last_param = msg.params[-1]
        match = re.search(r'(\d+)\s*seconds?', last_param, re.IGNORECASE)
        if match:
            delay = int(match.group(1)) + 2  # add a small buffer

        # Look up the key for this channel from our autojoin config
        key = self.network_config.autojoin.get(target)
        # Also check case-insensitively
        if key is None:
            for ch, k in self.network_config.autojoin.items():
                if ch.lower() == target.lower():
                    key = k
                    break

        retry_at = time.time() + delay
        # Dedup: if this channel is already queued, just push its retry_at
        # forward instead of appending. Otherwise repeated 439s for the same
        # channel pile up and cause hammering.
        for i, (ch, k, _) in enumerate(self._join_retry_queue):
            if ch.lower() == target.lower():
                self._join_retry_queue[i] = (ch, k if k is not None else key, retry_at)
                logger.info("Pushing JOIN retry for %s on %s out by %ds", target, self.network_name, delay)
                break
        else:
            self._join_retry_queue.append((target, key, retry_at))
            logger.info("Will retry JOIN %s on %s in %ds", target, self.network_name, delay)

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
                        self._join_retry_queue[i] = (ch, k, now + 300)
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
        keyed = [(ch, key) for ch, key in self.network_config.autojoin.items() if key]
        unkeyed = [ch for ch, key in self.network_config.autojoin.items() if not key]

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

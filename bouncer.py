#!/usr/bin/env python3
"""Wicket IRC Bouncer - Main entry point."""

from __future__ import annotations
import argparse
import asyncio
import dataclasses
import io
import logging
import logging.handlers
import os
import signal
import ssl
import sys
from typing import Optional

from config import BouncerConfig, NetworkConfig, UserConfig, set_user_password
from database import Database
from ident import IdentServer
from downstream import DownstreamConnection
from upstream import UpstreamConnection
from user import User

logger = logging.getLogger(__name__)

# Top-level settings that only startup reads: the listening socket, the
# database, the ident server, and the server name each User is built with.
_RESTART_ONLY = frozenset({"listen", "database", "ident", "server_name"})

# Network settings used only while connecting and registering.  The rest act
# from the moment REHASH copies them (rate_limit_ms and auto_connect with
# work of their own).
_NETWORK_ON_RECONNECT = frozenset({
    "servers", "nick", "alt_nicks", "user", "ident_username", "realname",
    "password", "sasl", "caps_wanted", "upstream_caps",
})


class Bouncer:
    def __init__(self, config: BouncerConfig, config_path: str = "", cli_args=None):
        self.config = config
        self.config_path = config_path
        self._cli_args = cli_args
        self.db = Database(config.database)
        self.users: dict[str, User] = {}
        self._server: Optional[asyncio.Server] = None
        self._downstream_tasks: set[asyncio.Task] = set()
        # The connection objects behind those tasks. Cancelling a task is not
        # enough to tear a client down -- only closing its socket reliably
        # unblocks a pending read on a half-open connection -- and the task
        # alone gives no handle on the socket, so track the objects too.
        self._downstreams: set[DownstreamConnection] = set()
        self.ident_server: Optional[IdentServer] = None
        # Set once shutdown starts; fires when it has finished. Doubles as the
        # "already shutting down" flag so a second caller can wait rather than
        # race ahead of the first.
        self._shutdown_done: Optional[asyncio.Event] = None

    async def start(self) -> None:
        """Start the bouncer."""
        # Initialize database
        await self.db.connect()
        logger.info("Database initialized: %s", self.config.database)

        # Start ident server if enabled
        if self.config.ident.enabled:
            self.ident_server = IdentServer(
                self.config.ident.host, self.config.ident.port,
            )
            await self.ident_server.start()

        # Create user objects
        for uname, uconf in self.config.users.items():
            self.users[uname] = User(uconf, self.db, self.config.server_name, self.config_path)
            logger.info("Loaded user: %s (%d networks)",
                        uname, len(uconf.networks))

        # Set up TLS for the listener
        ssl_ctx = None
        if self.config.listen.tls:
            if not self.config.listen.tls_cert or not self.config.listen.tls_key:
                logger.error("TLS enabled but no cert/key configured. "
                             "Set listen.tls_cert and listen.tls_key, or set listen.tls: false")
                sys.exit(1)
            import os
            cert_path = self.config.listen.tls_cert
            key_path = self.config.listen.tls_key
            if not os.path.isfile(cert_path):
                logger.error("TLS certificate not found: %s", cert_path)
                sys.exit(1)
            if not os.path.isfile(key_path):
                logger.error("TLS private key not found: %s", key_path)
                sys.exit(1)
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            try:
                ssl_ctx.load_cert_chain(cert_path, key_path)
            except (ssl.SSLError, OSError) as e:
                logger.error("Failed to load TLS cert/key: %s", e)
                sys.exit(1)
            ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Start listening
        try:
            self._server = await asyncio.start_server(
                self._accept_client,
                self.config.listen.host,
                self.config.listen.port,
                ssl=ssl_ctx,
            )
        except OSError as e:
            logger.error("Could not bind to %s:%d: %s",
                         self.config.listen.host, self.config.listen.port, e)
            sys.exit(1)

        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        tls_str = " (TLS)" if ssl_ctx else " (plaintext)"
        logger.info("Bouncer listening on %s%s", addrs, tls_str)

        # Connect to upstream networks (after successful bind so we don't
        # spam connect/disconnect on networks if the listen port is in use)
        connect_tasks = []
        for uname, user in self.users.items():
            for nname, nconf in user.config.networks.items():
                upstream = UpstreamConnection(user, nconf, self.ident_server)
                user.upstreams[nname] = upstream
                if nconf.auto_connect:
                    connect_tasks.append(upstream.connect())
                    logger.info("Connecting to %s for %s", nname, uname)

        if connect_tasks:
            await asyncio.gather(*connect_tasks, return_exceptions=True)

        # Serve until cancelled
        async with self._server:
            await self._server.serve_forever()

    async def _accept_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new client connection."""
        ds = DownstreamConnection(self, reader, writer)
        task = asyncio.create_task(ds.start())
        self._downstream_tasks.add(task)
        self._downstreams.add(ds)

        def _finished(t: asyncio.Task, ds=ds) -> None:
            self._downstream_tasks.discard(t)
            self._downstreams.discard(ds)

        task.add_done_callback(_finished)

    async def rehash(self, requesting_ds=None) -> tuple[bool, list[str]]:
        """Reload config from disk and apply safe changes.

        Returns whether the reload went through, and the status messages to
        show, one line each: each becomes one NOTICE, so none may contain a
        line break.
        """
        if not self.config_path:
            return False, ["No config path available for rehash"]

        try:
            new_config = BouncerConfig.load(self.config_path)
        except Exception as e:
            msg = f"Failed to reload config, nothing was changed: {e}"
            logger.error(msg)
            # A YAML parse error or a ConfigError spans several lines.
            return False, msg.splitlines()

        messages: list[str] = []
        try:
            await self._apply_config(new_config, messages)
        except Exception as e:
            logger.exception("Rehash failed while applying the new config")
            messages.append(f"Rehash failed partway through: {e}")
            messages.append("Changes listed above were applied; the rest were not. "
                            "See the log for details.")
            return False, messages

        if not messages:
            messages.append("No changes detected")

        logger.info("Rehash complete: %d changes", len(messages))
        for msg in messages:
            logger.info("  Rehash: %s", msg)

        return True, messages

    async def _apply_config(self, new_config: BouncerConfig, messages: list[str]) -> None:
        """Apply `new_config` to the running bouncer, appending a line to
        `messages` for each change.

        Every field that differs is taken over, so no setting in the file is
        dropped; fields differ only in when they take effect, which the message
        says.  The exception is _RESTART_ONLY, kept at its running value so
        that every REHASH until the restart still reports it as pending.
        """
        if new_config.logging != self.config.logging:
            self.config.logging = new_config.logging
            _setup_logging(new_config, self._cli_args)
            messages.append("Logging configuration reloaded")

        for f in dataclasses.fields(BouncerConfig):
            if f.name in ("users", "logging"):
                continue
            new = getattr(new_config, f.name)
            if new == getattr(self.config, f.name):
                continue
            if f.name in _RESTART_ONLY:
                messages.append(f"{f.name} changed (takes effect when Wicket restarts)")
            else:
                # A cascading default; the loader has already applied it to
                # every user and network it reaches, which report it below.
                setattr(self.config, f.name, new)

        # Process users
        for uname, new_ucfg in new_config.users.items():
            if uname not in self.users:
                # New user
                self.users[uname] = User(new_ucfg, self.db, self.config.server_name, self.config_path)
                messages.append(f"Added new user: {uname}")
                # Create upstreams for new user
                for nname, nconf in new_ucfg.networks.items():
                    upstream = UpstreamConnection(self.users[uname], nconf, self.ident_server)
                    self.users[uname].upstreams[nname] = upstream
                    if nconf.auto_connect:
                        asyncio.create_task(upstream.connect())
                        messages.append(f"  Connecting to {nname} for {uname}")
                continue

            user = self.users[uname]
            old_ucfg = user.config

            for f in dataclasses.fields(UserConfig):
                if f.name in ("username", "networks"):
                    continue
                new = getattr(new_ucfg, f.name)
                if new == getattr(old_ucfg, f.name):
                    continue
                setattr(old_ucfg, f.name, new)
                # The rest are cascading defaults, reported by the networks
                # they reach.
                if f.name == "password":
                    messages.append(f"{uname}: password updated")
                elif f.name in ("delivery", "delivery_source"):
                    messages.append(f"{uname}: {f.name} changed to {new}")

            # Process networks
            for nname, new_ncfg in new_ucfg.networks.items():
                if nname not in old_ucfg.networks:
                    # New network
                    old_ucfg.networks[nname] = new_ncfg
                    upstream = UpstreamConnection(user, new_ncfg, self.ident_server)
                    user.upstreams[nname] = upstream
                    messages.append(f"{uname}: added network {nname}")
                    if new_ncfg.auto_connect:
                        asyncio.create_task(upstream.connect())
                        messages.append(f"{uname}: connecting to {nname}")
                    continue

                old_ncfg = old_ucfg.networks[nname]
                changed = [f.name for f in dataclasses.fields(NetworkConfig)
                           if getattr(old_ncfg, f.name) != getattr(new_ncfg, f.name)]
                # The upstream reads its config when it next connects
                # (UpstreamConnection._start_fresh), so copying is applying.
                for name in changed:
                    setattr(old_ncfg, name, getattr(new_ncfg, name))
                upstream = user.upstreams.get(nname)

                on_reconnect = [n for n in changed if n in _NETWORK_ON_RECONNECT]
                if on_reconnect:
                    messages.append(f"{uname}/{nname}: {', '.join(on_reconnect)} "
                                    f"changed (takes effect on reconnect)")
                live = [n for n in changed if n not in _NETWORK_ON_RECONNECT
                        and n not in ("rate_limit_ms", "auto_connect")]
                if live:
                    messages.append(f"{uname}/{nname}: {', '.join(live)} updated")

                if "rate_limit_ms" in changed:
                    if upstream and upstream.rate_limiter and upstream.connected:
                        await upstream.update_rate_limit(new_ncfg.rate_limit_ms)
                    messages.append(f"{uname}/{nname}: rate_limit_ms changed to {new_ncfg.rate_limit_ms}")

                # auto_connect is applied live, not just remembered for the next
                # startup. Turning it off is how you say "stay off undernet
                # until further notice" in a way that survives a restart, and it
                # would be useless if the network kept running (or kept
                # retrying) until you happened to restart Wicket. Only an actual
                # change acts, so an unrelated REHASH never disturbs a network
                # you took down by hand with DISCONNECT.
                if "auto_connect" in changed:
                    if upstream is None:
                        pass
                    elif new_ncfg.auto_connect:
                        if not upstream.connected and not upstream.reconnect_pending:
                            upstream._should_reconnect = True
                            asyncio.create_task(upstream.connect())
                            messages.append(f"{uname}/{nname}: auto_connect enabled, connecting")
                        else:
                            messages.append(f"{uname}/{nname}: auto_connect enabled")
                    else:
                        await upstream.disconnect("auto_connect disabled")
                        messages.append(f"{uname}/{nname}: auto_connect disabled, disconnected")

        # Warn about removed users (don't disconnect them)
        for uname in list(self.users.keys()):
            if uname not in new_config.users:
                messages.append(f"{uname}: removed from config (still active until restart)")

    async def shutdown(self) -> None:
        """Gracefully shut down the bouncer.

        Safe to call concurrently and repeatedly: on a signal the handler
        schedules this as its own task, and ``run()``'s ``finally`` calls it
        again once ``serve_forever()`` unwinds. A later caller *waits for* the
        first run instead of returning early -- returning early let ``run()``
        finish while shutdown was still in progress, and the process-level
        cleanup would then cancel it before it had closed the database.
        """
        if self._shutdown_done is not None:
            await self._shutdown_done.wait()
            return
        self._shutdown_done = asyncio.Event()
        try:
            await self._shutdown()
        finally:
            self._shutdown_done.set()

    async def _shutdown(self) -> None:
        logger.info("Shutting down...")

        # Stop accepting new connections
        if self._server:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=2.0)
            except asyncio.TimeoutError:
                pass

        # Disconnect all upstreams (with timeout)
        disconnect_tasks = []
        for user in self.users.values():
            for upstream in user.upstreams.values():
                disconnect_tasks.append(upstream.disconnect("Bouncer shutting down"))

        if disconnect_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*disconnect_tasks, return_exceptions=True),
                    timeout=5.0,
                )
            except asyncio.TimeoutError:
                logger.warning("Timed out waiting for upstream disconnects")

        # Stop ident server
        if self.ident_server:
            await self.ident_server.stop()

        # Disconnect downstream clients
        await self._shutdown_downstreams()

        # Close database
        await self.db.close()
        logger.info("Shutdown complete")

    # How long the graceful phase of downstream teardown gets: cancel the read
    # loops and let each one save its read positions on the way out. Kept longer
    # than DownstreamConnection._DETACH_TIMEOUT so that a client whose detach is
    # merely slow -- rather than wedged -- still gets to finish, and so that one
    # whose detach does hit its own ceiling unwinds inside this phase instead of
    # having its socket yanked a moment before it would have succeeded.
    DOWNSTREAM_TEARDOWN_TIMEOUT = 5.0
    # And how long they get after their sockets have been aborted, for the read
    # loop to notice the dead transport and unwind.
    DOWNSTREAM_ABORT_TIMEOUT = 5.0

    async def _shutdown_downstreams(self) -> None:
        """Tear down every connected client, under a hard deadline.

        Every step here is bounded on purpose. Cancelling a read loop does not
        guarantee it finishes: its ``finally`` still runs ``_on_disconnect()``,
        which persists read positions, and a client whose socket has gone
        black-hole (a sleeping phone, a dropped mobile connection) can leave
        that path -- or the pending ``reader.read()`` the cancel was aimed at --
        stuck for minutes. The old code waited on a bare ``gather()`` with no
        timeout, so on 2026-08-21 shutdown sat there for 2m45s and only finished
        when each client's own 180s ping-reap timer closed its socket for it.
        Shutdown must not depend on that timer, so nothing below waits forever.
        """
        # Stop the keepalive loops first. They are separate tasks that nothing
        # else cancels, so otherwise they go on PINGing dead sockets for as long
        # as the rest of the teardown takes.
        for ds in list(self._downstreams):
            ds.stop_ping()

        for task in list(self._downstream_tasks):
            task.cancel()
        if not self._downstream_tasks:
            return

        pending = await self._wait_downstream_tasks(self.DOWNSTREAM_TEARDOWN_TIMEOUT)
        if not pending:
            return

        logger.warning("%d client connection(s) did not shut down in %.0fs; "
                       "aborting their sockets", len(pending),
                       self.DOWNSTREAM_TEARDOWN_TIMEOUT)
        for ds in list(self._downstreams):
            ds.abort()

        pending = await self._wait_downstream_tasks(self.DOWNSTREAM_ABORT_TIMEOUT)
        if pending:
            # Abandon them: they cannot block the rest of shutdown. Log where
            # each one is stuck so the next occurrence diagnoses itself instead
            # of needing another live post-mortem.
            logger.warning("%d client connection(s) still stuck after abort; "
                           "abandoning them", len(pending))
            for task in pending:
                buf = io.StringIO()
                try:
                    task.print_stack(limit=12, file=buf)
                except Exception:  # pragma: no cover - diagnostics only
                    continue
                logger.warning("Stuck client task:\n%s", buf.getvalue())

    async def _wait_downstream_tasks(self, timeout: float) -> set[asyncio.Task]:
        """Wait up to `timeout` for the downstream tasks; return those still running.

        Uses asyncio.wait rather than wait_for(gather(...)) because wait_for
        cancels what it is waiting on and then re-awaits it, which never returns
        if a task swallows CancelledError -- precisely the case this exists to
        survive. asyncio.wait always returns when its timer fires.
        """
        tasks = set(self._downstream_tasks)
        if not tasks:
            return set()
        _done, pending = await asyncio.wait(tasks, timeout=timeout)
        return pending


def _setup_logging(config: BouncerConfig, args) -> None:
    """Configure logging from config file and CLI overrides."""
    log_cfg = config.logging

    # CLI -v flags override config level
    if args.verbose >= 2:
        level = logging.DEBUG
        log_cfg.log_irc = True
    elif args.verbose == 1:
        level = logging.DEBUG
    else:
        level = getattr(logging, log_cfg.level.upper(), logging.INFO)

    # Reconfigure root logger
    root = logging.getLogger()
    root.setLevel(level)

    # Clear any handlers from basicConfig
    root.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Always log to stderr
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(fmt)
    root.addHandler(stderr_handler)

    # Log file (CLI overrides config)
    log_file = args.log_file or log_cfg.file
    if log_file:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=log_cfg.max_bytes,
            backupCount=log_cfg.backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
        logger.info("Logging to file: %s", log_file)

    # If IRC traffic logging is off, silence the irc_traffic logger
    irc_traffic_logger = logging.getLogger("irc_traffic")
    if not log_cfg.log_irc:
        irc_traffic_logger.setLevel(logging.WARNING)
    else:
        irc_traffic_logger.setLevel(logging.DEBUG)
        logger.info("IRC traffic logging enabled")


def main() -> None:
    parser = argparse.ArgumentParser(description="Wicket IRC Bouncer")
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to YAML configuration file",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v for debug, -vv for debug + IRC traffic)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Log to file (overrides config file setting)",
    )
    parser.add_argument(
        "--set-password",
        nargs=2,
        metavar=("USERNAME", "PASSWORD"),
        help="Set a user's password (bcrypt-hashed) in the config file and exit",
    )
    args = parser.parse_args()

    # Minimal logging for --set-password (before config is loaded)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Handle --set-password: hash and save, then exit
    if args.set_password:
        username, password = args.set_password
        try:
            set_user_password(args.config, username, password)
            print(f"Password updated for user '{username}' in {args.config}")
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # Load config
    try:
        config = BouncerConfig.load(args.config)
    except Exception as e:
        logger.error("Failed to load config: %s", e)
        sys.exit(1)

    # Set up logging from config + CLI overrides
    _setup_logging(config, args)

    bouncer = Bouncer(config, config_path=args.config, cli_args=args)

    # Handle signals
    loop = asyncio.new_event_loop()

    async def run() -> None:
        # Set up signal handlers on Unix
        if sys.platform != "win32":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, lambda: asyncio.ensure_future(bouncer.shutdown()))
            loop.add_signal_handler(signal.SIGHUP, lambda: asyncio.ensure_future(bouncer.rehash()))
        else:
            # Windows: loop.add_signal_handler isn't supported. Install a
            # plain signal.signal handler that schedules shutdown on the
            # loop from the signal context (call_soon_threadsafe is signal-safe).
            def _win_sigint(_signum, _frame):
                loop.call_soon_threadsafe(lambda: asyncio.ensure_future(bouncer.shutdown()))
            signal.signal(signal.SIGINT, _win_sigint)

        try:
            await bouncer.start()
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            await bouncer.shutdown()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        # shutdown() has a guard against being called twice
        loop.run_until_complete(bouncer.shutdown())
    finally:
        # Cancel any remaining tasks. Use asyncio.wait (not wait_for+gather)
        # because wait_for re-awaits a cancelled coro, which hangs forever
        # if any task swallows CancelledError (e.g. shielded TLS I/O).
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            try:
                loop.run_until_complete(
                    asyncio.wait(pending, timeout=3.0)
                )
            except (asyncio.TimeoutError, KeyboardInterrupt):
                pass
        try:
            loop.close()
        except Exception:
            pass
        # Force-exit to avoid hanging on uncancellable background threads
        # (e.g. aiosqlite's worker thread). All meaningful cleanup is done.
        os._exit(0)


if __name__ == "__main__":
    main()

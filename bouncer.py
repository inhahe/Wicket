#!/usr/bin/env python3
"""Wicket IRC Bouncer - Main entry point."""

from __future__ import annotations
import argparse
import asyncio
import logging
import logging.handlers
import signal
import ssl
import sys
from typing import Optional

from config import BouncerConfig, set_user_password
from database import Database
from ident import IdentServer
from downstream import DownstreamConnection
from upstream import UpstreamConnection
from user import User

logger = logging.getLogger(__name__)


class Bouncer:
    def __init__(self, config: BouncerConfig, config_path: str = "", cli_args=None):
        self.config = config
        self.config_path = config_path
        self._cli_args = cli_args
        self.db = Database(config.database)
        self.users: dict[str, User] = {}
        self._server: Optional[asyncio.Server] = None
        self._downstream_tasks: set[asyncio.Task] = set()
        self.ident_server: Optional[IdentServer] = None

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
        task.add_done_callback(self._downstream_tasks.discard)

    async def rehash(self, requesting_ds=None) -> list[str]:
        """Reload config from disk and apply safe changes.

        Returns list of status messages.
        """
        if not self.config_path:
            return ["No config path available for rehash"]

        try:
            new_config = BouncerConfig.load(self.config_path)
        except Exception as e:
            msg = f"Failed to reload config: {e}"
            logger.error(msg)
            return [msg]

        messages = []

        # Update logging
        self.config.logging = new_config.logging
        _setup_logging(new_config, self._cli_args)
        messages.append("Logging configuration reloaded")

        # Update top-level cascading defaults
        self.config.nick = new_config.nick
        self.config.alt_nicks = new_config.alt_nicks
        self.config.user = new_config.user
        self.config.ident_username = new_config.ident_username
        self.config.realname = new_config.realname
        self.config.delivery = new_config.delivery
        self.config.delivery_source = new_config.delivery_source
        self.config.caps_wanted = new_config.caps_wanted
        self.config.upstream_caps = new_config.upstream_caps
        self.config.downstream_caps = new_config.downstream_caps
        self.config.rate_limit_ms = new_config.rate_limit_ms
        self.config.auto_connect = new_config.auto_connect
        self.config.replay_activity = new_config.replay_activity
        self.config.replay_activity_target = new_config.replay_activity_target

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

            # Safe user-level changes
            if old_ucfg.password != new_ucfg.password:
                old_ucfg.password = new_ucfg.password
                messages.append(f"{uname}: password updated")
            if old_ucfg.delivery != new_ucfg.delivery:
                old_ucfg.delivery = new_ucfg.delivery
                messages.append(f"{uname}: delivery changed to {new_ucfg.delivery}")
            if old_ucfg.delivery_source != new_ucfg.delivery_source:
                old_ucfg.delivery_source = new_ucfg.delivery_source
                messages.append(f"{uname}: delivery_source changed to {new_ucfg.delivery_source}")

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

                # Warn about changes that need reconnect
                reconnect_fields = []
                if old_ncfg.nick != new_ncfg.nick:
                    reconnect_fields.append("nick")
                if old_ncfg.user != new_ncfg.user:
                    reconnect_fields.append("user")
                if old_ncfg.realname != new_ncfg.realname:
                    reconnect_fields.append("realname")
                if old_ncfg.ident_username != new_ncfg.ident_username:
                    reconnect_fields.append("ident_username")
                if old_ncfg.sasl != new_ncfg.sasl:
                    reconnect_fields.append("sasl")
                if old_ncfg.servers != new_ncfg.servers:
                    reconnect_fields.append("servers")
                if reconnect_fields:
                    fields_str = ", ".join(reconnect_fields)
                    messages.append(
                        f"{uname}/{nname}: {fields_str} changed (takes effect on reconnect)"
                    )
                    # Still update the config so reconnect uses new values
                    old_ncfg.nick = new_ncfg.nick
                    old_ncfg.alt_nicks = new_ncfg.alt_nicks
                    old_ncfg.user = new_ncfg.user
                    old_ncfg.realname = new_ncfg.realname
                    old_ncfg.ident_username = new_ncfg.ident_username
                    old_ncfg.sasl = new_ncfg.sasl
                    old_ncfg.servers = new_ncfg.servers

                # Safe network-level changes
                if old_ncfg.rate_limit_ms != new_ncfg.rate_limit_ms:
                    old_ncfg.rate_limit_ms = new_ncfg.rate_limit_ms
                    upstream = user.upstreams.get(nname)
                    if upstream and upstream.rate_limiter and upstream.connected:
                        await upstream.update_rate_limit(new_ncfg.rate_limit_ms)
                    messages.append(f"{uname}/{nname}: rate_limit_ms changed to {new_ncfg.rate_limit_ms}")

                old_ncfg.autojoin = new_ncfg.autojoin
                old_ncfg.auto_connect = new_ncfg.auto_connect
                old_ncfg.caps_wanted = new_ncfg.caps_wanted
                old_ncfg.upstream_caps = new_ncfg.upstream_caps
                old_ncfg.downstream_caps = new_ncfg.downstream_caps
                old_ncfg.replay_activity = new_ncfg.replay_activity
                old_ncfg.replay_activity_target = new_ncfg.replay_activity_target
                old_ncfg.channel_replay_activity = new_ncfg.channel_replay_activity

        # Warn about removed users (don't disconnect them)
        for uname in list(self.users.keys()):
            if uname not in new_config.users:
                messages.append(f"{uname}: removed from config (still active until restart)")

        if not messages:
            messages.append("No changes detected")

        logger.info("Rehash complete: %d changes", len(messages))
        for msg in messages:
            logger.info("  Rehash: %s", msg)

        return messages

    async def shutdown(self) -> None:
        """Gracefully shut down the bouncer."""
        if hasattr(self, '_shutting_down'):
            return
        self._shutting_down = True
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

        # Cancel all downstream tasks and wait briefly
        for task in self._downstream_tasks:
            task.cancel()
        if self._downstream_tasks:
            await asyncio.gather(*self._downstream_tasks, return_exceptions=True)

        # Close database
        await self.db.close()
        logger.info("Shutdown complete")


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
        # Cancel any remaining tasks
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            try:
                loop.run_until_complete(asyncio.wait_for(
                    asyncio.gather(*pending, return_exceptions=True),
                    timeout=3.0,
                ))
            except (asyncio.TimeoutError, KeyboardInterrupt):
                pass
        loop.close()


if __name__ == "__main__":
    main()

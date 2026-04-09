"""RFC 1413 Ident server for the bouncer.

When enabled, responds to ident queries from IRC servers so that the
bouncer's upstream connections don't get the ~ prefix on their username.

The ident server tracks active upstream connections by their local port
and responds with the configured username for that connection.
"""

from __future__ import annotations
import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class IdentServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 113):
        self.host = host
        self.port = port
        self._server: Optional[asyncio.Server] = None
        # Maps local_port -> ident username
        self._ports: dict[int, str] = {}

    def register(self, local_port: int, username: str) -> None:
        """Register an ident response for a local port."""
        self._ports[local_port] = username
        logger.debug("Ident registered: port %d -> %s", local_port, username)

    def unregister(self, local_port: int) -> None:
        """Remove an ident registration."""
        self._ports.pop(local_port, None)
        logger.debug("Ident unregistered: port %d", local_port)

    async def start(self) -> None:
        """Start listening for ident queries."""
        try:
            self._server = await asyncio.start_server(
                self._handle_client, self.host, self.port,
            )
        except OSError as e:
            logger.warning("Could not start ident server on port %d: %s", self.port, e)
            return
        addrs = ", ".join(str(s.getsockname()) for s in self._server.sockets)
        logger.info("Ident server listening on %s", addrs)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("Ident server stopped")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a single ident query.

        Protocol (RFC 1413):
          Query:    <port-on-server>, <port-on-client>\r\n
          Response: <port-on-server>, <port-on-client> : USERID : UNIX : <userid>\r\n
          Error:    <port-on-server>, <port-on-client> : ERROR : NO-USER\r\n
        """
        try:
            # Read with a timeout — ident queries should be fast
            data = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not data:
                return

            line = data.decode("utf-8", errors="replace").strip()
            logger.debug("Ident query: %s", line)

            # Parse "serverport, clientport"
            parts = line.split(",")
            if len(parts) != 2:
                return

            try:
                server_port = int(parts[0].strip())
                client_port = int(parts[1].strip())
            except ValueError:
                return

            # Look up by the client port (our local port for the upstream connection)
            username = self._ports.get(client_port)
            if username:
                response = f"{server_port}, {client_port} : USERID : UNIX : {username}\r\n"
                logger.debug("Ident response: %s", response.strip())
            else:
                response = f"{server_port}, {client_port} : ERROR : NO-USER\r\n"
                logger.debug("Ident no match for local port %d", client_port)

            writer.write(response.encode("utf-8"))
            await writer.drain()
        except asyncio.TimeoutError:
            pass
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass

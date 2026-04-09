"""Rate-limited output buffer for IRC server connections."""

from __future__ import annotations
import asyncio
from typing import Optional


class RateLimiter:
    """Queues outgoing messages and sends them at a controlled rate."""

    def __init__(self, writer: asyncio.StreamWriter, interval_ms: int = 500):
        self._writer = writer
        self._interval = interval_ms / 1000.0
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._closed = False

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._drain_loop())

    async def send(self, data: bytes) -> None:
        """Enqueue data to be sent at the rate-limited pace."""
        if not self._closed:
            await self._queue.put(data)

    async def send_now(self, data: bytes) -> None:
        """Send data immediately, bypassing the rate limiter."""
        if not self._closed:
            self._writer.write(data)
            await self._writer.drain()

    async def _drain_loop(self) -> None:
        try:
            while not self._closed:
                data = await self._queue.get()
                if self._closed:
                    break
                self._writer.write(data)
                await self._writer.drain()
                if not self._queue.empty():
                    await asyncio.sleep(self._interval)
        except (ConnectionError, OSError):
            pass
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        self._closed = True
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        # Flush remaining
        while not self._queue.empty():
            try:
                data = self._queue.get_nowait()
                self._writer.write(data)
            except asyncio.QueueEmpty:
                break
        try:
            await asyncio.wait_for(self._writer.drain(), timeout=1.0)
        except (ConnectionError, OSError, asyncio.TimeoutError):
            pass

"""SQLite3 database for message history and per-identifier read positions."""

from __future__ import annotations
import aiosqlite
import time

from irc_parser import IRCMessage


class Database:
    def __init__(self, path: str):
        self.path = path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        self._conn = await aiosqlite.connect(self.path)
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._initialize()

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def _initialize(self) -> None:
        assert self._conn
        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT NOT NULL,
                network TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp REAL NOT NULL,
                source TEXT,
                command TEXT NOT NULL,
                raw_line BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_lookup
                ON messages(user, network, target, id);
            CREATE INDEX IF NOT EXISTS idx_messages_time
                ON messages(user, network, target, timestamp);

            CREATE TABLE IF NOT EXISTS read_positions (
                user TEXT NOT NULL,
                network TEXT NOT NULL,
                identifier TEXT NOT NULL,
                target TEXT NOT NULL,
                message_id INTEGER NOT NULL,
                PRIMARY KEY (user, network, identifier, target)
            );

            CREATE TABLE IF NOT EXISTS channel_state (
                user TEXT NOT NULL,
                network TEXT NOT NULL,
                channel TEXT NOT NULL,
                topic TEXT,
                topic_set_by TEXT,
                topic_set_at REAL,
                PRIMARY KEY (user, network, channel)
            );
        """)
        await self._conn.commit()

    async def store_message(
        self,
        user: str,
        network: str,
        target: str,
        msg: IRCMessage,
        timestamp: float | None = None,
    ) -> int:
        """Store a message and return its row ID."""
        assert self._conn
        if timestamp is None:
            timestamp = time.time()
        target = target.lower()
        raw = msg.serialize()
        source = msg.source or ""
        cursor = await self._conn.execute(
            "INSERT INTO messages (user, network, target, timestamp, source, command, raw_line) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (user, network, target, timestamp, source, msg.command, raw),
        )
        await self._conn.commit()
        return cursor.lastrowid  # type: ignore

    async def get_read_position(
        self, user: str, network: str, identifier: str, target: str
    ) -> int | None:
        """Get the last-read message ID for a user/network/identifier/target."""
        assert self._conn
        target = target.lower()
        cursor = await self._conn.execute(
            "SELECT message_id FROM read_positions "
            "WHERE user=? AND network=? AND identifier=? AND target=?",
            (user, network, identifier, target),
        )
        row = await cursor.fetchone()
        return row[0] if row else None

    async def set_read_position(
        self, user: str, network: str, identifier: str, target: str, message_id: int
    ) -> None:
        """Update the last-read message ID."""
        assert self._conn
        target = target.lower()
        await self._conn.execute(
            "INSERT OR REPLACE INTO read_positions (user, network, identifier, target, message_id) "
            "VALUES (?, ?, ?, ?, ?)",
            (user, network, identifier, target, message_id),
        )
        await self._conn.commit()

    async def get_messages_after(
        self,
        user: str,
        network: str,
        target: str,
        after_id: int,
        limit: int = 4096,
    ) -> list[tuple[int, float, bytes]]:
        """Get messages after a given ID. Returns list of (id, timestamp, raw_line)."""
        assert self._conn
        target = target.lower()
        cursor = await self._conn.execute(
            "SELECT id, timestamp, raw_line FROM messages "
            "WHERE user=? AND network=? AND target=? AND id>? "
            "ORDER BY id ASC LIMIT ?",
            (user, network, target, after_id, limit),
        )
        return await cursor.fetchall()

    async def get_messages_between(
        self,
        user: str,
        network: str,
        target: str,
        start_ts: float,
        end_ts: float,
        limit: int = 4096,
    ) -> list[tuple[int, float, bytes]]:
        """Get messages between two timestamps."""
        assert self._conn
        target = target.lower()
        cursor = await self._conn.execute(
            "SELECT id, timestamp, raw_line FROM messages "
            "WHERE user=? AND network=? AND target=? AND timestamp>=? AND timestamp<=? "
            "ORDER BY id ASC LIMIT ?",
            (user, network, target, start_ts, end_ts, limit),
        )
        return await cursor.fetchall()

    async def get_activity_after(
        self,
        user: str,
        network: str,
        targets: list[str],
        after_ids: dict[str, int],
        limit: int = 4096,
    ) -> list[tuple[int, str, float, bytes]]:
        """Get activity messages (JOIN/PART/KICK/MODE/NICK/QUIT) after read positions.

        Returns list of (id, target, timestamp, raw_line) sorted by id.
        targets: list of target names to query (already lowercased).
        after_ids: mapping of target -> last-read message id.
        """
        assert self._conn
        activity_cmds = ("JOIN", "PART", "KICK", "MODE", "NICK", "QUIT")
        results = []
        for target in targets:
            after_id = after_ids.get(target, 0)
            placeholders = ",".join("?" for _ in activity_cmds)
            cursor = await self._conn.execute(
                f"SELECT id, target, timestamp, raw_line FROM messages "
                f"WHERE user=? AND network=? AND target=? AND id>? "
                f"AND command IN ({placeholders}) "
                f"ORDER BY id ASC LIMIT ?",
                (user, network, target, after_id, *activity_cmds, limit),
            )
            rows = await cursor.fetchall()
            results.extend(rows)
        results.sort(key=lambda r: r[0])
        if len(results) > limit:
            results = results[:limit]
        return results

    async def get_all_targets(self, user: str, network: str) -> list[str]:
        """Get all targets (channels/nicks) that have stored messages."""
        assert self._conn
        cursor = await self._conn.execute(
            "SELECT DISTINCT target FROM messages WHERE user=? AND network=?",
            (user, network),
        )
        rows = await cursor.fetchall()
        return [r[0] for r in rows]

    async def get_latest_message_id(self, user: str, network: str, target: str) -> int | None:
        """Get the latest message ID for a target."""
        assert self._conn
        target = target.lower()
        cursor = await self._conn.execute(
            "SELECT MAX(id) FROM messages WHERE user=? AND network=? AND target=?",
            (user, network, target),
        )
        row = await cursor.fetchone()
        return row[0] if row and row[0] is not None else None

    async def save_channel_state(
        self, user: str, network: str, channel: str,
        topic: str | None = None, topic_set_by: str | None = None,
        topic_set_at: float | None = None
    ) -> None:
        assert self._conn
        channel = channel.lower()
        await self._conn.execute(
            "INSERT OR REPLACE INTO channel_state "
            "(user, network, channel, topic, topic_set_by, topic_set_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user, network, channel, topic, topic_set_by, topic_set_at),
        )
        await self._conn.commit()

    async def get_channel_state(
        self, user: str, network: str, channel: str
    ) -> tuple[str | None, str | None, float | None] | None:
        assert self._conn
        channel = channel.lower()
        cursor = await self._conn.execute(
            "SELECT topic, topic_set_by, topic_set_at FROM channel_state "
            "WHERE user=? AND network=? AND channel=?",
            (user, network, channel),
        )
        return await cursor.fetchone()

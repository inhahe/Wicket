"""IRC message parser and serializer with full IRCv3 tag support."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional


# IRCv3 tag value escaping
_TAG_ESCAPE_MAP = {
    "\\:": ";",
    "\\s": " ",
    "\\\\": "\\",
    "\\r": "\r",
    "\\n": "\n",
}

_TAG_UNESCAPE_MAP = {v: k for k, v in _TAG_ESCAPE_MAP.items()}


def _unescape_tag_value(value: str) -> str:
    result = []
    i = 0
    while i < len(value):
        if i + 1 < len(value) and value[i] == "\\":
            pair = value[i : i + 2]
            if pair in _TAG_ESCAPE_MAP:
                result.append(_TAG_ESCAPE_MAP[pair])
                i += 2
                continue
            # Unknown escape: drop the backslash
            result.append(value[i + 1])
            i += 2
            continue
        result.append(value[i])
        i += 1
    return "".join(result)


def _escape_tag_value(value: str) -> str:
    result = []
    for ch in value:
        if ch in _TAG_UNESCAPE_MAP:
            result.append(_TAG_UNESCAPE_MAP[ch])
        else:
            result.append(ch)
    return "".join(result)


@dataclass
class IRCMessage:
    command: str
    params: list[str] = field(default_factory=list)
    source: Optional[str] = None
    tags: dict[str, str | bool] = field(default_factory=dict)

    @staticmethod
    def parse(line: str | bytes) -> IRCMessage:
        """Parse an IRC message from a raw line.

        Handles IRCv3 message tags, source prefix, command, and parameters.
        Strips trailing \\r\\n if present.
        """
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        line = line.rstrip("\r\n")
        if not line:
            raise ValueError("Empty IRC message")

        tags: dict[str, str | bool] = {}
        source: str | None = None
        idx = 0

        # Parse tags
        if line[idx] == "@":
            space = line.index(" ", idx)
            raw_tags = line[idx + 1 : space]
            for tag_str in raw_tags.split(";"):
                if not tag_str:
                    continue
                if "=" in tag_str:
                    key, val = tag_str.split("=", 1)
                    tags[key] = _unescape_tag_value(val)
                else:
                    tags[tag_str] = True
            idx = space + 1
            # Skip extra spaces
            while idx < len(line) and line[idx] == " ":
                idx += 1

        # Parse source
        if idx < len(line) and line[idx] == ":":
            space = line.index(" ", idx)
            source = line[idx + 1 : space]
            idx = space + 1
            while idx < len(line) and line[idx] == " ":
                idx += 1

        # Parse command and params
        rest = line[idx:]
        params: list[str] = []
        while rest:
            if rest[0] == ":":
                params.append(rest[1:])
                break
            if " " in rest:
                param, rest = rest.split(" ", 1)
                params.append(param)
                # Skip extra spaces
                rest = rest.lstrip(" ")
            else:
                params.append(rest)
                break

        if not params:
            raise ValueError(f"No command in IRC message: {line!r}")

        command = params.pop(0).upper()
        return IRCMessage(command=command, params=params, source=source, tags=tags)

    def serialize(self) -> bytes:
        """Serialize this message to bytes suitable for sending on the wire.

        Returns the message with \\r\\n appended.
        """
        parts: list[str] = []

        if self.tags:
            tag_parts = []
            for key, val in self.tags.items():
                if val is True:
                    tag_parts.append(key)
                else:
                    tag_parts.append(f"{key}={_escape_tag_value(str(val))}")
            parts.append("@" + ";".join(tag_parts))

        if self.source:
            parts.append(":" + self.source)

        parts.append(self.command)

        for i, param in enumerate(self.params):
            if i == len(self.params) - 1 and (" " in param or param.startswith(":") or param == ""):
                parts.append(":" + param)
            else:
                parts.append(param)

        return (" ".join(parts) + "\r\n").encode("utf-8")

    @staticmethod
    def parse_prefix(source: str) -> tuple[str, str | None, str | None]:
        """Parse a source prefix into (nick, user, host).

        Handles formats:
        - nick
        - nick!user@host
        - nick@host
        """
        nick = source
        user = None
        host = None

        if "!" in nick:
            nick, rest = nick.split("!", 1)
            if "@" in rest:
                user, host = rest.split("@", 1)
            else:
                user = rest
        elif "@" in nick:
            nick, host = nick.split("@", 1)

        return nick, user, host

    def copy(self, **overrides) -> IRCMessage:
        """Return a shallow copy of this message with optional field overrides."""
        d = {
            "command": self.command,
            "params": list(self.params),
            "source": self.source,
            "tags": dict(self.tags),
        }
        d.update(overrides)
        return IRCMessage(**d)

    def __repr__(self) -> str:
        return f"IRCMessage({self.serialize().decode().strip()!r})"

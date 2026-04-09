"""IRCv3 capability negotiation for both upstream and downstream connections."""

from __future__ import annotations
import enum
import logging
from typing import Callable, Optional

from irc_parser import IRCMessage

logger = logging.getLogger(__name__)

# Capabilities the bouncer wants from upstream servers
UPSTREAM_CAPS_WANTED = {
    "message-tags",
    "server-time",
    "away-notify",
    "account-notify",
    "extended-join",
    "sasl",
    "labeled-response",
    "echo-message",
    "batch",
    "draft/chathistory",
    "chathistory",
    "draft/typing",
    "typing",
    "multi-prefix",
    "userhost-in-names",
    "cap-notify",
    "invite-notify",
    "setname",
    "account-tag",
    "chghost",
}

# Capabilities the bouncer advertises to downstream clients
DOWNSTREAM_CAPS_AVAILABLE = {
    "message-tags",
    "server-time",
    "away-notify",
    "account-notify",
    "extended-join",
    "labeled-response",
    "batch",
    "draft/typing",
    "typing",
    "multi-prefix",
    "userhost-in-names",
    "cap-notify",
    "invite-notify",
    "setname",
    "account-tag",
    "chghost",
    "sasl",
}

# Caps that only work if the upstream server also supports them.
# After auth, the bouncer sends CAP DEL for any of these the upstream lacks.
UPSTREAM_REQUIRED_CAPS = {
    "away-notify",
    "account-notify",
    "extended-join",
    "invite-notify",
    "setname",
    "account-tag",
    "chghost",
    "draft/typing",
    "typing",
}


class CapState(enum.Enum):
    NEGOTIATING = "negotiating"
    DONE = "done"


class CapNegotiator:
    """Tracks capability negotiation state."""

    def __init__(
        self, is_upstream: bool = True,
        extra_wanted: set[str] | None = None,
        override_caps: set[str] | None = None,
    ):
        self.is_upstream = is_upstream
        self.advertised: dict[str, str | None] = {}  # cap -> value or None
        self.enabled: set[str] = set()
        self.state = CapState.NEGOTIATING
        self._extra_wanted = extra_wanted or set()
        self._override_caps = override_caps  # If set, replaces the defaults entirely

    @property
    def wanted(self) -> set[str]:
        if self.is_upstream:
            base = self._override_caps if self._override_caps is not None else UPSTREAM_CAPS_WANTED
            return base | self._extra_wanted
        return set()  # downstream: we don't request caps, we advertise them

    def get_caps_to_request(self) -> set[str]:
        """Return caps we want that the server advertises."""
        available = set(self.advertised.keys())
        return self.wanted & available - self.enabled

    def handle_ls(self, cap_str: str) -> None:
        """Process a CAP LS response."""
        for token in cap_str.split():
            if "=" in token:
                name, value = token.split("=", 1)
                self.advertised[name] = value
            else:
                self.advertised[token] = None

    def handle_ack(self, cap_str: str) -> set[str]:
        """Process a CAP ACK response. Returns newly enabled caps."""
        newly_enabled = set()
        for token in cap_str.split():
            cap = token.lstrip("-")
            if token.startswith("-"):
                self.enabled.discard(cap)
            else:
                self.enabled.add(cap)
                newly_enabled.add(cap)
        return newly_enabled

    def handle_nak(self, cap_str: str) -> None:
        """Process a CAP NAK response."""
        for token in cap_str.split():
            logger.debug("CAP NAK: %s", token)

    def handle_new(self, cap_str: str) -> set[str]:
        """Process a CAP NEW notification. Returns caps we should request."""
        self.handle_ls(cap_str)
        return self.get_caps_to_request()

    def handle_del(self, cap_str: str) -> None:
        """Process a CAP DEL notification."""
        for token in cap_str.split():
            self.advertised.pop(token, None)
            self.enabled.discard(token)

    def build_advertise_string(
        self, upstream_enabled: set[str] | None = None,
        extra_caps: set[str] | None = None,
        downstream_override: set[str] | None = None,
    ) -> str:
        """Build the CAP LS response string for downstream clients.

        downstream_override: if set, completely replaces DOWNSTREAM_CAPS_AVAILABLE.
        extra_caps: additional pass-through caps from caps_wanted config.
        upstream_enabled: if given, only advertise caps the upstream has.
        """
        caps = downstream_override if downstream_override is not None else set(DOWNSTREAM_CAPS_AVAILABLE)
        if extra_caps:
            caps |= extra_caps
        if upstream_enabled is not None:
            bouncer_only = {"sasl", "batch"}
            caps = (caps & upstream_enabled) | (caps & bouncer_only)
            if extra_caps:
                caps |= (extra_caps & upstream_enabled)
        return " ".join(sorted(caps))

    def supports(self, cap: str) -> bool:
        """Check if a capability is currently enabled."""
        return cap in self.enabled

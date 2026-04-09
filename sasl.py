"""SASL authentication for upstream IRC connections."""

from __future__ import annotations
import asyncio
import base64
import logging

from irc_parser import IRCMessage

logger = logging.getLogger(__name__)

# Max AUTHENTICATE chunk size per IRC spec
SASL_CHUNK_SIZE = 400


def build_plain_response(username: str, password: str, authzid: str = "") -> str:
    """Build a SASL PLAIN response (base64-encoded)."""
    payload = f"{authzid}\0{username}\0{password}"
    return base64.b64encode(payload.encode("utf-8")).decode("ascii")


def build_external_response() -> str:
    """Build a SASL EXTERNAL response."""
    return "+"


async def perform_sasl(
    send_func,
    mechanism: str,
    username: str = "",
    password: str = "",
) -> None:
    """Send the AUTHENTICATE command with the appropriate payload.

    The caller is responsible for handling 903/904/905 responses.
    """
    await send_func(IRCMessage(command="AUTHENTICATE", params=[mechanism]))

    # The actual AUTHENTICATE response will be sent when we receive
    # AUTHENTICATE + from the server. We store the credentials for later.
    # This is handled in upstream.py's message handler.


def get_sasl_payload(mechanism: str, username: str, password: str) -> list[str]:
    """Get the SASL payload chunks to send.

    Returns a list of base64 strings, each <= 400 chars, with '+' appended
    if the last chunk is exactly 400 chars.
    """
    if mechanism.upper() == "PLAIN":
        encoded = build_plain_response(username, password)
    elif mechanism.upper() == "EXTERNAL":
        encoded = build_external_response()
    else:
        raise ValueError(f"Unsupported SASL mechanism: {mechanism}")

    if encoded == "+":
        return ["+"]

    chunks = []
    for i in range(0, len(encoded), SASL_CHUNK_SIZE):
        chunks.append(encoded[i : i + SASL_CHUNK_SIZE])

    # If the last chunk is exactly 400 chars, append '+' to signal end
    if len(chunks[-1]) == SASL_CHUNK_SIZE:
        chunks.append("+")

    return chunks

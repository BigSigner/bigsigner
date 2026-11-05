"""Read a PSBT from the QR and file formats SeedSigner and Specter-DIY scan.

A single code or file may be base64 (the usual text form), Electrum's base43,
or a binary PSBT whose text form still begins with the PSBT magic. A sequence
may be:

- Specter-DIY ``pMofN <base64 chunk>``
- a Blockchain Commons ``ur:crypto-psbt`` or legacy ``ur:bytes`` sequence
- a BBQr whose file type is ``P`` (PSBT)

SeedSigner scans all of those. Specter-DIY scans the Specter parts, both UR
forms, and base64. Neither project publishes one shared byte cap. A decoded
PSBT is refused above 100000 bytes, and a Specter sequence above 1295 parts,
which is BBQr's own maximum. That keeps one QR sequence from exhausting memory.
"""

import base64
import re

from .message_sign import starts_with_signmessage_command
from .scan import classify_content, wrong_type_message
from .session import SessionError

PSBT_MAX_BYTES = 100_000
PSBT_MAX_PARTS = 1295
TOO_LARGE = "This PSBT is too large for this hardware wallet."
UNREADABLE = "The PSBT could not be read."
_MAGIC = b"psbt\xff"
_SPECTER = re.compile(r"\Ap(\d+)of(\d+) (.+)\Z", re.IGNORECASE | re.DOTALL)
_BASE43 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:"


class SpecterParts:
    """The ``pMofN`` parts of one Specter-DIY animated PSBT."""

    def __init__(self):
        self.parts: dict[int, str] = {}
        self.count = 0

    def reset(self):
        self.parts = {}
        self.count = 0

    @property
    def received(self) -> int:
        return len(self.parts)

    def add(self, index: int, count: int, chunk: str) -> str | None:
        if count < 1 or count > PSBT_MAX_PARTS or index < 1 or index > count:
            raise SessionError("This QR sequence is unsupported by this hardware wallet.")
        if self.count not in (0, count):
            raise SessionError("This QR sequence is unsupported by this hardware wallet.")
        previous = self.parts.get(index)
        if previous is not None and previous != chunk:
            raise SessionError("This QR sequence is unsupported by this hardware wallet.")
        self.count = count
        self.parts[index] = chunk
        if len(self.parts) < count:
            return None
        return "".join(self.parts[number] for number in range(1, count + 1))


def psbt_bytes(text: str) -> bytes:
    """The decoded PSBT, or an error when the text is not one or is too large."""
    compact = "".join(str(text).split())
    raw = _decode_base64(compact)
    if raw is None:
        raw = _decode_base43(compact)
    if raw is None or not raw.startswith(_MAGIC):
        raise SessionError(UNREADABLE)
    if len(raw) > PSBT_MAX_BYTES:
        raise SessionError(TOO_LARGE)
    return raw


def psbt_text(text: str) -> str:
    """Base64 of a PSBT, which is the form the rest of the app stores."""
    return base64.b64encode(psbt_bytes(text)).decode("ascii")


def explain_not_psbt(text: str, source: str, network: str) -> str:
    """Name a seed, message, or other payload that was offered as a PSBT."""
    stripped = str(text).strip()
    if starts_with_signmessage_command(stripped):
        return f"This is a sign-message command, not a PSBT."
    try:
        parsed = classify_content(stripped, network)
    except SessionError as exc:
        return str(exc)
    return wrong_type_message(parsed.kind, "psbt", source, network)


def _decode_base64(text: str) -> bytes | None:
    if not text:
        return None
    padded = text + ("=" * ((4 - len(text) % 4) % 4))
    try:
        return base64.b64decode(padded, validate=False)
    except Exception:
        return None


def _decode_base43(text: str) -> bytes | None:
    if not text or any(char not in _BASE43 for char in text):
        return None
    value = 0
    power = 1
    for char in reversed(text):
        value += _BASE43.index(char) * power
        power *= 43
    if value == 0:
        return b"\x00"
    raw = bytearray()
    while value:
        value, byte = divmod(value, 256)
        raw.append(byte)
    return bytes(reversed(raw))

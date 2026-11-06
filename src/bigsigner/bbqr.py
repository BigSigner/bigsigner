"""BBQr decoder. The format is the public-domain specification from Coinkite."""

import base64
import zlib

from .session import SessionError

_HEADER = 8


class BbqrError(ValueError):
    pass


def encode_bbqr(data: bytes, *, chunk: int = 100) -> list[str]:
    """BBQr parts for a PSBT. The payload is raw deflate, then base32, file type P."""
    compressor = zlib.compressobj(level=9, wbits=-10)
    raw = compressor.compress(data) + compressor.flush()
    pieces = [raw[index : index + chunk] for index in range(0, len(raw), chunk)] or [b""]
    if len(pieces) > 1295:
        raise BbqrError("This PSBT needs too many BBQr parts.")
    count = _base36(len(pieces))
    parts = []
    for index, piece in enumerate(pieces):
        encoded = base64.b32encode(piece).decode("ascii").rstrip("=")
        parts.append(f"B$ZP{count}{_base36(index)}{encoded}")
    return parts


def _base36(value: int) -> str:
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return alphabet[value // 36] + alphabet[value % 36]


def split_bbqr(text: str) -> tuple[str, str, int, int, str]:
    """Return encoding, file type, part count, part index, and the payload characters."""
    body = "".join(text.split()).upper()
    if not body.startswith("B$") or len(body) < _HEADER:
        raise BbqrError("This BBQr could not be read.")
    encoding = body[2]
    file_type = body[3]
    if encoding not in "H2Z" or not body[4:8].isalnum():
        raise BbqrError("This BBQr could not be read.")
    try:
        count = int(body[4:6], 36)
        index = int(body[6:8], 36)
    except ValueError as exc:
        raise BbqrError("This BBQr could not be read.") from exc
    if count < 1 or count > 1295 or index >= count:
        raise BbqrError("This BBQr could not be read.")
    return encoding, file_type, count, index, body[8:]


def join_bbqr(parts: list[str], encoding: str) -> bytes:
    if encoding == "H":
        try:
            return b"".join(bytes.fromhex(part) for part in parts)
        except ValueError as exc:
            raise BbqrError("This BBQr could not be read.") from exc
    raw = b""
    try:
        for part in parts:
            padding = (8 - (len(part) % 8)) % 8
            raw += base64.b32decode(part + ("=" * padding), casefold=True)
    except Exception as exc:
        raise BbqrError("This BBQr could not be read.") from exc
    if encoding == "2":
        return raw
    if encoding == "Z":
        try:
            return zlib.decompress(raw, wbits=-10)
        except zlib.error as exc:
            raise BbqrError("This BBQr could not be read.") from exc
    raise BbqrError("This BBQr could not be read.")


def text_from_bbqr(file_type: str, raw: bytes, expect: str, source: str) -> str:
    del expect, source
    if file_type in ("U", "J"):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SessionError("This BBQr could not be read.") from exc
    if file_type in ("P", "T"):
        return base64.b64encode(raw).decode("ascii")
    raise SessionError("This QR code uses a format this version does not read.")

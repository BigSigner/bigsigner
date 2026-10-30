"""BBQr decoder. The format is the public-domain specification from Coinkite."""

import base64
import zlib

from .session import SessionError

_HEADER = 8


class BbqrError(ValueError):
    pass


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
    if file_type == "U":
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SessionError("This BBQr could not be read.") from exc
    if file_type == "J":
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SessionError("This BBQr could not be read.") from exc
    if file_type == "P":
        return base64.b64encode(raw).decode("ascii")
    if file_type == "T":
        if expect == "descriptor":
            raise SessionError("This is a transaction, not a wallet descriptor.")
        raise SessionError(f"That {source} is a transaction, not a key.")
    raise SessionError("This QR code uses a format this version does not read.")

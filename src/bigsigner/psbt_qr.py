"""QR payloads for a signed PSBT.

The formats are the ones Load Transaction already reads: an Animated UR,
one Static UR when it fits, one base64 code when it fits, a Specter Animated
code, and BBQr.
"""

import base64
import zlib

from .bbqr import encode_bbqr
from .fountain import FountainDecoder, part_from_cbor
from .qr import qr_matrix
from .ur import _array, _bstr, _uint, encode_minimal, encode_ur

_CHUNK = 200


def psbt_qr_parts(raw: bytes, kind: str) -> list[str]:
    """The QR texts for one format. Base64 is a single code, or empty when it does not fit."""
    if kind == "base64":
        text = base64.b64encode(raw).decode("ascii")
        return [text] if _fits(text) else []
    if kind == "specter":
        text = base64.b64encode(raw).decode("ascii")
        chunks = [text[index : index + _CHUNK] for index in range(0, len(text), _CHUNK)] or [""]
        count = len(chunks)
        return [f"p{index + 1}of{count} {chunk}" for index, chunk in enumerate(chunks)]
    if kind == "bbqr":
        return encode_bbqr(raw, chunk=_CHUNK)
    if kind == "ur":
        single = encode_ur("crypto-psbt", _bstr(raw))
        return [single] if _fits(single) else []
    if kind == "animated-ur":
        return _animated_ur_parts(raw)
    raise ValueError(kind)


def _fits(text: str) -> bool:
    try:
        qr_matrix(text)
    except Exception:
        return False
    return True


def _animated_ur_parts(raw: bytes) -> list[str]:
    """A fountain sequence of at least two crypto-psbt parts."""
    message = _bstr(raw)
    width = 80
    if len(message) <= width:
        width = max(1, (len(message) + 1) // 2)
    return _fountain_parts(message, width)


def _fountain_parts(message: bytes, width: int) -> list[str]:
    count = max(1, (len(message) + width - 1) // width)
    padded = message + (b"\x00" * (count * width - len(message)))
    checksum = zlib.crc32(message) & 0xFFFFFFFF
    parts = []
    for index in range(count):
        chunk = padded[index * width : (index + 1) * width]
        body = _array(
            [
                _uint(index + 1),
                _uint(count),
                _uint(len(message)),
                _uint(checksum),
                _bstr(chunk),
            ]
        )
        parts.append(f"ur:crypto-psbt/{index + 1}-{count}/{encode_minimal(body)}")
    return parts


def _ur_parts(raw: bytes) -> list[str]:
    single = encode_ur("crypto-psbt", _bstr(raw))
    if _fits(single):
        return [single]
    return _fountain_parts(_bstr(raw), 80)


def ur_parts_round_trip(raw: bytes, parts: list[str] | None = None) -> bytes:
    """The PSBT bytes a scanner would recover from the UR parts. Used by tests."""
    if parts is None:
        parts = _ur_parts(raw)
    if len(parts) == 1:
        from .ur import decode_ur, text_from_ur

        kind, cbor = decode_ur(parts[0])
        import base64 as _b64

        text = text_from_ur(kind, cbor, "main")
        return _b64.b64decode(text)
    decoder = FountainDecoder()
    for part in parts:
        from .ur import split_ur

        _kind, _seq, payload = split_ur(part)
        seq_num, seq_len, message_len, checksum, data = part_from_cbor(payload)
        decoder.receive(seq_num, seq_len, message_len, checksum, data)
    if decoder.message is None:
        raise AssertionError("UR parts did not rebuild")
    from .ur import cbor_decode

    return cbor_decode(decoder.message)

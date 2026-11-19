"""Turn one OpenPGP secret key into a single-subkey export.

GnuPG's ``--export-secret-subkeys FINGERPRINT!`` keeps that subkey's secret
and replaces the primary secret with an eight-byte GNU dummy. The public
portion of a version-4 secret packet is the prefix whose fingerprint is the
key's fingerprint. Everything after that prefix is the secret, and it is
discarded.
"""

import base64
import hashlib
import re

from .gpg import GpgError

_GNU_DUMMY = bytes.fromhex("ff006500474e5501")


def secret_subkey_armor(content: bytes | str, primary_fingerprint: str, sub_fingerprint: str) -> str:
    """Armored private key whose only secret is the selected subkey."""
    packets = _packets(_dearmor(content))
    if not packets or packets[0][0] not in (5, 6):
        raise GpgError("The key could not be exported.")
    primary_body = packets[0][1]
    public = _public_prefix(primary_body, primary_fingerprint)
    if public is None:
        raise GpgError("The key could not be exported.")
    secret_tail = primary_body[len(public):]
    preamble = [_packet(5, public + _GNU_DUMMY)]
    groups = []
    current = None
    for tag, _body, raw in packets[1:]:
        if tag in (7, 14):
            if current is not None:
                groups.append(current)
            current = [raw]
        elif current is not None:
            current.append(raw)
        else:
            preamble.append(raw)
    if current is not None:
        groups.append(current)
    kept = None
    for group in groups:
        tag, body, _raw = _one(group[0])
        if tag == 7 and _public_prefix(body, sub_fingerprint) is not None:
            kept = group
            break
    if kept is None:
        raise GpgError("The subkey could not be exported.")
    patched = b"".join(preamble + kept)
    if secret_tail != _GNU_DUMMY and secret_tail in patched:
        raise GpgError("The key could not be exported.")
    return _armor(patched)


def _public_prefix(body: bytes, fingerprint: str):
    want = fingerprint.strip().upper()
    if not re.fullmatch(r"[0-9A-F]{40}", want):
        return None
    for end in range(6, len(body) + 1):
        if _v4_fingerprint(body[:end]) == want:
            return body[:end]
    return None


def _v4_fingerprint(public_body: bytes) -> str:
    hashed = b"\x99" + len(public_body).to_bytes(2, "big") + public_body
    return hashlib.sha1(hashed).hexdigest().upper()


def _dearmor(content: bytes | str) -> bytes:
    if isinstance(content, str):
        content = content.encode("utf-8")
    if not content.lstrip().startswith(b"-----BEGIN"):
        return content
    lines = []
    inside = False
    for line in content.splitlines():
        if line.startswith(b"-----BEGIN"):
            inside = True
            continue
        if line.startswith(b"-----END"):
            break
        if inside and line and not line.startswith(b"="):
            lines.append(line.strip())
    try:
        return base64.b64decode(b"".join(lines), validate=True)
    except Exception as exc:
        raise GpgError("The key could not be exported.") from exc


def _packets(data: bytes):
    found = []
    index = 0
    while index < len(data):
        tag, body, raw, index = _read_packet(data, index)
        found.append((tag, body, raw))
    return found


def _one(raw: bytes):
    tag, body, packet, index = _read_packet(raw, 0)
    if index != len(raw):
        raise GpgError("The key could not be exported.")
    return tag, body, packet


def _read_packet(data: bytes, index: int):
    if index >= len(data):
        raise GpgError("The key could not be exported.")
    header = data[index]
    if header & 0x80 == 0:
        raise GpgError("The key could not be exported.")
    if header & 0x40:
        tag = header & 0x3F
        first = data[index + 1]
        if first < 192:
            length, size = first, 2
        elif first < 224:
            length = ((first - 192) << 8) + data[index + 2] + 192
            size = 3
        elif first == 255:
            length = int.from_bytes(data[index + 2:index + 6], "big")
            size = 6
        else:
            raise GpgError("The key could not be exported.")
    else:
        tag = (header >> 2) & 0x0F
        kind = header & 0x03
        if kind == 3:
            raise GpgError("The key could not be exported.")
        size = 1 + (1, 2, 4)[kind]
        length = int.from_bytes(data[index + 1:index + size], "big")
    end = index + size + length
    if end > len(data):
        raise GpgError("The key could not be exported.")
    return tag, data[index + size:end], data[index:end], end


def _packet(tag: int, body: bytes) -> bytes:
    if len(body) < 192:
        return bytes([0xC0 | tag, len(body)]) + body
    if len(body) < 8384:
        number = len(body) - 192
        return bytes([0xC0 | tag, (number >> 8) + 192, number & 0xFF]) + body
    return bytes([0xC0 | tag, 255]) + len(body).to_bytes(4, "big") + body


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _bit in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def _armor(data: bytes) -> str:
    text = base64.b64encode(data).decode("ascii")
    lines = [text[index:index + 64] for index in range(0, len(text), 64)]
    checksum = base64.b64encode(_crc24(data).to_bytes(3, "big")).decode("ascii")
    return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + "\n".join(lines) + "\n=" + checksum + "\n-----END PGP PRIVATE KEY BLOCK-----\n"

"""Deterministic primary keys from BIP-85.

RSA uses application 828365, path m/83696968h/828365h/{bits}h/{index}h.
BIP-85 turns that child key into 64 bytes, then BIP85-DRNG-SHAKE256 feeds
the prime search. The primality test uses fixed bases and does not read the
DRNG, so the same seed, bit length, and index always produce the same primes.

EdDSA uses application 828366, path m/83696968h/828366h/1h/256h/{index}h.
The same DRNG supplies the 32-byte Ed25519 seed. The OpenPGP packet is
version 4, algorithm 22, which GnuPG calls EdDSA. The self-signature is
Ed25519, which is deterministic, so no salt is drawn.

Name, email, key flags, and expiration are OpenPGP signatures over that
public key. They are not inputs to the DRNG. BIP-85 fixes the key creation
time at the Bitcoin genesis timestamp, because that time is part of the
fingerprint.
"""

import base64
import hashlib
from datetime import datetime, timezone

from embit.bip85 import derive_entropy

APPLICATION = 828365
EDDSA_APPLICATION = 828366
EDDSA_TYPE = 1
EDDSA_BITS = 256
# RFC 9580 Ed25519 OID 1.3.6.1.4.1.11591.15.1, with its one-byte length.
_ED25519_OID = bytes.fromhex("092b06010401da470f01")
ENTROPY_APPLICATION = 128169
ENTROPY_BYTES = 64
CREATION = 1231006505  # 2009-01-03 18:15:05 UTC
PUBLIC_EXPONENT = 65537
_TRIAL = []
_BASES = (2, 3, 5, 7, 11, 13, 23, 29)


def _trial_primes():
    if _TRIAL:
        return _TRIAL
    limit = 3000
    sieve = bytearray(b"\x01") * limit
    sieve[0:2] = b"\x00\x00"
    for i in range(2, int(limit**0.5) + 1):
        if sieve[i]:
            step = i
            start = i * i
            sieve[start::step] = b"\x00" * len(sieve[start::step])
    _TRIAL.extend(i for i in range(limit) if sieve[i])
    return _TRIAL


class ShakeReader:
    """BIP85-DRNG-SHAKE256. The seed is the 64-byte BIP-85 HMAC output."""

    def __init__(self, seed: bytes):
        if len(seed) != 64:
            raise ValueError("BIP-85 entropy must be 64 bytes.")
        self._shake = hashlib.shake_256(seed)
        self._pos = 0

    def read(self, count: int) -> bytes:
        end = self._pos + count
        data = self._shake.digest(end)
        chunk = data[self._pos:end]
        self._pos = end
        return chunk


def drng_bytes(entropy: bytes, count: int) -> bytes:
    return ShakeReader(entropy).read(count)


def raw_entropy(root, index: int) -> bytes:
    """64 bytes at m/83696968h/128169h/64h/{index}h.

    BIP-85 application 128169 is raw entropy. The HMAC-SHA512 output is 64
    bytes, which is the maximum this application allows, so nothing is cut.
    """
    if index < 0 or index >= 0x80000000:
        raise ValueError("The index is too large.")
    return derive_entropy(root, ENTROPY_APPLICATION, [ENTROPY_BYTES, index])


def entropy_path(index: int) -> str:
    return f"m/83696968h/{ENTROPY_APPLICATION}h/{ENTROPY_BYTES}h/{index}h"


def entropy_for(root, bits: int, index: int) -> bytes:
    if bits not in (3072, 4096) and bits < 512:
        raise ValueError("The RSA key length is not supported.")
    if index < 0 or index >= 0x80000000:
        raise ValueError("The index is too large.")
    return derive_entropy(root, APPLICATION, [bits, index])


def _is_prime(number: int) -> bool:
    if number < 2:
        return False
    for prime in _trial_primes():
        if number == prime:
            return True
        if number % prime == 0:
            return False
    witness = number - 1
    shift = 0
    while witness % 2 == 0:
        witness //= 2
        shift += 1
    for base in _BASES:
        value = pow(base, witness, number)
        if value == 1 or value == number - 1:
            continue
        for _ in range(shift - 1):
            value = pow(value, 2, number)
            if value == number - 1:
                break
        else:
            return False
    return True


def prime(reader: ShakeReader, bits: int) -> int:
    """One DRNG read, then odd candidates until the fixed Miller-Rabin test passes."""
    width = (bits + 7) // 8
    while True:
        number = int.from_bytes(reader.read(width), "big")
        number &= (1 << bits) - 1
        number |= 1 << (bits - 1)
        number |= 1
        while number.bit_length() == bits:
            if _is_prime(number):
                return number
            number += 2


class RSAKey:
    def __init__(self, n, e, d, p, q, u):
        self.n, self.e, self.d, self.p, self.q, self.u = n, e, d, p, q, u


def generate_rsa(reader: ShakeReader, bits: int) -> RSAKey:
    if bits < 512 or bits % 2:
        raise ValueError("The RSA key length is not supported.")
    half = bits // 2
    while True:
        first = prime(reader, half)
        second = prime(reader, half)
        if first == second:
            continue
        if (first * second).bit_length() != bits:
            continue
        phi = (first - 1) * (second - 1)
        try:
            pow(PUBLIC_EXPONENT, -1, phi)
        except ValueError:
            continue
        break
    p, q = (first, second) if first > second else (second, first)
    phi = (p - 1) * (q - 1)
    d = pow(PUBLIC_EXPONENT, -1, phi)
    u = pow(p, -1, q)
    return RSAKey(p * q, PUBLIC_EXPONENT, d, p, q, u)


def derive_rsa(root, bits: int, index: int) -> RSAKey:
    return generate_rsa(ShakeReader(entropy_for(root, bits, index)), bits)


def creation_text() -> str:
    stamp = datetime.fromtimestamp(CREATION, timezone.utc)
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _mpi(number: int) -> bytes:
    length = max(1, (number.bit_length() + 7) // 8)
    return number.bit_length().to_bytes(2, "big") + number.to_bytes(length, "big")


def _packet(tag: int, body: bytes) -> bytes:
    size = len(body)
    if size < 192:
        length = bytes([size])
    elif size < 8384:
        adjusted = size - 192
        length = bytes([(adjusted >> 8) + 192, adjusted & 0xFF])
    else:
        length = b"\xff" + size.to_bytes(4, "big")
    return bytes([0xC0 | tag]) + length + body


def _subpacket(kind: int, data: bytes) -> bytes:
    body = bytes([kind]) + data
    if len(body) >= 192:
        raise ValueError("This signature field is too long.")
    return bytes([len(body)]) + body


def identity(name: str, email: str) -> bytes:
    name = " ".join(name.split())
    email = email.strip()
    if not name or any(char in name for char in "<>"):
        raise ValueError("Enter a name.")
    if not email:
        return name.encode()
    if email.count("@") != 1 or any(char.isspace() for char in email):
        raise ValueError("Enter an email address.")
    local, domain = email.split("@")
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("Enter an email address.")
    return f"{name} <{email}>".encode()


def expiration_seconds(expires_on):
    if expires_on is None:
        return None
    year, month, day = expires_on
    stamp = int(datetime(year, month, day, tzinfo=timezone.utc).timestamp())
    delta = stamp - CREATION
    if delta <= 0:
        raise ValueError("The expiration is before this key was created.")
    if delta > 0xFFFFFFFF:
        raise ValueError("That expiration is too far ahead.")
    return delta


def _pkcs1_sha256(key: RSAKey, message: bytes) -> int:
    digest = hashlib.sha256(message).digest()
    prefix = bytes.fromhex("3031300d060960864801650304020105000420")
    encoded = prefix + digest
    width = (key.n.bit_length() + 7) // 8
    padding = b"\xff" * (width - len(encoded) - 3)
    block = b"\x00\x01" + padding + b"\x00" + encoded
    return pow(int.from_bytes(block, "big"), key.d, key.n)


def secret_packets(key: RSAKey, name: str, email: str, *, signing: bool, expires_on=None) -> bytes:
    """OpenPGP secret key, user id, and one self-signature. No subkeys."""
    public = bytes([4]) + CREATION.to_bytes(4, "big") + bytes([1]) + _mpi(key.n) + _mpi(key.e)
    fingerprint = hashlib.sha1(b"\x99" + len(public).to_bytes(2, "big") + public).digest()
    uid = identity(name, email)
    flags = b"\x03" if signing else b"\x01"
    hashed = b"".join([
        _subpacket(2, CREATION.to_bytes(4, "big")),
        _subpacket(27, flags),
        _subpacket(11, bytes([9, 8, 7])),
        _subpacket(21, bytes([10, 9, 8])),
        _subpacket(22, bytes([2, 1, 0])),
        _subpacket(30, b"\x01"),
        _subpacket(33, b"\x04" + fingerprint),
    ])
    seconds = expiration_seconds(expires_on)
    if seconds is not None:
        hashed += _subpacket(9, seconds.to_bytes(4, "big"))
    unhashed = _subpacket(16, fingerprint[-8:])
    prefix = bytes([4, 0x13, 1, 8]) + len(hashed).to_bytes(2, "big") + hashed
    signed = (
        b"\x99" + len(public).to_bytes(2, "big") + public
        + b"\xb4" + len(uid).to_bytes(4, "big") + uid
        + prefix
        + b"\x04\xff" + len(prefix).to_bytes(4, "big")
    )
    digest = hashlib.sha256(signed).digest()
    signature = _mpi(_pkcs1_sha256(key, signed))
    sig_body = prefix + len(unhashed).to_bytes(2, "big") + unhashed + digest[:2] + signature
    secret_mpis = _mpi(key.d) + _mpi(key.p) + _mpi(key.q) + _mpi(key.u)
    checksum = sum(secret_mpis) & 0xFFFF
    secret = public + bytes([0]) + secret_mpis + checksum.to_bytes(2, "big")
    return _packet(5, secret) + _packet(13, uid) + _packet(2, sig_body)


def armor(packets: bytes) -> str:
    text = base64.b64encode(packets).decode()
    lines = [text[i:i + 64] for i in range(0, len(text), 64)]
    checksum = base64.b64encode(_crc24(packets).to_bytes(3, "big")).decode("ascii")
    return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n" + "\n".join(lines) + "\n=" + checksum + "\n-----END PGP PRIVATE KEY BLOCK-----\n"


def _crc24(data: bytes) -> int:
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _bit in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def secret_armor(root, bits: int, index: int, name: str, email: str, *, signing: bool, expires_on=None) -> str:
    if bits not in (3072, 4096):
        raise ValueError("Choose 3072 or 4096 bits.")
    key = derive_rsa(root, bits, index)
    return armor(secret_packets(key, name, email, signing=signing, expires_on=expires_on))


def path_text(bits: int, index: int) -> str:
    return f"m/83696968h/{APPLICATION}h/{bits}h/{index}h"


def eddsa_path(index: int) -> str:
    """Version-4 EdDSA primary key: application 828366, key type 1, 256 bits."""
    return f"m/83696968h/{EDDSA_APPLICATION}h/{EDDSA_TYPE}h/{EDDSA_BITS}h/{index}h"


_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, -1, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _edwards_add(p, q):
    x1, y1 = p
    x2, y2 = q
    prod = _D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + prod, -1, _P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - prod, -1, _P)
    return x3 % _P, y3 % _P


def _scalarmult(point, scalar: int):
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _edwards_add(result, addend)
        addend = _edwards_add(addend, addend)
        scalar >>= 1
    return result


def _base_point():
    y = 4 * pow(5, -1, _P) % _P
    xx = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = x * _I % _P
    if x & 1:
        x = _P - x
    return x % _P, y


_B = _base_point()


def _clamp(seed_hash: bytes) -> int:
    scalar = int.from_bytes(seed_hash[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar


def _encode_point(point) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_public(seed: bytes) -> bytes:
    """32-byte RFC 8032 public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("The EdDSA seed must be 32 bytes.")
    scalar = _clamp(hashlib.sha512(seed).digest())
    return _encode_point(_scalarmult(_B, scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """64-byte RFC 8032 signature. The nonce comes from the seed, not the OS."""
    if len(seed) != 32:
        raise ValueError("The EdDSA seed must be 32 bytes.")
    digest = hashlib.sha512(seed).digest()
    scalar = _clamp(digest)
    public = _encode_point(_scalarmult(_B, scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % _L
    commitment = _encode_point(_scalarmult(_B, nonce))
    challenge = int.from_bytes(hashlib.sha512(commitment + public + message).digest(), "little") % _L
    response = (nonce + challenge * scalar) % _L
    return commitment + response.to_bytes(32, "little")


def eddsa_entropy(root, index: int) -> bytes:
    if index < 0 or index >= 0x80000000:
        raise ValueError("The index is too large.")
    return derive_entropy(root, EDDSA_APPLICATION, [EDDSA_TYPE, EDDSA_BITS, index])


def eddsa_seed(root, index: int) -> bytes:
    """First 32 bytes of the DRNG. The derivation does not clamp this seed."""
    return ShakeReader(eddsa_entropy(root, index)).read(32)


def eddsa_packets(seed: bytes, name: str, email: str, *, signing: bool, expires_on=None) -> bytes:
    """Version-4 EdDSA secret key, user id, and one self-signature. No subkeys."""
    point = ed25519_public(seed)
    public = bytes([4]) + CREATION.to_bytes(4, "big") + bytes([22]) + _ED25519_OID + _mpi(int.from_bytes(b"\x40" + point, "big"))
    fingerprint = hashlib.sha1(b"\x99" + len(public).to_bytes(2, "big") + public).digest()
    uid = identity(name, email)
    flags = b"\x03" if signing else b"\x01"
    hashed = b"".join([
        _subpacket(2, CREATION.to_bytes(4, "big")),
        _subpacket(27, flags),
        _subpacket(11, bytes([9, 8, 7])),
        _subpacket(21, bytes([10, 9, 8])),
        _subpacket(22, bytes([2, 1, 0])),
        _subpacket(30, b"\x01"),
        _subpacket(33, b"\x04" + fingerprint),
    ])
    seconds = expiration_seconds(expires_on)
    if seconds is not None:
        hashed += _subpacket(9, seconds.to_bytes(4, "big"))
    unhashed = _subpacket(16, fingerprint[-8:])
    prefix = bytes([4, 0x13, 22, 10]) + len(hashed).to_bytes(2, "big") + hashed
    signed = (
        b"\x99" + len(public).to_bytes(2, "big") + public
        + b"\xb4" + len(uid).to_bytes(4, "big") + uid
        + prefix
        + b"\x04\xff" + len(prefix).to_bytes(4, "big")
    )
    digest = hashlib.sha512(signed).digest()
    # GnuPG checks this as PureEdDSA over the SHA-512 digest. The two
    # signature values are the RFC 8032 halves, stored as unsigned integers.
    native = ed25519_sign(seed, digest)
    signature = _mpi(int.from_bytes(native[:32], "big")) + _mpi(int.from_bytes(native[32:], "big"))
    sig_body = prefix + len(unhashed).to_bytes(2, "big") + unhashed + digest[:2] + signature
    secret_mpi = _mpi(int.from_bytes(seed, "big"))
    checksum = sum(secret_mpi) & 0xFFFF
    secret = public + bytes([0]) + secret_mpi + checksum.to_bytes(2, "big")
    return _packet(5, secret) + _packet(13, uid) + _packet(2, sig_body)


def eddsa_armor(root, index: int, name: str, email: str, *, signing: bool, expires_on=None) -> str:
    return armor(eddsa_packets(eddsa_seed(root, index), name, email, signing=signing, expires_on=expires_on))

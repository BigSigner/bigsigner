"""Fountain-code decoder for a multipart Uniform Resource.

Fragment choice matches Blockchain Commons URKit. The xoshiro256** generator
it uses is public domain.
"""

import hashlib
import zlib

from .ur import cbor_decode

_MASK = (1 << 64) - 1
_MAX_PARTS = 1296
_MAX_MESSAGE = 2_000_000


class FountainError(ValueError):
    pass


class FountainDecoder:
    def __init__(self):
        self.expected = 0
        self.codes = 0
        self.message = None
        self._checksum = 0
        self._message_len = 0
        self._fragment_len = 0
        self._seen = set()
        self._simples = {}
        self._mixed = {}
        self._queue = []

    def receive(self, seq_num: int, seq_len: int, message_len: int, checksum: int, data: bytes) -> bool:
        """Accept one fountain part. Return False when it belongs to another message."""
        if self.message is not None:
            return False
        if seq_len < 1 or seq_len > _MAX_PARTS or message_len < 1 or message_len > _MAX_MESSAGE:
            raise FountainError("This UR sequence is too large.")
        if not data or message_len > seq_len * len(data):
            return False
        if self.expected == 0:
            self.expected = seq_len
            self._message_len = message_len
            self._checksum = checksum
            self._fragment_len = len(data)
        elif (
            self.expected != seq_len
            or self._message_len != message_len
            or self._checksum != checksum
            or self._fragment_len != len(data)
        ):
            return False
        if seq_num in self._seen:
            return True
        self._seen.add(seq_num)
        self.codes = len(self._seen)
        indexes = tuple(choose_fragments(seq_num, seq_len, checksum))
        self._queue.append((indexes, data))
        while self.message is None and self._queue:
            self._drain()
        return True

    def _drain(self):
        indexes, data = self._queue.pop(0)
        if len(indexes) == 1:
            self._simple(indexes, data)
        else:
            self._mixed_part(indexes, data)

    def _simple(self, indexes, data):
        index = indexes[0]
        if index in self._simples:
            return
        self._simples[index] = data
        if set(self._simples) == set(range(self.expected)):
            pieces = [self._simples[number] for number in range(self.expected)]
            message = b"".join(pieces)[: self._message_len]
            if (zlib.crc32(message) & 0xFFFFFFFF) != (self._checksum & 0xFFFFFFFF):
                raise FountainError("This UR sequence could not be read.")
            self.message = message
            return
        self._reduce_mixed(indexes, data)

    def _mixed_part(self, indexes, data):
        for other_indexes, other_data in list(self._simples.items()):
            indexes, data = _reduce(indexes, data, (other_indexes,), other_data)
        for other_indexes, other_data in list(self._mixed.items()):
            indexes, data = _reduce(indexes, data, other_indexes, other_data)
        if not indexes:
            return
        if len(indexes) == 1:
            self._queue.append((indexes, data))
            return
        self._reduce_mixed(indexes, data)
        self._mixed[indexes] = data

    def _reduce_mixed(self, indexes, data):
        reduced = {}
        for other_indexes, other_data in self._mixed.items():
            new_indexes, new_data = _reduce(other_indexes, other_data, indexes, data)
            if len(new_indexes) == 1:
                self._queue.append((new_indexes, new_data))
            elif new_indexes:
                reduced[new_indexes] = new_data
        self._mixed = reduced


def part_from_cbor(data: bytes) -> tuple[int, int, int, int, bytes]:
    item = cbor_decode(data)
    if not isinstance(item, list) or len(item) != 5 or not isinstance(item[4], (bytes, bytearray)):
        raise FountainError("This UR part could not be read.")
    seq_num, seq_len, message_len, checksum = item[:4]
    if not all(isinstance(value, int) and value >= 0 for value in item[:4]):
        raise FountainError("This UR part could not be read.")
    if seq_num < 1:
        raise FountainError("This UR part could not be read.")
    return seq_num, seq_len, message_len, checksum, bytes(item[4])


def choose_fragments(seq_num: int, seq_len: int, checksum: int) -> list[int]:
    if seq_num <= seq_len:
        return [seq_num - 1]
    seed = (seq_num & 0xFFFFFFFF).to_bytes(4, "big") + (checksum & 0xFFFFFFFF).to_bytes(4, "big")
    rng = _Xoshiro(seed)
    degree = _Alias([1 / i for i in range(1, seq_len + 1)]).next(rng) + 1
    remaining = list(range(seq_len))
    shuffled = []
    while remaining:
        shuffled.append(remaining.pop(int(rng.next_double() * len(remaining))))
    return shuffled[:degree]


def _reduce(indexes, data, other_indexes, other_data):
    if set(other_indexes) <= set(indexes):
        gone = set(other_indexes)
        return tuple(index for index in indexes if index not in gone), _xor(data, other_data)
    return indexes, data


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _rotl(value: int, shift: int) -> int:
    value &= _MASK
    return ((value << shift) | (value >> (64 - shift))) & _MASK


class _Xoshiro:
    """xoshiro256**. Seeded from the SHA-256 of the eight seed bytes, as URKit does."""

    def __init__(self, seed: bytes):
        digest = hashlib.sha256(seed).digest()
        self.s = [int.from_bytes(digest[i : i + 8], "big") for i in range(0, 32, 8)]

    def next_long(self) -> int:
        s0, s1, s2, s3 = self.s
        result = _rotl((s1 * 5) & _MASK, 7)
        result = (result * 9) & _MASK
        t = (s1 << 17) & _MASK
        s2 = (s2 ^ s0) & _MASK
        s3 = (s3 ^ s1) & _MASK
        s1 = (s1 ^ s2) & _MASK
        s0 = (s0 ^ s3) & _MASK
        s2 = (s2 ^ t) & _MASK
        s3 = _rotl(s3, 45)
        self.s = [s0, s1, s2, s3]
        return result

    def next_double(self) -> float:
        return (self.next_long() >> 11) * (2**-53)


class _Alias:
    def __init__(self, probabilities):
        count = len(probabilities)
        total = sum(probabilities)
        scaled = [prob * count / total for prob in probabilities]
        small = []
        large = []
        for index in range(count - 1, -1, -1):
            (small if scaled[index] < 1 else large).append(index)
        self.probs = [0.0] * count
        self.aliases = [0] * count
        while small and large:
            low = small.pop()
            high = large.pop()
            self.probs[low] = scaled[low]
            self.aliases[low] = high
            scaled[high] = scaled[high] + scaled[low] - 1
            (small if scaled[high] < 1 else large).append(high)
        while large:
            self.probs[large.pop()] = 1
        while small:
            self.probs[small.pop()] = 1

    def next(self, rng: _Xoshiro) -> int:
        r1 = rng.next_double()
        r2 = rng.next_double()
        index = int(len(self.probs) * r1)
        return index if r2 < self.probs[index] else self.aliases[index]

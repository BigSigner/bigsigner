"""SeedSigner standard and compact SeedQR payloads."""

from embit import bip39


def standard_digits(mnemonic: str) -> str:
    words = mnemonic.split()
    indexes = [f"{bip39.WORDLIST.index(word):04d}" for word in words]
    return "".join(indexes)


def mnemonic_from_standard(digits: str) -> str:
    if len(digits) not in (48, 72, 96) or not digits.isdigit():
        raise ValueError("A standard SeedQR is 12, 18, or 24 word indexes.")
    words = [bip39.WORDLIST[int(digits[i : i + 4])] for i in range(0, len(digits), 4)]
    mnemonic = " ".join(words)
    bip39.mnemonic_to_bytes(mnemonic)
    return mnemonic


def compact_bytes(mnemonic: str) -> bytes:
    return bip39.mnemonic_to_bytes(mnemonic)


def mnemonic_from_compact(raw: bytes) -> str:
    if len(raw) not in (16, 24, 32):
        raise ValueError("A compact SeedQR must be 16, 24, or 32 bytes.")
    return bip39.mnemonic_from_bytes(raw)

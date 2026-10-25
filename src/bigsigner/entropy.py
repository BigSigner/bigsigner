"""SeedSigner dice, coin, and camera entropy. The same dice string matches SeedSigner."""

import hashlib

from embit import bip39

DICE_12 = 50
DICE_24 = 99
COINS_12 = 128
COINS_24 = 256


def mnemonic_from_dice(rolls: str) -> str:
    if len(rolls) not in (DICE_12, DICE_24) or any(roll not in "123456" for roll in rolls):
        raise ValueError("Enter 50 dice rolls for 12 words, or 99 rolls for 24 words.")
    return _from_ascii(rolls, sixteen=len(rolls) == DICE_12)


def mnemonic_from_coins(flips: str) -> str:
    if len(flips) not in (COINS_12, COINS_24) or any(flip not in "01" for flip in flips):
        raise ValueError("Enter 128 coin flips for 12 words, or 256 flips for 24 words.")
    return _from_ascii(flips, sixteen=len(flips) == COINS_12)


def mnemonic_from_camera(
    frames: list[bytes], final: bytes, serial: bytes, timestamp: str, words: int = 24
) -> str:
    """Match SeedSigner's chain. The same picture on two devices does not repeat.

    A 12-word seed keeps the first 16 bytes of the final hash, as the dice path does.
    """
    if words not in (12, 24):
        raise ValueError("Camera entropy can make a 12-word or 24-word seed.")
    digest = hashlib.sha256(serial).digest()
    digest = hashlib.sha256(digest + timestamp.encode("utf-8")).digest()
    for frame in frames:
        digest = hashlib.sha256(digest + frame).digest()
    digest = hashlib.sha256(digest + final).digest()
    if words == 12:
        digest = digest[:16]
    return bip39.mnemonic_from_bytes(digest)


def _from_ascii(text: str, sixteen: bool) -> str:
    digest = hashlib.sha256(text.encode()).digest()
    if sixteen:
        digest = digest[:16]
    return bip39.mnemonic_from_bytes(digest)

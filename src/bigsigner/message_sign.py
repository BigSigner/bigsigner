"""BIP-137 message signing for a Native-Segwit singlesig address.

The request line is the one Sparrow and Specter put in a QR code:
``signmessage m/84h/0h/0h/0/0 ascii:hello``. The signature is the 65-byte
recoverable ECDSA signature, base64-encoded, with the P2WPKH header byte.
"""

import base64
import hashlib
import re

from embit.misc import secp256k1

from .paths import HARDENED, PathError, coin_type, format_path, parse_path
from .scan import classify_content, wrong_type_message
from .session import SessionError, _seed_root

NOT_ASCII = "This message must be in ASCII format."
ADDRESS_MESSAGE_COMMAND = (
    "This is a sign-message command. Load it from the Sign Message button on the wallet screen."
)
BAD_COMMAND = "This message signing command is not valid."
BAD_PATH = "This derivation path is not valid."
BAD_PURPOSE = "This derivation path is not a Native-Segwit path."
BAD_NETWORK = "This derivation path is for a different network."
BAD_ADDRESS = "This derivation path does not name a receive or change address."
SIGN_FAILED = "The signature could not be created."
MESSAGE_MAX_BYTES = 1024
TOO_LONG = "The message cannot be longer than 1024 bytes."

# P2WPKH uses header 39 plus the recovery id. BIP-137.
_P2WPKH_HEADER = 39
_CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_CURVE_HALF = _CURVE_ORDER // 2
_COMMAND = re.compile(r"\Asignmessage (\S+) ascii:(.*)\Z", re.DOTALL)
_MAX_TEXT = 100_000


def message_lines(text: str, columns: int) -> list[tuple[int, str]]:
    """Break on newlines, then before the character that would pass `columns`.

    Each item is the index of that line in `text` and the characters on it.
    A trailing newline keeps an empty line after it. Spaces are ordinary characters.
    """
    if columns < 1:
        columns = 1
    if text == "":
        return [(0, "")]
    lines = []
    index = 0
    length = len(text)
    while index < length:
        newline = text.find("\n", index)
        end = length if newline < 0 else newline
        paragraph = text[index:end]
        if paragraph == "":
            lines.append((index, ""))
        else:
            offset = 0
            while offset < len(paragraph):
                lines.append((index + offset, paragraph[offset : offset + columns]))
                offset += columns
        if newline < 0:
            break
        index = newline + 1
        if index == length:
            lines.append((index, ""))
            break
    return lines or [(0, "")]


def message_ending(text: str) -> str | None:
    """``newline`` or ``space`` when the message ends with one of those."""
    if not text:
        return None
    if text[-1] in "\n\r":
        return "newline"
    if text[-1] == " ":
        return "space"
    return None


def starts_with_signmessage_command(text: str) -> bool:
    """True when spaces and newlines at the start leave a ``signmessage `` command."""
    return isinstance(text, str) and text.lstrip(" \n\r").startswith("signmessage ")


def address_message_text(text: str) -> str:
    """The message to sign with the address already on screen.

    Leading spaces and newlines are ignored only when checking for a
    ``signmessage `` command. That command belongs on the wallet screen.
    """
    if not isinstance(text, str) or len(text) > _MAX_TEXT:
        raise SessionError("That message could not be read.")
    if not text.isascii():
        raise SessionError(NOT_ASCII)
    if starts_with_signmessage_command(text):
        raise SessionError(ADDRESS_MESSAGE_COMMAND)
    if len(text.encode("utf-8")) > MESSAGE_MAX_BYTES:
        raise SessionError(TOO_LONG)
    return text


def read_sign_command(text: str, source: str, network: str) -> str:
    """The raw command, or the same refusal used for an unexpected QR or file."""
    if not isinstance(text, str) or len(text) > _MAX_TEXT:
        raise SessionError(f"That {source} could not be read.")
    if text.startswith("signmessage "):
        if not text.isascii():
            raise SessionError(NOT_ASCII)
        return text
    if not text.strip():
        raise SessionError(f"That {source} is empty.")
    parsed = classify_content(text, network)
    raise SessionError(wrong_type_message(parsed.kind, "message", source, network))


def parse_sign_command(text: str) -> tuple[str, str]:
    """The derivation path token and the message after ``ascii:``."""
    match = _COMMAND.match(text)
    if match is None:
        raise SessionError(BAD_COMMAND)
    message = match.group(2)
    if len(message.encode("utf-8")) > MESSAGE_MAX_BYTES:
        raise SessionError(TOO_LONG)
    return match.group(1), message


def native_sign_path(path_text: str, network: str, account: int) -> tuple[int, int, list[int]]:
    """Receive or change branch, address index, and the five derivation steps.

    The path must be ``m/84h/<coin>h/<account>h/<0 or 1>/<index>`` for this
    network and the wallet's selected account. ``h``, ``'``, and ``H`` are
    the same hardened mark.
    """
    if not path_text.startswith("m/"):
        raise SessionError(BAD_PATH)
    try:
        steps = parse_path(path_text)
    except PathError as exc:
        raise SessionError(BAD_PATH) from exc
    purpose = 84 | HARDENED
    coin = coin_type(network) | HARDENED
    if not steps or steps[0] != purpose:
        raise SessionError(BAD_PURPOSE)
    if len(steps) < 2 or steps[1] != coin:
        raise SessionError(BAD_NETWORK)
    if len(steps) < 3 or not (steps[2] & HARDENED) or steps[2] != (account | HARDENED):
        if len(steps) >= 3 and steps[2] & HARDENED:
            found = steps[2] & ~HARDENED
            raise SessionError(
                f"This command is for account index {found}, "
                f"but the account index you selected is {account}."
            )
        raise SessionError("This derivation path does not include an account index.")
    branch_ok = len(steps) == 5 and not (steps[3] & HARDENED) and steps[3] in (0, 1)
    index_ok = branch_ok and not (steps[4] & HARDENED)
    if not index_ok:
        raise SessionError(BAD_ADDRESS)
    return steps[3], steps[4], steps


def signing_secret(seed_key, steps: list[int]) -> bytes:
    """The private key at this full path, from the loaded seed."""
    if seed_key is None or not seed_key.has_seed:
        raise SessionError("This seed is no longer loaded.")
    return _seed_root(seed_key).derive(format_path(list(steps))).secret


def bip137_signature(secret: bytes, message: str) -> str:
    """Base64 BIP-137 signature for a native-segwit address."""
    if not message.isascii():
        raise SessionError(NOT_ASCII)
    raw = message.encode("ascii")
    if len(raw) > MESSAGE_MAX_BYTES:
        raise SessionError(TOO_LONG)
    payload = b"\x18Bitcoin Signed Message:\n" + _compact_size(len(raw)) + raw
    digest = hashlib.sha256(hashlib.sha256(payload).digest()).digest()
    recoverable = secp256k1.ecdsa_sign_recoverable(digest, secret)
    compact, _recid = secp256k1.ecdsa_recoverable_signature_serialize_compact(recoverable)
    value_r = int.from_bytes(compact[:32], "big")
    value_s = int.from_bytes(compact[32:], "big")
    if value_s > _CURVE_HALF:
        value_s = _CURVE_ORDER - value_s
    compact = value_r.to_bytes(32, "big") + value_s.to_bytes(32, "big")
    internal = secp256k1.ecdsa_signature_parse_compact(compact)
    public = secp256k1.ec_pubkey_create(secret)
    recid = None
    for index in range(4):
        try:
            found = secp256k1.ecdsa_recover(internal + bytes([index]), digest)
        except (ValueError, OSError, OverflowError):
            continue
        if found == public:
            recid = index
            break
    if recid is None:
        raise SessionError(SIGN_FAILED)
    return base64.b64encode(bytes([_P2WPKH_HEADER + recid]) + compact).decode("ascii")


def _compact_size(length: int) -> bytes:
    if length < 0xFD:
        return bytes([length])
    if length <= 0xFFFF:
        return b"\xfd" + length.to_bytes(2, "little")
    if length <= 0xFFFFFFFF:
        return b"\xfe" + length.to_bytes(4, "little")
    return b"\xff" + length.to_bytes(8, "little")

"""Wallet files that wrap one output descriptor.

embit reads a single descriptor string. It does not detect a Specter Desktop
JSON export, a Specter DIY addwallet command, a Coldcard multisig setup file,
or a Bitcoin Core descriptor file. BlueWallet and Keystone use that same setup
file. Those are unwrapped here. The descriptor inside is what the rest of the
app parses.
"""

import json
import re

from .parse import ParseError, split_checksum

_POLICY = re.compile(r"([0-9]+)\s+of\s+([0-9]+)\Z", re.IGNORECASE)
_SETUP_LABELS = frozenset({"policy", "format", "derivation", "# derivation"})

_SPECTER_KEYS = frozenset({"label", "blockheight", "descriptor"})


def descriptor_from_specter_desktop(text: str) -> str | None:
    """The descriptor string from a Specter Desktop wallet export, or None.

    The export is a JSON object whose keys are exactly ``label``,
    ``blockheight``, and ``descriptor``. ``descriptor`` has to be a string.
    Sparrow writes this file from its Specter Desktop exporter.
    """
    raw = _text(text)
    if not raw.startswith("{"):
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or set(value) != _SPECTER_KEYS:
        return None
    descriptor = value["descriptor"]
    if not isinstance(descriptor, str):
        return None
    return descriptor.strip()


def descriptor_from_specter_diy(text: str) -> str | None:
    """The descriptor from a Specter DIY ``addwallet`` command, or None.

    The command is ``addwallet``, a space, a wallet name, ``&``, and the
    descriptor. The name is ignored. The descriptor is the text after the
    last ``&``, so the name may contain ``&``. A checksum may be absent.
    """
    raw = _text(text)
    if len(raw) <= len("addwallet") or not raw.startswith("addwallet") or not raw[len("addwallet")].isspace():
        return None
    rest = raw[len("addwallet") :].lstrip()
    if "&" not in rest:
        return None
    descriptor = rest.rsplit("&", 1)[1].strip()
    if not descriptor:
        return None
    return descriptor


def descriptor_from_multisig_setup(text: str) -> str | None:
    """The descriptor from a Coldcard, BlueWallet, or Keystone multisig file.

    Sparrow's ``ColdcardMultisig.importWallet`` reads this text, and the
    BlueWallet and Keystone importers call that method. This format is
    multisig only. A line that begins with ``#`` is a comment, except the
    legacy ``# derivation`` label. ``Name`` is ignored. ``Policy`` is ``M of
    N``. ``Format`` must be ``P2WSH``. ``Derivation`` starts with ``m/`` and
    may use ``'`` or ``h``. It applies to each fingerprint line that follows,
    and a later derivation replaces it. The fingerprint is eight hex
    characters and the value is that key's extended public key.
    """
    lines = _setup_lines(text)
    if lines is None:
        return None
    threshold = 0
    cosigners = 0
    policy_found = False
    format_found = False
    derivation = None
    keys = []
    for key, value in lines:
        if key == "name":
            continue
        if key == "policy":
            match = _POLICY.match(value)
            if policy_found or match is None:
                raise ParseError("This multisig file's policy could not be read.")
            policy_found = True
            threshold = int(match.group(1))
            cosigners = int(match.group(2))
            continue
        if key in ("derivation", "# derivation"):
            if not value:
                raise ParseError("This multisig file's derivation is empty.")
            if not value.lower().startswith("m/"):
                raise ParseError("This multisig file's derivation must start with m/.")
            derivation = value[2:]
            continue
        if key == "format":
            if format_found:
                raise ParseError("This multisig file specifies more than one script format.")
            format_found = True
            if value.upper() != "P2WSH":
                raise ParseError("This multisig file does not use P2WSH.")
            continue
        if len(key) == 8 and all(character in "0123456789abcdef" for character in key):
            if derivation is None:
                raise ParseError("This multisig file has a key before its derivation.")
            if not value or any(character not in _BASE58 for character in value):
                raise ParseError("This multisig file has a key that could not be read.")
            keys.append(f"[{key}/{derivation}]{value}/<0;1>/*")
    if not format_found:
        raise ParseError("This multisig file does not use P2WSH.")
    if not policy_found or threshold == 0:
        raise ParseError("This multisig file does not specify a policy.")
    if cosigners != len(keys):
        noun = "key" if len(keys) == 1 else "keys"
        raise ParseError(
            f"This multisig file specifies a policy of {threshold} of {cosigners}, but contains {len(keys)} {noun}."
        )
    return f"wsh(sortedmulti({threshold},{','.join(keys)}))"


def descriptor_from_bitcoin_core(text: str) -> str | None:
    """The combined descriptor from a Bitcoin Core descriptor file, or None.

    Blank lines and lines that start with ``#`` are ignored. The first
    remaining line is the descriptor that contains ``<0;1>``. Each later line
    is that same descriptor with every ``<0;1>`` written as ``0`` or as ``1``.
    Each line keeps its own checksum, because that text is different.
    """
    lines = _content_lines(text)
    if len(lines) < 2:
        return None
    first = _body(lines[0])
    if "<0;1>" not in first:
        return None
    allowed = {first.replace("<0;1>", "0"), first.replace("<0;1>", "1")}
    if any(_body(line) not in allowed for line in lines[1:]):
        return None
    for line in lines:
        split_checksum(line)
    return lines[0]


_BASE58 = frozenset("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")


def _setup_lines(text: str) -> list[tuple[str, str]] | None:
    """Field lines from a multisig setup file, or None when it is another format."""
    raw_lines = str(text).lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    records = []
    recognized = False
    dirty = False
    for raw in raw_lines:
        if any((ord(character) < 0x20 and character != "\t") or ord(character) == 0x7F for character in raw):
            dirty = True
        line = raw.strip()
        separator = line.find(":")
        if not line or separator < 0:
            continue
        key = line[:separator].strip().lower()
        value = line[separator + 1 :].strip()
        if key in _SETUP_LABELS:
            recognized = True
        records.append((key, value))
    if not recognized:
        return None
    if dirty:
        raise ParseError("This multisig file contains unexpected control characters.")
    return records


def _text(text: str) -> str:
    return str(text).lstrip("\ufeff").strip()


def _content_lines(text: str) -> list[str]:
    lines = []
    for raw in _text(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _body(line: str) -> str:
    return line.split("#", 1)[0]

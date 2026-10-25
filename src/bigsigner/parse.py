"""Parse the key expressions and descriptors this version accepts."""

import re
import unicodedata

from embit.bip32 import HDKey
from embit.descriptor.checksum import checksum

from .paths import (
    MULTISIG_NATIVE,
    SINGLESIG_NATIVE,
    SINGLESIG_TAPROOT,
    PathError,
    classify_path,
    format_path,
    parse_path,
)
from .slip132 import Slip132Error, accept_for_role, label_of


class ParseError(ValueError):
    pass


class ParsedKey:
    def __init__(self, fingerprint, path, xpub, account, role, branch_note):
        self.fingerprint = fingerprint
        self.path = tuple(path)
        self.xpub = xpub
        self.account = account
        self.role = role
        self.branch_note = branch_note

    @property
    def canonical(self):
        return self.xpub.to_string()


class ParsedWallet:
    def __init__(self, role, threshold, keys, warnings):
        self.role = role
        self.threshold = threshold
        self.keys = keys
        self.warnings = warnings

    @property
    def multisig(self):
        return self.role == MULTISIG_NATIVE


def split_checksum(text: str) -> tuple[str, str | None]:
    if text.count("#") > 1:
        raise ParseError("The descriptor has more than one checksum.")
    if "#" not in text:
        return text, None
    body, digest = text.split("#", 1)
    digest = digest.strip()
    if not re.fullmatch(r"[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{8}", digest):
        raise ParseError("The descriptor checksum is not valid.")
    try:
        expected = checksum(body)
    except Exception as exc:
        raise ParseError("The descriptor checksum could not be checked.") from exc
    if expected != digest:
        raise ParseError("The descriptor checksum does not match.")
    return body, digest


def _normalize_expression(text: str) -> str:
    # Apostrophes are path markers. The letter H also appears inside an xpub,
    # so it is translated later, only inside the path.
    return "".join(text.split()).replace("’", "'")


def _key_from_expression(body: str, network: str) -> tuple[ParsedKey, str]:
    match = re.fullmatch(
        r"\[([0-9a-fA-F]{8})/([0-9hH'’/]+)\]([1-9A-HJ-NP-Za-km-z]+)(/.*)?",
        body,
    )
    if match is None:
        raise ParseError("A key expression needs a fingerprint, a path, and an extended key.")
    fingerprint = bytes.fromhex(match.group(1))
    try:
        path = parse_path(match.group(2))
        role, account = classify_path(path, network)
    except PathError as exc:
        raise ParseError(str(exc)) from exc
    extended = match.group(3)
    try:
        if role == SINGLESIG_TAPROOT and label_of(extended) not in ("xpub", "tpub"):
            raise ParseError("A taproot key uses an xpub or tpub, not a zpub or Zpub.")
        canonical = accept_for_role(extended, network, role)
        xpub = HDKey.from_base58(canonical)
    except (Slip132Error, ParseError) as exc:
        raise ParseError(str(exc)) from exc
    except Exception as exc:
        raise ParseError("The extended key could not be read.") from exc
    if xpub.depth != len(path) or xpub.child_number != path[-1]:
        raise ParseError(
            "The extended key's depth or last step does not match the derivation path."
        )
    branch_note = _read_suffix(match.group(4) or "")
    return ParsedKey(fingerprint, path, xpub, account, role, branch_note), branch_note


def _read_suffix(suffix: str) -> str:
    if suffix in ("", "/<0;1>/*", "/{0,1}/*"):
        return "both" if suffix else "account"
    if suffix in ("/0/*", "/0"):
        return "receive_only"
    if suffix in ("/1/*", "/1"):
        return "change_only"
    raise ParseError("The key expression uses an unsupported address suffix.")


def parse_key_expression(text: str, network: str) -> ParsedKey:
    body, _digest = split_checksum(_normalize_expression(text))
    key, _note = _key_from_expression(body, network)
    return key


def parse_wallet(text: str, network: str) -> ParsedWallet:
    warnings = []
    raw = unicodedata.normalize("NFKD", text).strip()
    body, _digest = split_checksum(_normalize_expression(raw))
    if body.startswith("wsh(sortedmulti(") or body.startswith("wsh(multi("):
        return _parse_multisig(body, network, warnings)
    if body.startswith("tr("):
        return _parse_singlesig(body, network, "tr", warnings)
    if body.startswith("wpkh("):
        return _parse_singlesig(body, network, "wpkh", warnings)
    if body.startswith(("sh(", "wsh(", "pkh(", "pk(")) or "sortedmulti_a" in body or "musig(" in body:
        raise ParseError("This version does not support that wallet type.")
    key = parse_key_expression(body, network)
    if key.role == MULTISIG_NATIVE:
        raise ParseError("A multisig key expression is not a wallet. Import a full descriptor.")
    warnings.extend(_branch_warnings(key.branch_note))
    return ParsedWallet(key.role, 1, [key], warnings)


def _parse_singlesig(body: str, network: str, wrapper: str, warnings: list[str]) -> ParsedWallet:
    if wrapper == "tr" and "," in body:
        raise ParseError("This version does not support a taproot script tree.")
    inner = body[len(wrapper) + 1 :]
    if not inner.endswith(")"):
        raise ParseError("The descriptor is missing a closing parenthesis.")
    inner = inner[:-1]
    key, note = _key_from_expression(inner, network)
    if wrapper == "wpkh" and key.role != SINGLESIG_NATIVE:
        raise ParseError("A wpkh descriptor requires a native-segwit single-sig path.")
    if wrapper == "tr" and key.role != SINGLESIG_TAPROOT:
        raise ParseError("A tr descriptor requires a taproot single-sig path.")
    warnings.extend(_branch_warnings(note))
    return ParsedWallet(key.role, 1, [key], warnings)


def _parse_multisig(body: str, network: str, warnings: list[str]) -> ParsedWallet:
    if body.startswith("wsh(multi("):
        raise ParseError("Only sorted multisig descriptors are accepted.")
    if not body.startswith("wsh(sortedmulti(") or not body.endswith(")"):
        raise ParseError("The multisig descriptor is not wsh(sortedmulti(...)).")
    inner = body[len("wsh(sortedmulti(") : -1]
    if not inner.endswith(")"):
        raise ParseError("The multisig descriptor is missing a closing parenthesis.")
    inner = inner[:-1]
    threshold_text, _, rest = inner.partition(",")
    if not threshold_text.isdigit():
        raise ParseError("The multisig threshold is missing.")
    threshold = int(threshold_text)
    parts = _split_top_level(rest)
    if not 1 <= threshold <= len(parts) or len(parts) < 2 or len(parts) > 15:
        raise ParseError("The multisig threshold or number of keys is not supported.")
    keys = []
    for part in parts:
        key, note = _key_from_expression(part, network)
        if key.role != MULTISIG_NATIVE:
            raise ParseError("A native-segwit multisig descriptor requires m/48h paths ending in 2h.")
        warnings.extend(_branch_warnings(note))
        keys.append(key)
    fingerprints = [key.fingerprint for key in keys]
    if len(set(fingerprints)) != len(fingerprints):
        raise ParseError(
            "This descriptor uses the same fingerprint more than once. "
            "A wallet keeps one account index for each fingerprint, "
            "so two different accounts of the same key cannot be loaded together."
        )
    return ParsedWallet(MULTISIG_NATIVE, threshold, keys, warnings)


def _split_top_level(text: str) -> list[str]:
    parts = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    if any(not part for part in parts):
        raise ParseError("The descriptor has an empty key.")
    return parts


def _branch_warnings(note: str) -> list[str]:
    if note == "receive_only":
        return ["The import named only receive addresses. Change addresses were assumed as well."]
    if note == "change_only":
        return ["The import named only change addresses. Receive addresses were assumed as well."]
    return []

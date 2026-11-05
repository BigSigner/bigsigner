"""Turn one scanned QR payload or SD card file into a named kind of content."""

from embit.bip39 import WORDLIST

from .bbqr import BbqrError, join_bbqr, split_bbqr, text_from_bbqr
from .bsms import descriptor_from_bsms
from .descriptor_files import descriptor_from_bitcoin_core, descriptor_from_specter
from .fountain import FountainDecoder, FountainError, part_from_cbor
from .parse import ParseError, _normalize_expression
from .paths import format_path
from .seedqr import mnemonic_from_compact, mnemonic_from_standard
from .session import SessionError, normalize_address_text
from .ur import split_ur, text_from_ur

# What a QR code or a file was recognized as, and the words used in a refusal.
_KIND_NAME = {
    "address": "an address",
    "seed": "a seed",
    "compact-seed": "a compact seed",
    "numeric-seed": "a numeric seed",
    "bsms": "a BSMS file",
    "descriptor": "a wallet descriptor",
    "key": "a key expression",
    "transaction": "a transaction",
    "legacy-address": "a legacy address",
    "wrapped-address": "a wrapped SegWit address",
}
_ACCEPTED = {
    "key": {"seed", "compact-seed", "numeric-seed", "bsms", "descriptor", "key"},
    "descriptor": {"bsms", "descriptor"},
    "address": {"address"},
}


class ParsedContent:
    """One recognized payload. ``text`` is the form the next step can use."""

    def __init__(self, kind: str, text: str):
        self.kind = kind
        self.text = text


def classify_content(text: str, network: str) -> ParsedContent:
    """Name a complete QR payload or file and return its usable text.

    A UR or a BBQr is read first. The name is the content inside it, such as
    a compact seed or a wallet descriptor, not the transport.
    """
    if not isinstance(text, str):
        return ParsedContent("unknown", "")
    raw = text.strip()
    payload = " ".join(raw.split())
    if payload.startswith("cHNidP") or payload.lower().startswith("psbt"):
        return ParsedContent("transaction", payload)
    compact = _compact_mnemonic(text)
    if compact:
        return ParsedContent("compact-seed", compact)
    if not payload:
        return ParsedContent("unknown", "")
    if raw.upper().startswith("BSMS"):
        try:
            descriptor = descriptor_from_bsms(raw, network)
        except ParseError as exc:
            raise SessionError(str(exc)) from exc
        return ParsedContent("bsms", descriptor)
    words = payload.split()
    if len(words) in (12, 18, 24) and all(word in WORDLIST for word in words):
        return ParsedContent("seed", " ".join(words))
    if payload.isdigit():
        try:
            mnemonic = mnemonic_from_standard(payload)
        except Exception as exc:
            raise SessionError("The seed checksum is not valid.") from exc
        return ParsedContent("numeric-seed", mnemonic)
    specter = descriptor_from_specter(raw)
    if specter is not None:
        return ParsedContent("descriptor", specter)
    try:
        core = descriptor_from_bitcoin_core(raw)
    except ParseError as exc:
        raise SessionError(str(exc)) from exc
    if core is not None:
        return ParsedContent("descriptor", core)
    if _looks_like_descriptor(payload):
        return ParsedContent("descriptor", payload)
    if _is_key_expression(payload):
        return ParsedContent("key", payload)
    address = _classify_address(text, network)
    if address is not None:
        return address
    return ParsedContent("unknown", payload)


def wrong_type_message(kind: str, expect: str, source: str, network: str = "main") -> str:
    """Say what was found when it is not what this screen asked for."""
    if kind in ("legacy-address", "wrapped-address") and expect == "address":
        prefix = {"main": "bc1", "test": "tb1", "regtest": "bcrt1"}.get(network, "bc1")
        return f"This is {_KIND_NAME[kind]}, not a {prefix} address."
    if kind == "unknown":
        if expect == "key":
            return f"That {source} is not a seed, key expression or wallet descriptor."
        if expect == "descriptor":
            return f"That {source} is not a wallet descriptor."
        if expect == "message":
            return f"That {source} is not a message signing command."
        if expect == "psbt":
            return f"That {source} is not a PSBT."
        return f"That {source} is not an address."
    if kind == "transaction" and expect == "key":
        return f"That {source} is a transaction, not a key."
    if kind == "transaction" and expect == "descriptor":
        return "This is a transaction, not a wallet descriptor."
    if kind == "seed" and expect == "descriptor":
        return "This is a seed, not a wallet descriptor."
    if kind == "key" and expect == "descriptor":
        return "This is a key expression, not a wallet descriptor."
    expected = {
        "address": "an address",
        "descriptor": "a wallet descriptor",
        "key": "a seed, a key expression, or a wallet descriptor",
        "message": "a message signing command",
        "psbt": "a PSBT",
    }[expect]
    return f"This is {_KIND_NAME.get(kind, 'something else')}, not {expected}."


def read_address(text: str, network: str, source: str = "QR code") -> str:
    """The address in a QR code or a file, or an error that names the other kind."""
    opened = _open_transport(text, network, source, "address")
    parsed = classify_content(opened, network)
    if parsed.kind != "address":
        raise SessionError(wrong_type_message(parsed.kind, "address", source, network))
    return parsed.text


def import_scanned(session, text: str, expect: str = "key", source: str = "QR code") -> dict:
    """Import a mnemonic, SeedQR, key expression, or wallet descriptor.

    ``expect="descriptor"`` rejects seeds and transactions. The wallets
    screen asks for a descriptor, not a seed. ``source`` is the words used
    in a warning, such as "QR code" or "file".
    """
    opened = _open_transport(text, session.network, source, expect)
    parsed = classify_content(opened, session.network)
    if parsed.kind == "unknown" and not parsed.text.strip():
        raise SessionError(f"That {source} is empty.")
    if parsed.kind not in _ACCEPTED[expect]:
        raise SessionError(wrong_type_message(parsed.kind, expect, source, session.network))
    return _load_parsed(session, parsed, expect)


def _open_transport(text: str, network: str, source: str, expect: str) -> str:
    if not isinstance(text, str) or len(text) > 100_000:
        raise SessionError(f"That {source} could not be read.")
    if not (_is_ur(text) or _is_bbqr(text)):
        return text
    payload = QrSequence().take(text, network, source, expect)
    if payload is None:
        raise SessionError(f"That {source} is one part of a sequence. Scan every part with the camera.")
    return payload


def _load_parsed(session, parsed: ParsedContent, expect: str) -> dict:
    if parsed.kind in ("seed", "compact-seed", "numeric-seed"):
        return session.add_mnemonic(parsed.text.split())
    if parsed.kind in ("descriptor", "bsms") and expect == "key":
        loaded = session._parse_supported_descriptor(parsed.text)
        return {
            "choose": "descriptor",
            "text": parsed.text,
            "multisig": loaded.multisig,
            "expressions": [_key_expression(key) for key in loaded.keys],
            "labels": [_key_label(key) for key in loaded.keys],
        }
    if parsed.kind == "key":
        return {"review": "external-key", "key": session.prepare_external_key(parsed.text)}
    return {"review": "wallet", "text": parsed.text}


def _classify_address(text: str, network: str) -> ParsedContent | None:
    raw = "".join(str(text).split())
    if not raw:
        return None
    lowered = raw.lower()
    if lowered.startswith("bitcoin://"):
        body = raw[len("bitcoin://") :]
    elif lowered.startswith("bitcoin:"):
        body = raw[len("bitcoin:") :]
    else:
        body = raw
    body = "".join(body.split())
    body = body.split("?", 1)[0].split("#", 1)[0]
    folded = body.lower()
    if _legacy_address(body, network):
        kind = "wrapped-address" if body[:1] in "32" else "legacy-address"
        return ParsedContent(kind, body)
    prefix = {"main": "bc1", "test": "tb1", "regtest": "bcrt1"}.get(network, "bc1")
    if not folded.startswith(prefix) and not lowered.startswith("bitcoin:"):
        return None
    return ParsedContent("address", normalize_address_text(text, network))


_BRANCH_SUFFIX = {
    "both": "/<0;1>/*",
    "account": "",
    "receive_only": "/0/*",
    "change_only": "/1/*",
}


def _looks_like_descriptor(payload: str) -> bool:
    body = _normalize_expression(payload).split("#", 1)[0]
    return body.startswith(("wpkh(", "tr(", "wsh(", "sh(", "pkh(", "pk(", "musig("))


def _key_expression(key) -> str:
    origin = format_path(list(key.path))[2:]
    return f"[{key.fingerprint.hex()}/{origin}]{key.canonical}{_BRANCH_SUFFIX[key.branch_note]}"


def _key_label(key) -> str:
    return f"{key.fingerprint.hex()} {key.canonical[:10]}\u2026"


def _is_key_expression(payload: str) -> bool:
    body = payload.split("#", 1)[0].strip()
    return body.startswith("[")


def _legacy_address(text: str, network: str) -> bool:
    if len(text) < 26 or len(text) > 35:
        return False
    alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    if any(char not in alphabet for char in text):
        return False
    if network == "main":
        return text[0] in "13"
    return text[0] in "mn2"


def _is_ur(text: str) -> bool:
    return text.strip().lower().startswith("ur:")


def _is_bbqr(text: str) -> bool:
    return text.strip().upper().startswith("B$")


class QrSequence:
    """Parts of one UR or BBQr collected while the camera stays on the code."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.received = 0
        self.expected = 0
        self._ur = None
        self._ur_type = None
        self._bb_header = None
        self._bb_parts = {}
        self._bb_encoding = None
        self._bb_type = None

    def take(self, text: str, network: str, source: str, expect: str) -> str | None:
        if _is_ur(text):
            return self._take_ur(text, network, source)
        if _is_bbqr(text):
            return self._take_bbqr(text, source, expect)
        self.reset()
        return text

    def _take_ur(self, text: str, network: str, source: str) -> str | None:
        try:
            type_name, seq, payload = split_ur(text)
        except ValueError as exc:
            raise SessionError(f"That {source} could not be read.") from exc
        if seq is None:
            self.reset()
            return text_from_ur(type_name, payload, network)
        try:
            part = part_from_cbor(payload)
        except (FountainError, ValueError) as exc:
            raise SessionError(f"That {source} could not be read.") from exc
        if self._ur is None or self._ur_type != type_name:
            self.reset()
            self._ur = FountainDecoder()
            self._ur_type = type_name
        try:
            accepted = self._ur.receive(*part)
        except FountainError as exc:
            raise SessionError(f"That {source} could not be read.") from exc
        if not accepted:
            self.reset()
            self._ur = FountainDecoder()
            self._ur_type = type_name
            try:
                accepted = self._ur.receive(*part)
            except FountainError as exc:
                raise SessionError(f"That {source} could not be read.") from exc
            if not accepted:
                raise SessionError(f"That {source} could not be read.")
        self.received = self._ur.codes
        self.expected = self._ur.expected
        if self._ur.message is None:
            return None
        kind = self._ur_type
        message = self._ur.message
        self.reset()
        return text_from_ur(kind, message, network)

    def _take_bbqr(self, text: str, source: str, expect: str) -> str | None:
        try:
            encoding, file_type, count, index, payload = split_bbqr(text)
        except BbqrError as exc:
            raise SessionError(f"That {source} could not be read.") from exc
        header = "".join(text.split()).upper()[:6]
        if self._bb_header != header:
            self.reset()
            self._bb_header = header
            self._bb_encoding = encoding
            self._bb_type = file_type
        elif self._bb_parts.get(index) not in (None, payload):
            raise SessionError(f"That {source} could not be read.")
        self._bb_parts[index] = payload
        self.received = len(self._bb_parts)
        self.expected = count
        if len(self._bb_parts) < count:
            return None
        ordered = [self._bb_parts[number] for number in range(count)]
        try:
            raw = join_bbqr(ordered, self._bb_encoding)
        except BbqrError as exc:
            raise SessionError(f"That {source} could not be read.") from exc
        kind = self._bb_type
        self.reset()
        return text_from_bbqr(kind, raw, expect, source)


def _compact_mnemonic(text: str) -> str | None:
    if any(ord(char) > 255 for char in text):
        return None
    raw = text.encode("latin-1")
    if len(raw) not in (16, 24, 32):
        return None
    try:
        return mnemonic_from_compact(raw)
    except Exception:
        return None

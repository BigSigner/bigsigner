"""Turn one scanned QR payload into a seed, a key, or a wallet."""

from embit.bip39 import WORDLIST

from .bbqr import BbqrError, join_bbqr, split_bbqr, text_from_bbqr
from .bsms import descriptor_from_bsms
from .fountain import FountainDecoder, FountainError, part_from_cbor
from .parse import ParseError, _normalize_expression
from .paths import format_path
from .seedqr import mnemonic_from_compact, mnemonic_from_standard
from .session import SessionError
from .ur import split_ur, text_from_ur


def import_scanned(session, text: str, expect: str = "key", source: str = "QR code") -> dict:
    """Import a mnemonic, SeedQR, key expression, or wallet descriptor.

    ``expect="descriptor"`` rejects seeds and transactions. The wallets
    screen asks for a descriptor, not a seed. ``source`` is the words used
    in a warning, such as "QR code" or "file".
    """
    if not isinstance(text, str) or len(text) > 100_000:
        raise SessionError(f"That {source} could not be read.")
    if _is_ur(text) or _is_bbqr(text):
        payload = QrSequence().take(text, session.network, source, expect)
        if payload is None:
            raise SessionError(
                f"That {source} is one part of a sequence. Scan every part with the camera."
            )
        text = payload
    raw = text.strip()
    if raw.upper().startswith("BSMS"):
        try:
            raw = descriptor_from_bsms(raw, session.network)
        except ParseError as exc:
            raise SessionError(str(exc)) from exc
    payload = " ".join(raw.split())
    if not payload:
        raise SessionError(f"That {source} is empty.")
    if payload.startswith("cHNidP") or payload.lower().startswith("psbt"):
        if expect == "descriptor":
            raise SessionError("This is a transaction, not a wallet descriptor.")
        raise SessionError(f"That {source} is a transaction, not a key.")
    if expect == "descriptor" and _is_seed(text, payload):
        raise SessionError("This is a seed, not a wallet descriptor.")
    compact = _compact_mnemonic(text)
    if compact:
        return session.add_mnemonic(compact.split())
    words = payload.split()
    if len(words) in (12, 18, 24) and all(word in WORDLIST for word in words):
        return session.add_mnemonic(words)
    if payload.isdigit():
        try:
            mnemonic = mnemonic_from_standard(payload)
        except Exception as exc:
            raise SessionError("The seed checksum is not valid.") from exc
        return session.add_mnemonic(mnemonic.split())
    if expect == "key" and _looks_like_descriptor(payload):
        parsed = session._parse_supported_descriptor(payload)
        return {
            "choose": "descriptor",
            "text": payload,
            "multisig": parsed.multisig,
            "expressions": [_key_expression(key) for key in parsed.keys],
            "labels": [_key_label(key) for key in parsed.keys],
        }
    if expect == "key" and _is_key_expression(payload):
        return {"review": "external-key", "key": session.prepare_external_key(payload)}
    if expect == "descriptor":
        if _is_key_expression(payload):
            raise SessionError("This is a key expression, not a wallet descriptor.")
        return {"review": "wallet", "text": payload}
    try:
        return session.add_text(payload)
    except SessionError as exc:
        if payload.startswith(("[", "wpkh(", "wsh(", "tr(", "sh(")):
            raise
        if expect == "key":
            raise SessionError(
                f"That {source} is not a seed, key expression or wallet descriptor."
            ) from exc
        raise SessionError(f"That {source} is not a seed, key expression, or wallet descriptor.") from exc


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
    return f"{key.fingerprint.hex()} {key.canonical[:10]}..."


def _is_key_expression(payload: str) -> bool:
    body = payload.split("#", 1)[0].strip()
    return body.startswith("[")


def _is_seed(text: str, payload: str) -> bool:
    if _compact_mnemonic(text):
        return True
    words = payload.split()
    if len(words) in (12, 18, 24) and all(word in WORDLIST for word in words):
        return True
    return payload.isdigit() and len(payload) in (48, 72, 96)


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

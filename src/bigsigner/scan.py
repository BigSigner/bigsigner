"""Turn one scanned QR payload into a seed, a key, or a wallet."""

from embit.bip39 import WORDLIST

from .bsms import descriptor_from_bsms
from .parse import ParseError, _normalize_expression
from .paths import format_path
from .seedqr import mnemonic_from_compact, mnemonic_from_standard
from .session import SessionError


def import_scanned(session, text: str, expect: str = "key", source: str = "QR code") -> dict:
    """Import a mnemonic, SeedQR, key expression, or wallet descriptor.

    ``expect="descriptor"`` rejects seeds and transactions. The wallets
    screen asks for a descriptor, not a seed. ``source`` is the words used
    in a warning, such as "QR code" or "file".
    """
    if not isinstance(text, str) or len(text) > 100_000:
        raise SessionError(f"That {source} could not be read.")
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

"""SLIP-132 prefixes. Exports stay xpub or tpub. The other spellings are labels."""

from embit.base58 import decode_check, encode_check

from .paths import MULTISIG_NATIVE, SINGLESIG_NATIVE

MAIN_XPUB = bytes.fromhex("0488b21e")
TEST_TPUB = bytes.fromhex("043587cf")

_LABELS = {
    bytes.fromhex("0488b21e"): "xpub",
    bytes.fromhex("04b24746"): "zpub",
    bytes.fromhex("02aa7ed3"): "Zpub",
    bytes.fromhex("049d7cb2"): "ypub",
    bytes.fromhex("0295b43f"): "Ypub",
    bytes.fromhex("043587cf"): "tpub",
    bytes.fromhex("045f1cf6"): "vpub",
    bytes.fromhex("02575483"): "Vpub",
    bytes.fromhex("044a5262"): "upub",
    bytes.fromhex("024289ef"): "Upub",
}

_ACCEPTED = {
    ("main", SINGLESIG_NATIVE): {"xpub", "zpub"},
    ("test", SINGLESIG_NATIVE): {"tpub", "vpub"},
    ("main", MULTISIG_NATIVE): {"xpub", "Zpub"},
    ("test", MULTISIG_NATIVE): {"tpub", "Vpub"},
}


class Slip132Error(ValueError):
    pass


def label_of(extended: str) -> str:
    try:
        raw = decode_check(extended)
    except Exception as exc:
        raise Slip132Error("The extended key is not valid Base58.") from exc
    if len(raw) != 78:
        raise Slip132Error("The extended key has the wrong length.")
    label = _LABELS.get(raw[:4])
    if label is None:
        raise Slip132Error("The extended key uses an unknown version prefix.")
    return label


def _slip_network(network: str) -> str:
    """Regtest has no SLIP-132 prefixes. It uses the testnet vpub and Vpub bytes."""
    if network == "main":
        return "main"
    if network in ("test", "regtest"):
        return "test"
    raise Slip132Error("The network must be mainnet, testnet, or regtest.")


def to_canonical(extended: str, network: str) -> str:
    raw = bytearray(decode_check(extended))
    raw[:4] = MAIN_XPUB if _slip_network(network) == "main" else TEST_TPUB
    return encode_check(bytes(raw))


def accept_for_role(extended: str, network: str, role: str) -> str:
    """Return the xpub or tpub form, or explain why this prefix is refused."""
    label = label_of(extended)
    if role not in (SINGLESIG_NATIVE, MULTISIG_NATIVE):
        if label not in ("xpub", "tpub"):
            raise Slip132Error("Taproot keys are shown as xpub or tpub, not as a zpub.")
        version_network = _slip_network(network)
        expected = "xpub" if version_network == "main" else "tpub"
        if label != expected:
            raise Slip132Error("The extended key does not match the current network setting.")
        return extended
    allowed = _ACCEPTED[(_slip_network(network), role)]
    if label not in allowed:
        if label in ("zpub", "vpub", "Zpub", "Vpub"):
            raise Slip132Error(
                "That extended-key prefix does not match this derivation path "
                "or the current network setting."
            )
        raise Slip132Error(
            "This version does not accept legacy or nested-segwit extended keys."
        )
    return to_canonical(extended, network)


def display_form(canonical: str, network: str, role: str) -> str | None:
    """The SLIP-132 spelling, or None when this key has no alternate form."""
    targets = {
        ("main", SINGLESIG_NATIVE): bytes.fromhex("04b24746"),
        ("test", SINGLESIG_NATIVE): bytes.fromhex("045f1cf6"),
        ("main", MULTISIG_NATIVE): bytes.fromhex("02aa7ed3"),
        ("test", MULTISIG_NATIVE): bytes.fromhex("02575483"),
    }
    target = targets.get((_slip_network(network), role))
    if target is None:
        return None
    raw = bytearray(decode_check(canonical))
    raw[:4] = target
    return encode_check(bytes(raw))

"""Derivation paths for the three wallets this version understands."""

HARDENED = 0x80000000

SINGLESIG_NATIVE = "singlesig_native"
SINGLESIG_TAPROOT = "singlesig_taproot"
MULTISIG_NATIVE = "multisig_native"
TAPROOT_MULTISIG = "taproot_multisig"


class PathError(ValueError):
    pass


def coin_type(network: str) -> int:
    if network == "main":
        return 0
    if network in ("test", "regtest"):
        return 1
    raise PathError(f"Unknown network {network}.")


def format_index(value: int) -> str:
    if value & HARDENED:
        return f"{value & ~HARDENED}h"
    return str(value)


def format_path(steps: list[int]) -> str:
    return "m/" + "/".join(format_index(step) for step in steps)


def parse_path(text: str) -> list[int]:
    raw = text.strip().replace("’", "h").replace("'", "h").replace("H", "h")
    if raw.startswith("m/"):
        raw = raw[2:]
    if raw.startswith("/"):
        raw = raw[1:]
    if not raw:
        raise PathError("The derivation path is empty.")
    steps = []
    for part in raw.split("/"):
        if not part:
            raise PathError("The derivation path has an empty step.")
        hardened = part.endswith("h")
        number = part[:-1] if hardened else part
        if not number.isdigit():
            raise PathError(f"Cannot read derivation step {part}.")
        value = int(number)
        if value > 0x7FFFFFFF:
            raise PathError(f"Derivation step {part} is too large.")
        steps.append(value | HARDENED if hardened else value)
    return steps


def classify_path(steps: list[int], network: str) -> tuple[str, int]:
    """Return the role and the account index, or raise PathError."""
    coin = coin_type(network) | HARDENED
    try:
        return _classify_account_path(steps, coin)
    except PathError as exc:
        mismatch = path_network_mismatch(steps, network)
        if mismatch:
            raise PathError(mismatch) from exc
        raise


def path_network_mismatch(steps: list[int], network: str, *, address: bool = False) -> str | None:
    """Explain a wrong coin type only when the rest is a supported path.

    Account origins are checked by default. PSBTs and message-signing commands
    also need a valid Receive/Change branch and non-hardened address index.
    """
    coin = coin_type(network) | HARDENED
    if address:
        if len(steps) < 5 or steps[-2] not in (0, 1) or not 0 <= steps[-1] < HARDENED:
            return None
        steps = steps[:-2]
    if len(steps) < 2 or steps[1] not in (HARDENED, HARDENED | 1) or steps[1] == coin:
        return None
    if any(not 0 <= step < 2 * HARDENED for step in steps):
        return None
    try:
        _classify_account_path(steps, steps[1])
    except PathError:
        return None
    selected = {"main": "mainnet", "test": "testnet", "regtest": "regtest"}[network]
    belonging = "mainnet" if steps[1] == HARDENED else "testnet or regtest"
    return f"The currently selected network is {selected}, but the derivation path belongs to {belonging}."


def _classify_account_path(steps: list[int], coin: int) -> tuple[str, int]:
    purpose = steps[0] if steps else None
    if (
        len(steps) == 4
        and purpose == 48 | HARDENED
        and steps[1] == coin
        and steps[2] & HARDENED
        and steps[3] == 3 | HARDENED
    ):
        raise PathError("This version does not support taproot multisig.")
    if len(steps) == 3 and purpose == 84 | HARDENED and steps[1] == coin and steps[2] & HARDENED:
        return SINGLESIG_NATIVE, steps[2] & ~HARDENED
    if len(steps) == 3 and purpose == 86 | HARDENED and steps[1] == coin and steps[2] & HARDENED:
        return SINGLESIG_TAPROOT, steps[2] & ~HARDENED
    if (
        len(steps) == 4
        and purpose == 48 | HARDENED
        and steps[1] == coin
        and steps[2] & HARDENED
        and steps[3] == 2 | HARDENED
    ):
        return MULTISIG_NATIVE, steps[2] & ~HARDENED
    raise PathError(
        "The derivation path is not a supported singlesig or multisig path for this network."
    )

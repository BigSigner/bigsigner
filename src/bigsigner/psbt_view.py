"""The words on the Transaction Signing screen.

Bitcoin amounts stay strings. A satoshi count is padded to at least nine
digits and a point is placed eight digits from the right. Nothing here
divides the amount by 1e8.
"""

from datetime import datetime, timezone

from embit.networks import NETWORKS
from embit.psbt import PSBT

from .psbt_check import _input_amount, multisig_signature_note, seed_sign_rows
from .psbt_review import LOCKTIME_THRESHOLD, _derivations, _estimate_vsize, _locate
from .session import SessionError

OP_RETURN_WARNING = (
    "This transaction contains an OP_RETURN. "
    "Do not continue unless you specifically meant to add some custom metadata."
)
OP_RETURN_VALUE_WARNING = (
    "This transaction contains an OP_RETURN with a non-zero amount. "
    "That amount will not be spendable by anyone, ever. "
    "Do not continue unless you specifically meant to add some custom metadata."
)
HIGH_FEE_WARNING = "This transaction uses an extremely high fee."
TIMESTAMP_LEAD = (
    "This transaction uses a timestamp locktime. "
    "It can be mined only after:"
)
TIMESTAMP_NOTE = (
    "The time is calculated from the median timestamp reported in recent blocks, "
    "so it can differ significantly from the real current time."
)
RELATIVE_ONE = "One input uses a relative locktime."
RELATIVE_SOME = "Some inputs use a relative locktime."
RELATIVE_EXTRA = " This is an additional requirement on top of the absolute locktime."
RBF_ONE = (
    "One input is marked as Replace-by-Fee (RBF) Disabled. "
    "The Bitcoin network no longer honors that flag, "
    "so a higher-fee transaction could still replace this one."
)
RBF_SOME = (
    "Some inputs are marked as Replace-by-Fee (RBF) Disabled. "
    "The Bitcoin network no longer honors that flag, "
    "so a higher-fee transaction could still replace this one."
)
ALL_TO_WALLET = (
    "This transaction sends all funds back to the same wallet, except for the fee."
)
MANY_CHANGE_WARNING = (
    "This transaction has more than one change output. "
    "That is unusual, although a wallet may do it for privacy."
)
RECEIVE_CHANGE_ONE = (
    "One of the change outputs appears to be a receive address instead of a change address. "
    "This is unusual, but mostly harmless."
)
RECEIVE_CHANGE_SOME = (
    "Some of the change outputs appear to be receive addresses instead of change addresses. "
    "This is unusual, but mostly harmless."
)
HIGH_FEE_SATS = 100_000
SEARCH_WINDOW = 50
SEQUENCE_DISABLED = 0xFFFFFFFE
SEQUENCE_STANDARD = 0xFFFFFFFD


def format_btc(sats: int, *, bare_zero: bool = False) -> str:
    """Sats as a BTC string. Zero can stay the single character 0."""
    value = int(sats)
    if bare_zero and value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    digits = str(abs(value)).zfill(9)
    whole, frac = digits[:-8], digits[-8:]
    groups = []
    while whole:
        groups.append(whole[-3:])
        whole = whole[:-3]
    return sign + ",".join(reversed(groups)) + "." + frac


def format_fee_rate(fee: int, vsize: int) -> str:
    """Two decimal places. 3.4 and 3.403 are both 3.40."""
    if vsize <= 0:
        return "0.00"
    return f"{fee / vsize:.2f}"


def format_duration(seconds: int) -> str:
    """Days, hours, minutes, and seconds, with the zero parts left out."""
    remaining = max(0, int(seconds))
    days, remaining = divmod(remaining, 86400)
    hours, remaining = divmod(remaining, 3600)
    minutes, secs = divmod(remaining, 60)
    parts = []
    for count, one, many in (
        (days, "day", "days"),
        (hours, "hour", "hours"),
        (minutes, "minute", "minutes"),
        (secs, "second", "seconds"),
    ):
        if count:
            parts.append(f"{count} {one if count == 1 else many}")
    return ", ".join(parts) if parts else "0 seconds"


def format_locktime(locktime: int) -> str:
    """A Unix timestamp as UTC, independent of the device clock zone."""
    moment = datetime.fromtimestamp(int(locktime), timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def account_line(fingerprints, accounts: dict) -> str:
    indexes = [int(accounts[fingerprint]) for fingerprint in fingerprints]
    if len(indexes) > 1:
        note = "default" if all(index == 0 for index in indexes) else "non-default"
        return f"Account: {', '.join(str(index) for index in indexes)} ({note})"
    index = indexes[0] if indexes else 0
    note = "default" if index == 0 else "non-default"
    return f"Account: {index} ({note})"


def place_line(branch: int, index: int) -> str:
    kind = "Receive" if branch == 0 else "Change"
    return f"{kind} Address #{index}"


def op_return_payload(raw: bytes) -> bytes:
    """The data pushes that follow OP_RETURN, concatenated."""
    if not raw.startswith(b"\x6a"):
        return b""
    data = raw[1:]
    out = bytearray()
    index = 0
    while index < len(data):
        opcode = data[index]
        index += 1
        if opcode == 0x00:
            continue
        if 0x51 <= opcode <= 0x60:
            out.append(opcode - 0x50)
            continue
        if opcode == 0x4F:
            continue
        if opcode <= 0x4B:
            out += data[index : index + opcode]
            index += opcode
            continue
        if opcode == 0x4C and index < len(data):
            length = data[index]
            index += 1
            out += data[index : index + length]
            index += length
            continue
        if opcode == 0x4D and index + 2 <= len(data):
            length = int.from_bytes(data[index : index + 2], "little")
            index += 2
            out += data[index : index + length]
            index += length
            continue
        if opcode == 0x4E and index + 4 <= len(data):
            length = int.from_bytes(data[index : index + 4], "little")
            index += 4
            out += data[index : index + length]
            index += length
            continue
        break
    return bytes(out)


def hex_lines(payload: bytes) -> list[str]:
    """Eight bytes on a line, each byte two hex digits, separated by spaces."""
    if not payload:
        return [""]
    lines = []
    for start in range(0, len(payload), 8):
        chunk = payload[start : start + 8]
        lines.append(" ".join(f"{byte:02x}" for byte in chunk))
    return lines


def is_ascii(payload: bytes) -> bool:
    try:
        payload.decode("ascii")
    except UnicodeDecodeError:
        return False
    return True


def sequence_text(sequence: int) -> str:
    return f"0x{int(sequence):08X}"


# Paths both mempool.space and blockstream.info publish. Neither site has regtest.
EXPLORER_NETWORKS = (
    ("testnet", "Testnet"),
    ("testnet4", "Testnet4"),
    ("signet", "Signet"),
)


def input_qr_text(network: str, txid: str, vout: int, kind: str, explorer: str = "testnet") -> str:
    """A QR payload for one previous output.

    Mempool.space accepts ``txid:vout`` in the transaction URL and highlights
    that output. Blockstream.info uses ``#output:`` for the same output.
    Testnet and regtest choose among the public networks both sites publish.
    """
    point = f"{txid}:{int(vout)}"
    if kind == "raw":
        return point
    prefix = ""
    if network in ("test", "regtest"):
        slug = explorer if explorer in {item[0] for item in EXPLORER_NETWORKS} else "testnet"
        prefix = f"/{slug}"
    if kind == "mempool":
        return f"https://mempool.space{prefix}/tx/{point}"
    return f"https://blockstream.info{prefix}/tx/{txid}#output:{int(vout)}"


def txid_rows(txid: str) -> list[str]:
    """Four centered rows of 16 hex characters."""
    text = txid.lower()
    return [text[index : index + 16] for index in range(0, 64, 16)]


def describe_psbt(session, wallet_index: int, psbt: PSBT) -> dict:
    """Everything the Transaction Signing screen says about one checked PSBT."""
    wallet = session.wallets[wallet_index]
    transaction = psbt.tx
    inputs = [_input_card(psbt, index) for index in range(len(psbt.inputs))]
    outputs = []
    change_outputs = []
    for index, scope in enumerate(psbt.outputs):
        card = _output_card(session, wallet_index, psbt, index, scope)
        if card["change"]:
            change_outputs.append(card)
        else:
            outputs.append(card)
    if not outputs and _change_returns_to_spending_account(wallet, change_outputs):
        for card in change_outputs:
            card["receive_change"] = False
    fee = sum(item["amount"] for item in inputs) - sum(
        int(scope.value if scope.value is not None else psbt.tx.vout[index].value)
        for index, scope in enumerate(psbt.outputs)
    )
    vsize = _estimate_vsize(
        transaction, [{}] * len(psbt.inputs), [{}] * len(psbt.outputs), wallet
    )
    locktime = int(transaction.locktime or 0)
    warnings = _warnings(inputs, outputs, change_outputs, fee, locktime)
    relative = [item["index"] for item in inputs if item["relative"]]
    txid = transaction.txid().hex()
    return {
        "wallet_name": session.wallet_short_name_of(wallet),
        "account_line": account_line(wallet.fingerprints, wallet.accounts),
        "txid": txid,
        "txid_rows": txid_rows(txid),
        "locktime": locktime,
        "banner": _banner(locktime),
        "more_info": _more_info(locktime),
        "warnings": warnings,
        "outputs": outputs,
        "outputs_note": "" if outputs else ALL_TO_WALLET,
        "change_outputs": change_outputs,
        "fee": fee,
        "fee_rate": format_fee_rate(fee, vsize),
        "fee_high": fee >= HIGH_FEE_SATS,
        "locktime_label": _locktime_label(locktime, relative),
        "locktime_tone": "yellow" if locktime >= LOCKTIME_THRESHOLD else "grey",
        "relative_indexes": relative,
        "relative_line": _relative_line(relative, locktime),
        "inputs": inputs,
        "inputs_open": any(item["sequence"] != SEQUENCE_STANDARD for item in inputs),
        "change_open": _change_section_open(change_outputs),
        "signers": seed_sign_rows(session, wallet, psbt),
        "signature_note": multisig_signature_note(wallet, psbt),
    }


def search_address(session, spending_index: int, address: str, start: int, count: int = SEARCH_WINDOW):
    """A bounded search for callers that do not drive an interactive screen."""
    from .address_search import AddressSearch, MAX_INDEX

    if count <= 0:
        return None
    wallet = session.wallets[spending_index]
    selected = min(wallet.accounts.values())
    first = max(0, selected - 2)
    try:
        search = AddressSearch(session, address, first, min(first + 5, MAX_INDEX), start, min(start + count - 1, MAX_INDEX))
    except SessionError:
        return None
    try:
        while not search.done:
            search.step()
        found = search.result
        if found is not None:
            wallet = session.wallets[found["wallet_index"]]
            accounts = dict(zip(wallet.fingerprints, found["account_indexes"]))
            found["name"] = session.wallet_short_name_of(wallet)
            found["account_line"] = account_line(wallet.fingerprints, accounts)
            found["place"] = place_line(found["branch"], found["address_index"])
        return found
    finally:
        search.close()


def _change_section_open(change_outputs: list[dict]) -> bool:
    """Open the change list when a change output is unusual.

    A single change address stays closed. A receive address used as change, or
    more than one change output, is a warning and starts open.
    """
    if len(change_outputs) > 1:
        return True
    return any(card.get("receive_change") for card in change_outputs)


def _change_returns_to_spending_account(wallet, change_outputs: list[dict]) -> bool:
    """True when every change output uses the account this transaction spends."""
    if not change_outputs:
        return False
    spending = {fingerprint: int(wallet.accounts[fingerprint]) for fingerprint in wallet.fingerprints}
    for card in change_outputs:
        accounts = card.get("accounts") or {}
        if set(accounts) != set(spending):
            return False
        if any(int(accounts[fingerprint]) != spending[fingerprint] for fingerprint in spending):
            return False
    return True


def _warnings(inputs: list[dict], outputs: list[dict], change_outputs: list[dict], fee: int, locktime: int) -> list[dict]:
    warnings = []
    if any(item["kind"] == "op_return" and item["amount"] for item in outputs):
        warnings.append({"text": OP_RETURN_VALUE_WARNING, "tone": "red"})
    elif any(item["kind"] == "op_return" for item in outputs):
        warnings.append({"text": OP_RETURN_WARNING, "tone": "yellow"})
    if fee >= HIGH_FEE_SATS:
        warnings.append({"text": HIGH_FEE_WARNING, "tone": "red"})
    if locktime >= LOCKTIME_THRESHOLD:
        warnings.append({
            "text": TIMESTAMP_LEAD,
            "center": format_locktime(locktime),
            "after": TIMESTAMP_NOTE,
            "tone": "yellow",
        })
    relative = [item for item in inputs if item["relative"]]
    if relative:
        text = RELATIVE_ONE if len(relative) == 1 else RELATIVE_SOME
        if locktime:
            text += RELATIVE_EXTRA
        text += " See below for more details."
        warnings.append({"text": text, "tone": "yellow"})
    disabled = [item for item in inputs if item["sequence"] == SEQUENCE_DISABLED]
    if disabled:
        warnings.append({"text": RBF_ONE if len(disabled) == 1 else RBF_SOME, "tone": "yellow"})
    if len(change_outputs) > 1:
        warnings.append({"text": MANY_CHANGE_WARNING, "tone": "yellow"})
    receive_change = [item for item in change_outputs if item["receive_change"]]
    if receive_change:
        text = RECEIVE_CHANGE_ONE if len(receive_change) == 1 else RECEIVE_CHANGE_SOME
        warnings.append({"text": text, "tone": "yellow"})
    return warnings


def _banner(locktime: int) -> str:
    if locktime <= 0 or locktime >= LOCKTIME_THRESHOLD:
        return ""
    return f"This transaction can be mined only after block height {locktime}."


def _more_info(locktime: int) -> str:
    """Why a block-height locktime is usually close to the chain tip.

    A transaction is final only when nLockTime is strictly less than the
    block height, so block N cannot include a transaction locked to N.
    """
    if locktime <= 0 or locktime >= LOCKTIME_THRESHOLD:
        return ""
    return (
        "Modern wallets often set a block-height locktime close to the current block height, "
        "in order to discourage miners from rewriting recent blocks (a.k.a. reorgs). "
        "If you did not set a custom locktime and you want to broadcast this transaction right away, "
        f"check that the current block height is above {locktime}."
    )


def _locktime_label(locktime: int, relative: list[int]) -> str:
    if locktime <= 0 and not relative:
        return "No Locktimes: The transaction could be mined right away."
    if locktime <= 0:
        return "No Absolute Locktime"
    if locktime < LOCKTIME_THRESHOLD:
        return f"Absolute Locktime: After block height {locktime}"
    return f"Absolute Locktime: {format_locktime(locktime)}"


def _relative_line(indexes: list[int], locktime: int) -> str:
    if not indexes:
        return ""
    if len(indexes) == 1:
        text = f"Input {indexes[0]} uses a relative locktime."
    else:
        listed = ", ".join(str(index) for index in indexes)
        text = f"Inputs {listed} use a relative locktime."
    if locktime:
        text += RELATIVE_EXTRA
    return text


def _input_card(psbt: PSBT, index: int) -> dict:
    scope = psbt.inputs[index]
    vin = psbt.tx.vin[index]
    sequence = int(scope.sequence if scope.sequence is not None else vin.sequence)
    amount = int(_input_amount(psbt, index) or 0)
    relative = _relative(sequence)
    txid = vin.txid.hex()
    return {
        "index": index,
        "txid": txid,
        "txid_rows": txid_rows(txid),
        "vout": int(vin.vout),
        "amount": amount,
        "sequence": sequence,
        "relative": relative,
        "rbf_disabled": sequence == SEQUENCE_DISABLED,
    }


def _relative(sequence: int):
    if sequence >= SEQUENCE_STANDARD:
        return None
    if sequence <= 0xFFFF:
        noun = "block" if sequence == 1 else "blocks"
        return {"kind": "blocks", "label": "Relative Locktime:", "duration": f"{sequence} {noun}"}
    if 0x00400000 <= sequence <= 0x0040FFFF:
        seconds = (sequence & 0xFFFF) * 512
        return {"kind": "time", "label": "Relative Locktime:", "duration": format_duration(seconds)}
    return None


def _output_card(session, wallet_index: int, psbt: PSBT, index: int, scope) -> dict:
    vout = psbt.tx.vout[index]
    script = scope.script_pubkey or vout.script_pubkey
    amount = int(scope.value if scope.value is not None else vout.value)
    raw = b"" if script is None else bytes(script.data)
    if raw.startswith(b"\x6a"):
        payload = op_return_payload(raw)
        return {
            "index": index,
            "kind": "op_return",
            "amount": amount,
            "address": "",
            "owned": None,
            "change": False,
            "payload": payload,
            "ascii": is_ascii(payload),
            "hex_lines": hex_lines(payload),
        }
    owned = _owned_output(session, script, _derivations(scope))
    # Either branch can return change, but another account is a payment.
    change = bool(
        owned
        and owned["wallet_index"] == wallet_index
        and owned["accounts"] == session.wallets[wallet_index].accounts
    )
    address = ""
    if script is not None:
        try:
            address = script.address(network=_network(session.network))
        except Exception:
            address = raw.hex()
    return {
        "index": index,
        "kind": "payment",
        "amount": amount,
        "address": address,
        "owned": None if change else owned,
        "change": change,
        "place": owned["place"] if change else "",
        "accounts": None if owned is None else owned["accounts"],
        "receive_change": bool(change and owned["branch"] == 0),
        "payload": None,
        "ascii": False,
        "hex_lines": [],
    }


def _owned_output(session, script, derivations):
    if script is None or not derivations:
        return None
    for index, wallet in enumerate(session.wallets):
        try:
            located = _locate(session, wallet, derivations, script, required=False)
        except Exception:
            continue
        if not located:
            continue
        return {
            "wallet_index": index,
            "name": session.wallet_short_name_of(wallet),
            "account_line": account_line(wallet.fingerprints, located["accounts"]),
            "accounts": located["accounts"],
            "branch": located["branch"],
            "index": located["index"],
            "place": place_line(located["branch"], located["index"]),
        }
    return None


def _network(name: str):
    if name == "main":
        return NETWORKS["main"]
    if name == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]

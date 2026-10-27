"""Review a PSBT against one loaded wallet before anything is signed."""

from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, PSBTError
from embit.script import Script
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput, Witness

from .paths import HARDENED, classify_path, format_path, parse_path
from .session import SessionError, _account_path, _descriptor, _public_for, _seed_root

LOCKTIME_THRESHOLD = 500_000_000
SEQUENCE_FINAL = 0xFFFFFFFF
RBF_SIGNAL_BELOW = 0xFFFFFFFE


class ReviewError(ValueError):
    pass


def review_psbt(session, wallet_index: int, raw: str | bytes) -> dict:
    try:
        psbt = PSBT.from_string(raw) if isinstance(raw, str) else PSBT.parse(raw)
    except (PSBTError, Exception) as exc:
        raise ReviewError("The PSBT could not be read.") from exc
    if psbt.version not in (None, 0, 2):
        raise ReviewError("Only PSBT version 0 and version 2 are supported.")
    transaction = psbt.tx
    if transaction is None or transaction.version not in (1, 2):
        raise ReviewError("Only Bitcoin transaction version 1 and version 2 are supported.")
    wallet = session._wallet(wallet_index)
    inputs = [_read_input(session, wallet, psbt, index) for index in range(len(psbt.inputs))]
    accounts = _one_account_tuple(wallet, inputs)
    switched = accounts != {fp: wallet.accounts[fp] for fp in wallet.fingerprints}
    outputs = [_read_output(session, wallet, psbt, index, accounts) for index in range(len(psbt.outputs))]
    fee = sum(item["amount"] for item in inputs) - sum(item["amount"] for item in outputs)
    if fee < 0:
        raise ReviewError("The outputs are larger than the inputs.")
    if any(item["op_return"] and item["amount"] != 0 for item in outputs):
        raise ReviewError("An OP_RETURN output has a non-zero amount.")
    vsize = _estimate_vsize(transaction, inputs, outputs, wallet)
    external = [item for item in outputs if not item["change"]]
    warnings = _warnings(transaction, inputs, outputs, external)
    if vsize and fee / vsize > 200:
        warnings.append("The fee rate is above 200 sat/vB.")
    return {
        "psbt": psbt,
        "psbt_version": 0 if psbt.version in (None, 0) else 2,
        "tx_version": transaction.version,
        "txid": transaction.txid().hex(),
        "locktime": transaction.locktime,
        "inputs": inputs,
        "outputs": outputs,
        "external": external,
        "fee": fee,
        "vsize": vsize,
        "fee_rate": f"{fee / vsize:.2f}" if vsize else "0.00",
        "external_amount": sum(item["amount"] for item in external),
        "deducted": sum(item["amount"] for item in external) + fee,
        "warnings": warnings,
        "switch_accounts": accounts if switched else None,
        "signers": _signers(session, wallet, inputs),
    }


def _read_input(session, wallet, psbt, index: int) -> dict:
    scope = psbt.inputs[index]
    vin = psbt.tx.vin[index]
    if scope.witness_utxo is None:
        raise ReviewError("An input is missing its previous output.")
    sighash = scope.sighash_type
    _check_sighash(sighash, wallet.role == "singlesig_taproot")
    sequence = scope.sequence if scope.sequence is not None else vin.sequence
    _check_sequence_range(sequence)
    derivations = _derivations(scope)
    if not derivations:
        raise ReviewError("An input is missing its derivation path.")
    located = _locate(session, wallet, derivations, scope.witness_utxo.script_pubkey)
    return {
        "amount": scope.witness_utxo.value,
        "sequence": sequence,
        "sighash": sighash,
        "script": scope.witness_utxo.script_pubkey,
        "prev": f"{vin.txid.hex()}:{vin.vout}",
        **located,
    }


def _read_output(session, wallet, psbt, index: int, accounts: dict) -> dict:
    scope = psbt.outputs[index]
    vout = psbt.tx.vout[index]
    script = scope.script_pubkey or vout.script_pubkey
    amount = scope.value if scope.value is not None else vout.value
    op_return = bytes(script.data).startswith(b"\x6a") if script is not None else False
    payload = _op_return_payload(script) if op_return else None
    derivations = _derivations(scope)
    change = None
    if derivations and not op_return:
        try:
            located = _locate(session, wallet, derivations, script, accounts=accounts, required=False)
        except ReviewError:
            located = None
        if located and located["accounts"] == accounts:
            change = located
    address = None
    if script is not None and not op_return:
        try:
            address = script.address(network=_net(session.network))
        except Exception:
            address = script.data.hex()
    return {
        "amount": amount,
        "script": script,
        "address": address,
        "op_return": op_return,
        "payload": payload,
        "change": change is not None,
        "branch": None if change is None else change["branch"],
        "index": None if change is None else change["index"],
        "accounts": None if change is None else change["accounts"],
    }


def _derivations(scope) -> list[tuple[bytes, list[int]]]:
    found = []
    for derivation in scope.bip32_derivations.values():
        found.append((derivation.fingerprint, list(derivation.derivation)))
    for item in getattr(scope, "taproot_bip32_derivations", {}).values():
        derivation = item[1] if isinstance(item, tuple) else item
        found.append((derivation.fingerprint, list(derivation.derivation)))
    return found


def _locate(session, wallet, derivations, script, accounts=None, required=True):
    by_fingerprint = {}
    for fingerprint, path in derivations:
        if fingerprint in wallet.fingerprints:
            by_fingerprint.setdefault(fingerprint, []).append(path)
    if len(by_fingerprint) != len(wallet.fingerprints):
        if required:
            raise ReviewError("An input does not belong to the selected wallet.")
        return None
    branches = set()
    indexes = set()
    found_accounts = {}
    for fingerprint in wallet.fingerprints:
        paths = by_fingerprint[fingerprint]
        if len(paths) != 1:
            raise ReviewError("An input has more than one derivation for the same key.")
        path = paths[0]
        expected_prefix = _account_path(session.network, wallet.role, 0)[:-1]
        # The account is the hardened step at the account position, not a fixed 0.
        parsed = _split_wallet_path(path, wallet.role, session.network)
        branches.add(parsed["branch"])
        indexes.add(parsed["index"])
        found_accounts[fingerprint] = parsed["account"]
        del expected_prefix
    if len(branches) != 1 or len(indexes) != 1:
        raise ReviewError(
            "A multisig input mixes receive and change, or mixes address indexes."
        )
    branch = branches.pop()
    index = indexes.pop()
    if accounts is not None and found_accounts != accounts:
        return None
    trial = dict(wallet.accounts)
    trial.update(found_accounts)
    derived = _script_at(session, wallet, trial, branch, index)
    if derived != script:
        raise ReviewError("An input's script does not match the derived wallet script.")
    return {"accounts": found_accounts, "branch": branch, "index": index}


def _split_wallet_path(path: list[int], role: str, network: str) -> dict:
    if role == "multisig_native":
        if len(path) != 6:
            raise ReviewError("An input derivation does not include the address index.")
        account_path, branch, index = path[:4], path[4], path[5]
    else:
        if len(path) != 5:
            raise ReviewError("An input derivation does not include the address index.")
        account_path, branch, index = path[:3], path[3], path[4]
    try:
        parsed_role, account = classify_path(account_path, network)
    except Exception as exc:
        raise ReviewError("An input uses a derivation path this wallet does not use.") from exc
    if parsed_role != role or branch > 1 or index & HARDENED or branch & HARDENED:
        raise ReviewError("An input uses a derivation path this wallet does not use.")
    return {"account": account, "branch": branch, "index": index}


def _one_account_tuple(wallet, inputs: list[dict]) -> dict:
    tuples = [tuple(sorted(item["accounts"].items())) for item in inputs]
    if len(set(tuples)) != 1:
        raise ReviewError("The inputs spend from more than one account combination.")
    return dict(tuples[0])


def _script_at(session, wallet, accounts, branch: int, index: int):
    saved = dict(wallet.accounts)
    wallet.accounts.update(accounts)
    try:
        descriptor = _descriptor(wallet, session)
    finally:
        wallet.accounts = saved
    return Descriptor.from_string(descriptor).derive(index, branch_index=branch).script_pubkey()


def _check_sighash(sighash, taproot: bool):
    if sighash is None:
        return
    if sighash & SIGHASH.ANYONECANPAY:
        raise ReviewError("A signature hash lets a coordinator change which inputs are signed.")
    allowed = (SIGHASH.DEFAULT, SIGHASH.ALL) if taproot else (SIGHASH.ALL,)
    if sighash not in allowed:
        raise ReviewError("Only the default signature hash, SIGHASH_ALL, is accepted.")


def _check_sequence_range(sequence: int):
    if SEQUENCE_FINAL - 2 <= sequence <= SEQUENCE_FINAL:
        return
    if sequence <= 0xFFFF:
        return
    if 0x00400000 <= sequence <= 0x0040FFFF:
        return
    raise ReviewError("An input has a sequence number this signer does not accept.")


def _warnings(transaction, inputs, outputs, external) -> list[str]:
    warnings = []
    if transaction.version != 2:
        warnings.append("A legacy transaction version is being used.")
    if any(item["sequence"] in (0xFFFFFFFE, 0xFFFFFFFF) for item in inputs):
        if all(item["sequence"] >= RBF_SIGNAL_BELOW for item in inputs):
            warnings.append(
                "An input uses an uncommon sequence. The transaction does not signal "
                "replace-by-fee, but the network may still replace it."
            )
        else:
            warnings.append(
                "An input uses an uncommon sequence. The transaction still signals replace-by-fee."
            )
    if all(item["sequence"] == SEQUENCE_FINAL for item in inputs):
        warnings.append("Every sequence is final, so the locktime is ignored.")
    elif transaction.locktime >= LOCKTIME_THRESHOLD:
        warnings.append("The locktime is a timestamp. Median time is not a wall clock.")
    if any(0 < item["sequence"] <= 0xFFFF or 0x00400000 <= item["sequence"] <= 0x0040FFFF for item in inputs):
        warnings.append("An input has a relative locktime. See BIP68 for the exact rule.")
    if sum(1 for item in outputs if item["change"]) > 1:
        warnings.append("There is more than one change output.")
    if len(external) > 1:
        warnings.append("There is more than one external output.")
    if any(item["change"] and item["branch"] == 0 for item in outputs):
        warnings.append("A change output uses a receive address.")
    if any(item["op_return"] for item in outputs):
        warnings.append("The transaction contains an OP_RETURN output.")
    fee = sum(item["amount"] for item in inputs) - sum(item["amount"] for item in outputs)
    total_in = sum(item["amount"] for item in inputs)
    if total_in and fee * 100 > total_in * 5:
        warnings.append("The fee is more than 5% of the amount being spent.")
    return warnings


def _signers(session, wallet, inputs) -> list[dict]:
    rows = []
    for fingerprint in wallet.fingerprints:
        seed = session._seed_for(fingerprint)
        rows.append(
            {
                "fingerprint": fingerprint,
                "nickname": session.fingerprints[fingerprint].nickname,
                "can_sign": seed is not None,
            }
        )
    return rows


def _op_return_payload(script: Script) -> bytes:
    data = bytes(script.data)
    if not data.startswith(b"\x6a"):
        return b""
    return data[2:] if len(data) > 2 else b""


def _estimate_vsize(transaction: Transaction, inputs, outputs, wallet) -> int:
    clone = Transaction(
        version=transaction.version,
        locktime=transaction.locktime,
        vin=[
            TransactionInput(item.txid, item.vout, sequence=item.sequence)
            for item in transaction.vin
        ],
        vout=list(transaction.vout),
    )
    for vin, item in zip(clone.vin, inputs):
        if wallet.role == "singlesig_taproot":
            vin.witness = Witness([b"\x00" * 64])
        elif wallet.role == "singlesig_native":
            vin.witness = Witness([b"\x00" * 72, b"\x00" * 33])
        else:
            vin.witness = Witness([b"\x00" * 72] * wallet.threshold + [b"\x00" * 35])
        del item
    total = len(clone.serialize())
    for vin in clone.vin:
        vin.witness = Witness([])
    base = len(clone.serialize())
    weight = base * 3 + total
    return max(1, (weight + 3) // 4)


def _net(network: str):
    if network == "main":
        return NETWORKS["main"]
    if network == "regtest":
        return NETWORKS["regtest"]
    return NETWORKS["test"]


def apply_accounts(session, wallet_index: int, accounts: dict):
    wallet = session._wallet(wallet_index)
    for fingerprint, account in accounts.items():
        session.set_account(wallet_index, fingerprint, account)


def sign_with(session, wallet_index: int, psbt: PSBT, fingerprint: bytes):
    seed = session._seed_for(fingerprint)
    if seed is None:
        raise SessionError("That fingerprint does not have a seed.")
    root = _seed_root(seed)
    signed = psbt.sign_with(root)
    if not signed:
        raise ReviewError("This seed did not add a signature.")
    return psbt

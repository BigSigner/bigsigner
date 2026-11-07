"""Stop before signing when a PSBT asks for something this signer will not do.

The checks run in the order a person listed them. Each refusal says the case is
not supported by this hardware wallet, and names the wallets or accounts when
that is what distinguishes it.
"""

from embit.ec import PublicKey, SchnorrSig, Signature
from embit.psbt import PSBT, PSBTError
from embit.script import Script
from embit.transaction import SIGHASH

from .paths import HARDENED, SINGLESIG_NATIVE, SINGLESIG_TAPROOT, coin_type, format_path
from .psbt_load import UNREADABLE, psbt_bytes
from .psbt_review import ReviewError, _tx_weight
from .session import SessionError, _public_for

NOT_SUPPORTED = "not supported by this hardware wallet"


def require_psbt_version(psbt) -> None:
    """Version 0 may be omitted. Version 2 is BIP 370. Nothing else is signed."""
    if psbt.version not in (None, 0, 2):
        raise ReviewError(f"A PSBT version other than 0 or 2 is {NOT_SUPPORTED}.")


def refuse_v0_required_locktime(psbt) -> None:
    """BIP 370 puts these fields on version 2 only. A version 0 PSBT that carries one is refused."""
    if psbt.version == 2:
        return
    for scope in psbt.inputs:
        for key in scope.unknown:
            if key[:1] in (b"\x11", b"\x12"):
                raise ReviewError(
                    f"A per-input required locktime on a version 0 PSBT is {NOT_SUPPORTED}."
                )


def refuse_modifiable(psbt) -> None:
    """PSBT_GLOBAL_TX_MODIFIABLE means someone may still add inputs or outputs."""
    if any(key[:1] == b"\x06" for key in psbt.unknown):
        raise ReviewError(f"A modifiable transaction is {NOT_SUPPORTED}.")


SEQUENCE_FINAL = 0xFFFFFFFF
# Bitcoin Core 31's default -datacarriersize. The scripts of every standard
# OP_RETURN output are added together. The amount is not limited: an
# unspendable output has a dust threshold of zero.
DATACARRIER_MAX_BYTES = 100_000
# Bitcoin Core's maximum standard transaction weight. 400000 WU is 100000 vB.
MAX_STANDARD_TX_WEIGHT = 400_000
# Hard caps so Transaction Signing can keep a short window of pre-rendered
# tiles in RAM. A larger PSBT is refused before the per-input checks run.
MAX_PSBT_INPUTS = 100
MAX_PSBT_OUTPUTS = 100
# Bitcoin Core 31 dust thresholds at 3 sat/vB. An output below its threshold
# is not relayed. The limit follows the receiving script, not the sender.
# Legacy P2PKH is 546. P2SH, including wrapped Segwit, is 540.
LEGACY_DUST_SATS = 546
P2SH_DUST_SATS = 540
NATIVE_DUST_SATS = 294
WITNESS_SCRIPT_DUST_SATS = 330


def check_loaded_psbt(session, wallet_index: int, text: str, progress=None) -> PSBT:
    """The parsed PSBT, after every refusal below has been passed.

    ``progress`` is ``progress(message, done, total)``. ``done`` runs from 0 to
    ``total``. The caller may treat ``total`` as the check's share of a longer bar.
    """
    steps = iter_check_loaded_psbt(session, wallet_index, text)
    try:
        while True:
            message, done, total = next(steps)
            _progress(progress, message, done, total)
    except StopIteration as stop:
        return stop.value


def iter_check_loaded_psbt(session, wallet_index: int, text: str):
    """Yield ``(message, done, total)`` while checking; return the parsed PSBT.

    The browser emulator advances one paint's worth of work per frame. The panel
    drains the iterator inside one call and pushes frames with ``flush_display``.
    """
    yield ("Reading transaction\u2026", 0, 1)
    if isinstance(text, PSBT):
        psbt = text
    else:
        try:
            raw = psbt_bytes(text) if isinstance(text, str) else text
            psbt = PSBT.parse(raw)
        except (ReviewError, SessionError):
            raise
        except (PSBTError, Exception) as exc:
            raise ReviewError(UNREADABLE) from exc
    transaction = psbt.tx
    input_count = 0 if transaction is None else len(transaction.vin)
    output_count = 0 if transaction is None else len(transaction.vout)
    # Early checks, one pass over inputs for paths, one for matches, one for
    # signatures, and one pass over outputs.
    total = 1 + input_count + input_count + output_count + 1
    done = 0
    yield ("Checking transaction\u2026", done, total)
    require_psbt_version(psbt)
    refuse_v0_required_locktime(psbt)
    refuse_modifiable(psbt)
    if transaction is None or transaction.version not in (2, 3):
        raise ReviewError(f"A transaction version other than 2 or 3 is {NOT_SUPPORTED}.")
    if not transaction.vin:
        raise ReviewError(f"A transaction with no inputs is {NOT_SUPPORTED}.")
    if not transaction.vout:
        raise ReviewError(f"A transaction with no outputs is {NOT_SUPPORTED}.")
    if input_count > MAX_PSBT_INPUTS:
        raise ReviewError(
            f"A transaction with more than {MAX_PSBT_INPUTS} inputs is {NOT_SUPPORTED}."
        )
    if output_count > MAX_PSBT_OUTPUTS:
        raise ReviewError(
            f"A transaction with more than {MAX_PSBT_OUTPUTS} outputs is {NOT_SUPPORTED}."
        )
    _check_op_returns(psbt)
    _check_output_scripts(psbt)
    seen = set()
    for vin in transaction.vin:
        key = (bytes(vin.txid), vin.vout)
        if key in seen:
            raise ReviewError(f"Two inputs that spend the same output are {NOT_SUPPORTED}.")
        seen.add(key)
    amounts = [_input_amount(psbt, index) for index in range(len(transaction.vin))]
    if any(amount is None for amount in amounts):
        raise ReviewError(f"An input without an amount is {NOT_SUPPORTED}.")
    output_total = sum(int(vout.value) for vout in transaction.vout)
    if output_total > sum(amounts):
        raise ReviewError(f"Outputs that add up to more than the inputs are {NOT_SUPPORTED}.")
    wallet = session._wallet(wallet_index)
    if _tx_weight(transaction, wallet) > MAX_STANDARD_TX_WEIGHT:
        raise ReviewError(
            f"A transaction over {MAX_STANDARD_TX_WEIGHT} weight units (100000 vB) is {NOT_SUPPORTED}."
        )
    done = 1
    yield ("Checking transaction\u2026", done, total)
    parsed = []
    for index in range(input_count):
        yield (
            f"Parsing input {index + 1} of {input_count}",
            done + index,
            total,
        )
        parsed.append(_input_paths(session, wallet, psbt.inputs[index]))
    done += input_count
    _same_prefix(parsed)
    _known_wallet(session, wallet, parsed)
    _selected_accounts(wallet, parsed)
    for index, item in enumerate(parsed):
        yield (
            f"Checking input {index + 1} of {input_count}",
            done + index,
            total,
        )
        _matches_psbt(session, wallet, psbt.inputs[index], item)
        _scripts(wallet, psbt.inputs[index], session, item)
        _sighash(wallet, psbt.inputs[index])
        _sequence(psbt.inputs[index], transaction.vin[index])
    done += input_count
    for index in range(output_count):
        yield (
            f"Checking output {index + 1} of {output_count}",
            done + index,
            total,
        )
        _check_output(session, wallet, psbt, index)
    done += output_count
    yield ("Checking signatures\u2026", done, total)
    verify_existing_signatures(psbt)
    yield ("Checking signatures\u2026", total, total)
    return psbt


def _progress(progress, message: str, done: int, total: int) -> None:
    if progress is not None:
        progress(message, done, total)


def psbt_yaml(psbt: PSBT) -> str:
    """A readable YAML view of the transaction this PSBT contains."""
    inputs = []
    for index, scope in enumerate(psbt.inputs):
        vin = psbt.tx.vin[index]
        inputs.append(
            {
                "previous_output": f"{vin.txid.hex()}:{vin.vout}",
                "amount_sats": _input_amount(psbt, index),
                "sequence": _sequence_value(scope, vin),
                "sighash": _sighash_name(scope.sighash_type),
                "derivation": _yaml_paths(scope),
            }
        )
    outputs = []
    for index, scope in enumerate(psbt.outputs):
        vout = psbt.tx.vout[index]
        script = scope.script_pubkey or vout.script_pubkey
        address = ""
        if script is not None:
            try:
                address = script.address()
            except Exception:
                address = bytes(script.data).hex()
        outputs.append(
            {
                "amount_sats": int(scope.value if scope.value is not None else vout.value),
                "address": address,
                "derivation": _yaml_paths(scope),
            }
        )
    body = {
        "transaction_version": psbt.tx.version,
        "locktime": psbt.tx.locktime,
        "inputs": inputs,
        "outputs": outputs,
    }
    return _yaml(body)


def _input_amount(psbt: PSBT, index: int):
    scope = psbt.inputs[index]
    if scope.witness_utxo is not None:
        return int(scope.witness_utxo.value)
    if scope.non_witness_utxo is not None:
        try:
            return int(scope.non_witness_utxo.vout[psbt.tx.vin[index].vout].value)
        except Exception:
            return None
    return None


def _input_paths(session, wallet, scope) -> dict:
    derivations = _derivations(scope)
    if not derivations:
        raise ReviewError(
            f"An input without a master fingerprint and derivation path is {NOT_SUPPORTED}."
        )
    rows = []
    for fingerprint, path in derivations:
        if fingerprint not in wallet.fingerprints and not _wallet_for_fingerprint(session, fingerprint):
            continue
        rows.append(_parse_path(path))
        rows[-1]["fingerprint"] = fingerprint
        rows[-1]["path"] = path
    ours = [row for row in rows if row["fingerprint"] in wallet.fingerprints]
    if not ours:
        raise ReviewError(_other_wallet_message(session, wallet, rows) or _UNRECOGNIZED)
    if any(row["out_of_range"] and row["role"] == wallet.role for row in ours):
        raise ReviewError(
            f"An input derivation path that this wallet would not derive is {NOT_SUPPORTED}."
        )
    return {"rows": ours, "prefix": ours[0]["prefix"]}


_UNRECOGNIZED = f"An unrecognized derivation path is {NOT_SUPPORTED}."


def _parse_path(path: list[int]) -> dict:
    purpose = path[0] if path else None
    role = {84 | HARDENED: SINGLESIG_NATIVE, 86 | HARDENED: SINGLESIG_TAPROOT, 48 | HARDENED: "multisig_native"}.get(purpose)
    out = False
    prefix = list(path[:-2]) if len(path) >= 2 else list(path)
    branch = index = None
    if role == "multisig_native":
        if len(path) == 6 and path[3] & HARDENED:
            branch, index = path[4], path[5]
            prefix = path[:4]
        else:
            out = True
            prefix = path[:4]
    elif role is not None:
        if len(path) == 5:
            branch, index = path[3], path[4]
            prefix = path[:3]
        else:
            out = True
            prefix = path[:3]
    if branch is not None and (branch not in (0, 1) or branch & HARDENED or index & HARDENED):
        out = True
    return {
        "role": role,
        "prefix": tuple(prefix),
        "branch": branch,
        "index": index,
        "account": None if len(prefix) < 3 or not (prefix[2] & HARDENED) else prefix[2] & ~HARDENED,
        "coin": None if len(prefix) < 2 else prefix[1],
        "out_of_range": out,
    }


def _same_prefix(parsed: list[dict]):
    prefixes = {tuple(row["prefix"] for row in item["rows"]) for item in parsed}
    if len(prefixes) != 1:
        raise ReviewError(
            f"A transaction that spends from more than one account or wallet is {NOT_SUPPORTED}."
        )


def _known_wallet(session, wallet, parsed: list[dict]):
    item = parsed[0]
    network_coin = coin_type(session.network) | HARDENED
    for row in item["rows"]:
        if row["role"] == "multisig_native" and len(row["prefix"]) >= 4 and row["prefix"][3] != (2 | HARDENED):
            raise ReviewError(
                f"An input derivation path that this wallet would not derive is {NOT_SUPPORTED}."
            )
        if row["coin"] != network_coin or row["role"] != wallet.role:
            other = _matching_wallet(session, item, skip=wallet)
            if other is not None:
                current = session.wallet_short_name_of(wallet)
                name = session.wallet_short_name_of(other)
                raise ReviewError(
                    f"This transaction does not belong to wallet {current}. It belongs to wallet {name}."
                )
            raise ReviewError(_UNRECOGNIZED)
        if row["fingerprint"] not in wallet.fingerprints:
            raise ReviewError(_UNRECOGNIZED)
    fingerprints = {row["fingerprint"] for row in item["rows"]}
    if fingerprints != set(wallet.fingerprints):
        other = _matching_wallet(session, item, skip=wallet)
        if other is not None:
            current = session.wallet_short_name_of(wallet)
            name = session.wallet_short_name_of(other)
            raise ReviewError(
                f"This transaction does not belong to wallet {current}. It belongs to wallet {name}."
            )
        raise ReviewError(_UNRECOGNIZED)


def _selected_accounts(wallet, parsed: list[dict]):
    found = {row["fingerprint"]: row["account"] for row in parsed[0]["rows"]}
    selected = {fingerprint: wallet.accounts[fingerprint] for fingerprint in wallet.fingerprints}
    if found == selected:
        return
    if len(wallet.fingerprints) == 1:
        fingerprint = wallet.fingerprints[0]
        raise ReviewError(
            f"This transaction spends from account {found.get(fingerprint)}, "
            f"but the selected account is {selected[fingerprint]}. "
            "Go back to the wallet screen and change the account index."
        )
    found_text = ", ".join(str(found.get(fingerprint)) for fingerprint in wallet.fingerprints)
    selected_text = ", ".join(str(selected[fingerprint]) for fingerprint in wallet.fingerprints)
    raise ReviewError(
        f"This transaction spends from accounts {found_text}, "
        f"but the selected accounts are {selected_text}. "
        "Go back to the wallet screen and change the account indexes."
    )


def _matches_psbt(session, wallet, scope, item: dict):
    derived_script = _script_at(session, wallet, _accounts(item), item["rows"][0]["branch"], item["rows"][0]["index"])
    utxo = scope.witness_utxo
    script = None if utxo is None else utxo.script_pubkey
    if script is not None and script != derived_script:
        raise ReviewError(
            f"An input whose derived address does not match the PSBT is {NOT_SUPPORTED}."
        )
    for pubkey, derivation in _derivation_items(scope):
        fingerprint = derivation.fingerprint
        path = list(derivation.derivation)
        row = next((candidate for candidate in item["rows"] if candidate["fingerprint"] == fingerprint and candidate["path"] == path), None)
        if row is None:
            continue
        expected = _child_key(session, wallet, fingerprint, row)
        if not _same_key(pubkey, expected, wallet.role == SINGLESIG_TAPROOT):
            raise ReviewError(
                f"An input whose public key does not match its derivation path is {NOT_SUPPORTED}."
            )


def _scripts(wallet, scope, session, item: dict):
    del session, item
    if scope.redeem_script is not None or (
        wallet.role != "multisig_native" and scope.witness_script is not None
    ):
        raise ReviewError(f"An unexpected redeem script or witness script is {NOT_SUPPORTED}.")
    if wallet.role == "multisig_native" and scope.witness_script is not None:
        # The witness program is the SHA256 of the witness script. A different
        # script would already have failed the address check above.
        return


def verify_existing_signatures(psbt: PSBT) -> None:
    """Reject a PSBT when a signature already on an input does not match.

    A multisig input can carry one partial signature per cosigner. Each one is
    checked. Taproot key signatures and a finalized witness are checked too.
    """
    for index, scope in enumerate(psbt.inputs):
        _verify_partial_signatures(psbt, index, scope)
        _verify_taproot_script_signatures(psbt, index, scope)
        _verify_taproot_key_field(psbt, index, scope)
        _verify_final_witness(psbt, index, scope)


def _signature_mismatch(index: int):
    raise ReviewError(f"A signature on input {index} does not match.")


def _verify_partial_signatures(psbt: PSBT, index: int, scope) -> None:
    if not scope.partial_sigs:
        return
    try:
        message = psbt.sighash(index, sighash=SIGHASH.ALL)
    except Exception as exc:
        raise ReviewError(f"A signature on input {index} does not match.") from exc
    for pubkey, raw in scope.partial_sigs.items():
        if not _ecdsa_matches(pubkey, raw, message):
            _signature_mismatch(index)


def _ecdsa_matches(pubkey, raw: bytes, message: bytes) -> bool:
    if len(raw) < 9 or raw[0] != 0x30 or raw[-1] != SIGHASH.ALL:
        return False
    try:
        signature = Signature.parse(raw[:-1])
        return bool(pubkey.verify(signature, message))
    except Exception:
        return False


def _verify_taproot_key_field(psbt: PSBT, index: int, scope) -> None:
    raw = scope.unknown.get(b"\x13") if scope.unknown else None
    if not raw:
        return
    _verify_taproot_key_signature(psbt, index, scope, raw)


def _verify_taproot_script_signatures(psbt: PSBT, index: int, scope) -> None:
    from embit.hashes import tagged_hash

    for (pubkey, leaf_hash), raw in getattr(scope, "taproot_sigs", {}).items():
        body = _schnorr_body(raw)
        if body is None:
            _signature_mismatch(index)
        matched = False
        for script_bytes in getattr(scope, "taproot_scripts", {}).values():
            if not script_bytes:
                continue
            leaf_version = script_bytes[-1]
            script = Script(script_bytes[:-1])
            leaf = tagged_hash("TapLeaf", bytes([leaf_version]) + script.serialize())
            if leaf != leaf_hash:
                continue
            matched = True
            try:
                message = psbt.sighash(
                    index,
                    sighash=SIGHASH.DEFAULT,
                    ext_flag=1,
                    script=script,
                    leaf_version=leaf_version,
                )
            except Exception as exc:
                raise ReviewError(f"A signature on input {index} does not match.") from exc
            try:
                matches = pubkey.schnorr_verify(SchnorrSig(body), message)
            except Exception as exc:
                raise ReviewError(f"A signature on input {index} does not match.") from exc
            if not matches:
                _signature_mismatch(index)
        if not matched:
            _signature_mismatch(index)


def _verify_final_witness(psbt: PSBT, index: int, scope) -> None:
    witness = scope.final_scriptwitness
    if witness is None:
        return
    items = [item for item in list(getattr(witness, "items", []) or [])]
    if not items:
        return
    if _is_taproot_input(scope) and len(items) == 1 and len(items[0]) in (64, 65):
        _verify_taproot_key_signature(psbt, index, scope, items[0])
        return
    if len(items) == 2 and items[0][:1] == b"\x30" and _is_pubkey(items[1]):
        try:
            message = psbt.sighash(index, sighash=SIGHASH.ALL)
            pubkey = PublicKey.parse(items[1])
        except Exception as exc:
            raise ReviewError(f"A signature on input {index} does not match.") from exc
        if not _ecdsa_matches(pubkey, items[0], message):
            _signature_mismatch(index)
        return
    if len(items) >= 2:
        pubs = _pubkeys_in_script(items[-1])
        signatures = [item for item in items[:-1] if item]
        if signatures and not pubs:
            _signature_mismatch(index)
        if not pubs:
            return
        try:
            message = psbt.sighash(index, sighash=SIGHASH.ALL)
        except Exception as exc:
            raise ReviewError(f"A signature on input {index} does not match.") from exc
        for raw in signatures:
            if not any(_ecdsa_matches(pubkey, raw, message) for pubkey in pubs):
                _signature_mismatch(index)


def _verify_taproot_key_signature(psbt: PSBT, index: int, scope, raw: bytes) -> None:
    body = _schnorr_body(raw)
    script = _taproot_output_key(scope)
    if body is None or script is None:
        _signature_mismatch(index)
    try:
        message = psbt.sighash(index, sighash=SIGHASH.DEFAULT)
        pubkey = PublicKey.from_xonly(script)
    except Exception as exc:
        raise ReviewError(f"A signature on input {index} does not match.") from exc
    try:
        matches = pubkey.schnorr_verify(SchnorrSig(body), message)
    except Exception as exc:
        raise ReviewError(f"A signature on input {index} does not match.") from exc
    if not matches:
        _signature_mismatch(index)


def _schnorr_body(raw: bytes) -> bytes | None:
    if len(raw) == 64:
        return raw
    if len(raw) == 65 and raw[-1] == SIGHASH.DEFAULT:
        return raw[:64]
    return None


def _taproot_output_key(scope) -> bytes | None:
    utxo = scope.witness_utxo or getattr(scope, "utxo", None)
    if utxo is None or utxo.script_pubkey is None:
        return None
    data = bytes(utxo.script_pubkey.data)
    if len(data) == 34 and data[:2] == b"\x51\x20":
        return data[2:]
    return None


def _is_taproot_input(scope) -> bool:
    return _taproot_output_key(scope) is not None


def _is_pubkey(raw: bytes) -> bool:
    return len(raw) in (33, 65) and raw[:1] in (b"\x02", b"\x03", b"\x04")


def _pubkeys_in_script(script: bytes) -> list:
    pubs = []
    index = 0
    while index < len(script):
        opcode = script[index]
        index += 1
        if opcode in (33, 65) and index + opcode <= len(script) and _is_pubkey(script[index : index + opcode]):
            try:
                pubs.append(PublicKey.parse(script[index : index + opcode]))
            except Exception:
                return []
            index += opcode
            continue
        if opcode <= 0x4B:
            index += opcode
        elif opcode == 0x4C and index < len(script):
            index += 1 + script[index]
        elif opcode == 0x4D and index + 2 <= len(script):
            index += 2 + int.from_bytes(script[index : index + 2], "little")
        elif opcode == 0x4E and index + 4 <= len(script):
            index += 4 + int.from_bytes(script[index : index + 4], "little")
    return pubs


def _sighash(wallet, scope):
    sighash = scope.sighash_type
    if sighash is None:
        return
    if wallet.role == SINGLESIG_TAPROOT:
        if sighash != SIGHASH.DEFAULT:
            raise ReviewError(f"A signature hash other than SIGHASH_DEFAULT is {NOT_SUPPORTED}.")
        return
    if sighash != SIGHASH.ALL:
        raise ReviewError(f"A signature hash other than SIGHASH_ALL is {NOT_SUPPORTED}.")


def _sequence(scope, vin):
    sequence = _sequence_value(scope, vin)
    if sequence == SEQUENCE_FINAL:
        raise ReviewError(f"An input with sequence 0xFFFFFFFF is {NOT_SUPPORTED}.")
    blocks = sequence <= 0xFFFF
    time_lock = 0x00400000 <= sequence <= 0x0040FFFF
    final = sequence in (0xFFFFFFFD, 0xFFFFFFFE)
    if not (blocks or time_lock or final):
        raise ReviewError(f"An input sequence outside the supported ranges is {NOT_SUPPORTED}.")


def _check_op_returns(psbt: PSBT) -> None:
    """Refuse an OP_RETURN output Bitcoin Core 31 would not relay.

    A standard data output is OP_RETURN followed only by pushes. Any number of
    them is allowed. Their scripts together must be at most 100000 bytes.
    """
    total = 0
    for index, scope in enumerate(psbt.outputs):
        vout = psbt.tx.vout[index]
        script = scope.script_pubkey or vout.script_pubkey
        if script is None:
            continue
        raw = bytes(script.data)
        if not raw.startswith(b"\x6a"):
            continue
        if not _push_only(raw[1:]):
            raise ReviewError(
                f"An OP_RETURN output that is not followed only by data pushes is {NOT_SUPPORTED}."
            )
        total += len(raw)
        if total > DATACARRIER_MAX_BYTES:
            raise ReviewError(
                f"OP_RETURN outputs larger than {DATACARRIER_MAX_BYTES} bytes together are {NOT_SUPPORTED}."
            )


def _check_output_scripts(psbt: PSBT) -> None:
    """Refuse an output this signer will not pay.

    A spendable output must be P2PKH, P2SH, P2WPKH, P2WSH, or P2TR, and at
    least the Bitcoin Core dust threshold. A P2WSH output is any 32-byte
    witness program, not necessarily a multisig. An OP_RETURN output is the
    other accepted kind, at any amount.
    Inputs stay limited to the wallet types this signer can sign. Legacy
    outputs do not have that limit: malleability is a problem for legacy inputs.
    """
    for index, scope in enumerate(psbt.outputs):
        vout = psbt.tx.vout[index]
        script = scope.script_pubkey or vout.script_pubkey
        raw = b"" if script is None else bytes(script.data)
        kind = _output_kind(raw)
        amount = scope.value if scope.value is not None else vout.value
        if kind == "op_return":
            continue
        if kind == "p2pkh" and int(amount) < LEGACY_DUST_SATS:
            raise ReviewError(
                f"A legacy output below {LEGACY_DUST_SATS} sats is {NOT_SUPPORTED}."
            )
        if kind == "p2sh" and int(amount) < P2SH_DUST_SATS:
            raise ReviewError(
                f"A P2SH output below {P2SH_DUST_SATS} sats is {NOT_SUPPORTED}."
            )
        if kind == "native" and int(amount) < NATIVE_DUST_SATS:
            raise ReviewError(
                f"A Native-Segwit SingleSig output below {NATIVE_DUST_SATS} sats is {NOT_SUPPORTED}."
            )
        if kind == "taproot" and int(amount) < WITNESS_SCRIPT_DUST_SATS:
            raise ReviewError(
                f"A Taproot output below {WITNESS_SCRIPT_DUST_SATS} sats is {NOT_SUPPORTED}."
            )
        if kind == "p2wsh" and int(amount) < WITNESS_SCRIPT_DUST_SATS:
            raise ReviewError(
                f"A P2WSH output below {WITNESS_SCRIPT_DUST_SATS} sats is {NOT_SUPPORTED}."
            )
        if kind is None:
            raise ReviewError(
                "An output script other than OP_RETURN, P2PKH, P2SH, "
                "P2WPKH, P2WSH, "
                f"or P2TR is {NOT_SUPPORTED}."
            )


def _output_kind(raw: bytes) -> str | None:
    if raw.startswith(b"\x6a") and _push_only(raw[1:]):
        return "op_return"
    if len(raw) == 25 and raw[:3] == b"\x76\xa9\x14" and raw[-2:] == b"\x88\xac":
        return "p2pkh"
    if len(raw) == 23 and raw[:2] == b"\xa9\x14" and raw[-1:] == b"\x87":
        return "p2sh"
    if len(raw) == 22 and raw[:2] == b"\x00\x14":
        return "native"
    if len(raw) == 34 and raw[:2] == b"\x51\x20":
        return "taproot"
    if len(raw) == 34 and raw[:2] == b"\x00\x20":
        return "p2wsh"
    return None


def _push_only(data: bytes) -> bool:
    """True when every opcode is a push, using Bitcoin Core's push range."""
    index = 0
    while index < len(data):
        opcode = data[index]
        index += 1
        if opcode > 0x60:
            return False
        if opcode <= 0x4B:
            index += opcode
        elif opcode == 0x4C:
            if index >= len(data):
                return False
            index += 1 + data[index]
        elif opcode == 0x4D:
            if index + 2 > len(data):
                return False
            index += 2 + int.from_bytes(data[index : index + 2], "little")
        elif opcode == 0x4E:
            if index + 4 > len(data):
                return False
            index += 4 + int.from_bytes(data[index : index + 4], "little")
        if index > len(data):
            return False
    return True


def multisig_signature_note(wallet, psbt: PSBT) -> str:
    """How many more signatures a multisig still needs, from the least-signed input."""
    if not wallet.multisig:
        return ""
    counts = [input_signature_count(scope) for scope in psbt.inputs]
    least = min(counts) if counts else 0
    required = int(wallet.threshold)
    total = len(wallet.fingerprints)
    if least == 0:
        noun = "signature" if required == 1 else "signatures"
        verb = "is" if required == 1 else "are"
        return (
            f"Some inputs have no signatures. "
            f"{required} {noun} {verb} required to complete this {required}-of-{total} transaction."
        )
    extra = max(0, required - least)
    held = "signature" if least == 1 else "signatures"
    noun = "signature" if extra == 1 else "signatures"
    verb = "is" if extra == 1 else "are"
    return (
        f"Each input already has {least} {held}. "
        f"{extra} additional {noun} {verb} required to complete this {required}-of-{total} wallet."
    )


def input_signature_count(scope) -> int:
    """Signatures already attached to one input, from any cosigner."""
    partial = len(getattr(scope, "partial_sigs", {}) or {})
    if partial:
        return partial
    witness = getattr(scope, "final_scriptwitness", None)
    items = [] if witness is None else list(getattr(witness, "items", []) or [])
    return sum(1 for item in items if item and item[0] == 0x30)


def seed_sign_rows(session, wallet, psbt: PSBT) -> list[dict]:
    """One row per loaded seed in this wallet, in the wallet's fingerprint order."""
    taproot = wallet.role == SINGLESIG_TAPROOT
    rows = []
    for fingerprint in wallet.fingerprints:
        if session._seed_for(fingerprint) is None:
            continue
        name = session.fingerprints[fingerprint].nickname
        rows.append(
            {
                "fingerprint": fingerprint.hex(),
                "name": name,
                "signed": _fingerprint_signed_all(session, wallet, psbt, fingerprint, taproot),
                "note": f"Already signed by key {name}",
                "button": _sign_with_label(name),
            }
        )
    return rows


def _sign_with_label(name: str) -> str:
    words = name.split()
    if len(words) < 4:
        return f"Sign Transaction with\n{name}"
    return f"Sign Transaction with\n{' '.join(words[:2])}\n{' '.join(words[-2:])}"


def _fingerprint_signed_all(session, wallet, psbt: PSBT, fingerprint: bytes, taproot: bool) -> bool:
    if not psbt.inputs:
        return False
    for scope in psbt.inputs:
        pubkey = _pubkey_for_fingerprint(session, wallet, scope, fingerprint)
        if pubkey is None or not _has_our_signature(scope, pubkey, taproot):
            return False
    return True


def _pubkey_for_fingerprint(session, wallet, scope, fingerprint: bytes):
    for _pubkey, derivation in _derivation_items(scope):
        if derivation.fingerprint != fingerprint or session._seed_for(fingerprint) is None:
            continue
        row = _parse_path(list(derivation.derivation))
        if row["branch"] is None:
            continue
        return _child_key(session, wallet, fingerprint, row)
    return None


def _has_our_signature(scope, pubkey, taproot: bool) -> bool:
    for signed in scope.partial_sigs:
        if _same_key(signed, pubkey, taproot):
            return True
    if taproot:
        for signed, _leaf in getattr(scope, "taproot_sigs", {}):
            if _same_key(signed, pubkey, True):
                return True
        if b"\x13" in getattr(scope, "unknown", {}):
            return True
        witness = scope.final_scriptwitness
        return witness is not None and len(witness.items) == 1 and len(witness.items[0]) in (64, 65)
    witness = scope.final_scriptwitness
    if witness is None:
        return False
    sec = pubkey.sec() if hasattr(pubkey, "sec") else bytes(pubkey)
    return any(item == sec for item in witness.items)


def _outputs(session, wallet, psbt: PSBT):
    for index in range(len(psbt.outputs)):
        _check_output(session, wallet, psbt, index)


def _check_output(session, wallet, psbt: PSBT, index: int):
    scope = psbt.outputs[index]
    vout = psbt.tx.vout[index]
    script = scope.script_pubkey or vout.script_pubkey
    derivations = _derivations(scope)
    if not derivations or script is None:
        return
    owner = _output_wallet(session, derivations)
    if owner is None:
        return
    try:
        item = _input_paths(session, owner, scope)
    except ReviewError as exc:
        if "would not derive" in str(exc):
            raise
        return
    derived = _script_at(session, owner, _accounts(item), item["rows"][0]["branch"], item["rows"][0]["index"])
    if derived == script:
        return
    if owner is wallet:
        raise ReviewError(
            f"A change output whose derived address does not match the PSBT is {NOT_SUPPORTED}."
        )
    name = session.wallet_short_name_of(owner)
    raise ReviewError(
        f"An output matches {name}, but the derived address does not match the PSBT. "
        f"That is {NOT_SUPPORTED}."
    )


def _output_wallet(session, derivations):
    for fingerprint, path in derivations:
        parsed = _parse_path(path)
        for wallet in session.wallets:
            if fingerprint in wallet.fingerprints and wallet.role == parsed["role"]:
                return wallet
    return None


def _accounts(item: dict) -> dict:
    return {row["fingerprint"]: row["account"] for row in item["rows"]}


def _script_at(session, wallet, accounts: dict, branch: int, index: int):
    parsed = session._parsed_descriptor(wallet, accounts)
    return parsed.derive(index, branch_index=branch).script_pubkey()


def _child_key(session, wallet, fingerprint: bytes, row: dict):
    stored = _public_for(session, fingerprint, wallet.role, row["account"])
    return stored.xpub.derive(f"m/{row['branch']}/{row['index']}").key


def _same_key(pubkey, expected, taproot: bool) -> bool:
    try:
        if taproot and hasattr(pubkey, "xonly") and hasattr(expected, "xonly"):
            return pubkey.xonly() == expected.xonly()
        left = pubkey.sec() if hasattr(pubkey, "sec") else bytes(pubkey)
        right = expected.sec() if hasattr(expected, "sec") else bytes(expected)
        return left == right
    except Exception:
        return False


def _derivation_items(scope):
    items = list(getattr(scope, "bip32_derivations", {}).items())
    for pubkey, item in getattr(scope, "taproot_bip32_derivations", {}).items():
        derivation = item[1] if isinstance(item, tuple) else item
        items.append((pubkey, derivation))
    return items


def _derivations(scope) -> list[tuple[bytes, list[int]]]:
    found = []
    for _pubkey, derivation in _derivation_items(scope):
        found.append((derivation.fingerprint, list(derivation.derivation)))
    return found


def _sequence_value(scope, vin) -> int:
    if scope.sequence is not None:
        return int(scope.sequence)
    return int(vin.sequence)


def _sighash_name(sighash) -> str:
    if sighash is None:
        return "unspecified"
    if sighash == SIGHASH.DEFAULT:
        return "SIGHASH_DEFAULT"
    if sighash == SIGHASH.ALL:
        return "SIGHASH_ALL"
    return str(int(sighash))


def _yaml_paths(scope) -> list[str]:
    return [f"{fingerprint.hex()} {format_path(path)}" for fingerprint, path in _derivations(scope)]


def _wallet_for_fingerprint(session, fingerprint: bytes):
    for wallet in session.wallets:
        if fingerprint in wallet.fingerprints:
            return wallet
    return None


def _matching_wallet(session, item: dict, skip):
    fingerprints = {row["fingerprint"] for row in item["rows"]}
    role = item["rows"][0]["role"]
    for wallet in session.wallets:
        if wallet is skip:
            continue
        if wallet.role == role and set(wallet.fingerprints) == fingerprints:
            return wallet
    return None


def _other_wallet_message(session, wallet, rows: list[dict]) -> str | None:
    if not rows or any(row["out_of_range"] for row in rows):
        return None
    item = {"rows": rows}
    other = _matching_wallet(session, item, skip=wallet)
    if other is None:
        return None
    current = session.wallet_short_name_of(wallet)
    name = session.wallet_short_name_of(other)
    return f"This transaction does not belong to wallet {current}. It belongs to wallet {name}."


def _yaml(value, indent: int = 0) -> str:
    pad = "  " * indent
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                nested = _yaml(item, indent + 1)
                if nested:
                    lines.append(nested)
            else:
                lines.append(f"{pad}{key}: {_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, dict):
                body = _yaml(item, indent + 1)
                first, _, rest = body.partition("\n")
                lines.append(f"{pad}- {first.lstrip()}")
                if rest:
                    lines.append(rest)
            else:
                lines.append(f"{pad}- {_scalar(item)}")
        return "\n".join(lines)
    return _scalar(value)


def _scalar(value) -> str:
    if value is None:
        return ""
    text = str(value)
    if text == "" or any(char in text for char in ":#\n"):
        return '"' + text.replace('"', '\\"') + '"'
    return text

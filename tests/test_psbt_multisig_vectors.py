"""The shared 2-of-3 fixture pays Abandon and can arrive signed by LEGAL."""

import pytest
from embit.ec import Signature
from embit.finalizer import finalize_psbt
from embit.psbt import PSBT
from embit.script import p2wpkh
from embit.transaction import SIGHASH

from bigsigner.psbt_check import check_loaded_psbt, verify_existing_signatures
from bigsigner.psbt_review import ReviewError, sign_with
from bigsigner.psbt_view import describe_psbt
from bigsigner.session import Session
from bigsigner.ui.app import App
from psbt_output_vectors import (
    MULTI_DESCRIPTOR,
    MULTI_TO_ABANDON_LEGAL_VECTOR,
    MULTI_TO_ABANDON_VECTOR,
    VECTORS,
    multisig_to_abandon_vector,
)
from test_domain import ABANDON, LEGAL, expression, root_of


def _import_wallet(recipient_loaded=False):
    session = Session()
    session.add_mnemonic(ABANDON.split())
    if recipient_loaded:
        session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})")
    session.add_text((VECTORS / MULTI_DESCRIPTOR).read_text())
    return session, len(session.wallets) - 1


@pytest.mark.parametrize("signed,name", [(False, MULTI_TO_ABANDON_VECTOR), (True, MULTI_TO_ABANDON_LEGAL_VECTOR)])
@pytest.mark.parametrize("recipient_loaded", [False, True])
def test_multisig_payment_vectors_have_correct_payment_change_and_signatures(signed, name, recipient_loaded):
    source, built = multisig_to_abandon_vector(signed_by_legal=signed)
    raw = (VECTORS / name).read_bytes()
    assert raw == built.serialize()
    assert (VECTORS / MULTI_DESCRIPTOR).read_text().strip() == source.descriptor_text(0)
    session, wallet_index = _import_wallet(recipient_loaded)
    wallet = session.wallets[wallet_index]
    assert wallet.threshold == 2 and len(wallet.fingerprints) == 3
    assert all(account == 0 for account in wallet.accounts.values())
    checked = check_loaded_psbt(session, wallet_index, raw)
    assert checked.serialize() == raw
    view = describe_psbt(session, wallet_index, checked)
    assert len(view["outputs"]) == len(view["change_outputs"]) == 1
    payment = view["outputs"][0]
    assert payment["index"] == 0 and payment["amount"] == 50_000
    recipient = root_of(ABANDON).derive("m/84h/0h/0h/0/0").to_public().key
    assert checked.tx.vout[0].script_pubkey == p2wpkh(recipient)
    if recipient_loaded:
        assert payment["owned"]["wallet_index"] != wallet_index
        assert payment["owned"]["place"] == "Receive Address #0"
    else:
        assert payment["owned"] is None
    change = view["change_outputs"][0]
    assert change["index"] == 1 and change["amount"] == 40_000
    assert change["place"] == "Change Address #0"
    assert change["accounts"] == wallet.accounts
    derived = session._parsed_descriptor(wallet).derive(0, branch_index=1)
    assert checked.outputs[1].script_pubkey == derived.script_pubkey()
    assert checked.outputs[1].witness_script == derived.witness_script()
    assert {origin.fingerprint for origin in checked.outputs[1].bip32_derivations.values()} == set(wallet.fingerprints)
    assert all(origin.derivation[-2:] == [1, 0] for origin in checked.outputs[1].bip32_derivations.values())
    assert view["fee"] == 10_000 and view["warnings"] == []
    legal = root_of(LEGAL).derive("m/48h/0h/0h/2h/0/0").to_public().key
    for index, scope in enumerate(checked.inputs):
        assert scope.witness_utxo.value == 100_000
        assert scope.final_scriptwitness is None
        assert set(scope.partial_sigs) == ({legal} if signed else set())
        if signed:
            signature = scope.partial_sigs[legal]
            assert signature[-1] == SIGHASH.ALL
            assert legal.verify(Signature.parse(signature[:-1]), checked.sighash(index, sighash=SIGHASH.ALL))
    assert finalize_psbt(checked) is None
    assert view["signature_note"] == (
        "Each input already has 1 signature. 1 additional signature is required to complete this 2-of-3 wallet."
        if signed else "Some inputs have no signatures. 2 signatures are required to complete this 2-of-3 transaction."
    )
    # LEGAL is an external key in this session, so Abandon remains available.
    assert len(view["signers"]) == 1
    assert view["signers"][0]["fingerprint"] == root_of(ABANDON).my_fingerprint.hex()
    assert not view["signers"][0]["signed"]
    app = App()
    app.session = session
    app.wallet_index = wallet_index
    app._accept_psbt_text(raw, "file")
    assert app.screen == "psbt-yaml"
    assert len(app.psbt_view["change_outputs"]) == 1


def test_unsigned_and_legal_signed_vectors_differ_only_by_the_partial_signature():
    unsigned = PSBT.parse((VECTORS / MULTI_TO_ABANDON_VECTOR).read_bytes())
    signed = PSBT.parse((VECTORS / MULTI_TO_ABANDON_LEGAL_VECTOR).read_bytes())
    assert signed.tx.serialize() == unsigned.tx.serialize()
    assert [scope.serialize() for scope in signed.outputs] == [scope.serialize() for scope in unsigned.outputs]
    for scope in signed.inputs:
        assert len(scope.partial_sigs) == 1
        scope.partial_sigs.clear()
    assert signed.serialize() == unsigned.serialize()


def test_abandon_can_complete_the_legal_signed_multisig_vector():
    session, wallet_index = _import_wallet()
    psbt = check_loaded_psbt(session, wallet_index, (VECTORS / MULTI_TO_ABANDON_LEGAL_VECTOR).read_bytes())
    sign_with(session, wallet_index, psbt, root_of(ABANDON).my_fingerprint)
    verify_existing_signatures(psbt)
    assert all(len(scope.partial_sigs) == 2 for scope in psbt.inputs)
    transaction = finalize_psbt(psbt)
    assert transaction is not None
    assert transaction.txid() == psbt.tx.txid()
    assert all(len(vin.witness.items) == 4 for vin in transaction.vin)
    assert [output.serialize() for output in transaction.vout] == [output.serialize() for output in psbt.tx.vout]


def test_a_corrupted_legal_signature_in_the_vector_is_refused():
    session, wallet_index = _import_wallet()
    psbt = PSBT.parse((VECTORS / MULTI_TO_ABANDON_LEGAL_VECTOR).read_bytes())
    key, signature = next(iter(psbt.inputs[0].partial_sigs.items()))
    broken = bytearray(signature)
    broken[-2] ^= 1
    psbt.inputs[0].partial_sigs[key] = bytes(broken)
    with pytest.raises(ReviewError, match="A signature on input 0 does not match"):
        check_loaded_psbt(session, wallet_index, psbt.serialize())

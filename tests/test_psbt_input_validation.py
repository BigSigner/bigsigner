"""Every input must prove ownership with derived keys and its actual locking script."""

import pytest
from embit.psbt import DerivationPath, PSBT
from embit.script import Script
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.psbt_check import check_loaded_psbt, verify_existing_signatures
from bigsigner.psbt_review import ReviewError, review_psbt, sign_with
from bigsigner.session import Session, _public_for
from test_address_search import ZOO
from test_domain import ABANDON, LEGAL, expression, root_of
from test_psbt_output_accounts import _output
from test_psbt_wallet_mismatch import _wallet


def _fixture(purpose=84, *, watch_only=False, accounts=None):
    words = (ABANDON, LEGAL, ZOO) if purpose == 48 else (ABANDON,)
    session = _wallet(words, purpose)
    wallet = session.wallets[0]
    if accounts is not None:
        # Load account-specific expressions as well, so watch-only fixtures can
        # derive the same account sequence as the fixture with a seed loaded.
        keys = [expression(seed, f"m/48h/0h/{account}h/2h")
                for seed, account in zip(words, accounts)]
        session = Session()
        session.add_mnemonic(ABANDON.split())
        session.add_text(f"wsh(sortedmulti(2,{','.join(keys)}))")
        wallet = session.wallets[0]
    if watch_only:
        descriptor = session.descriptor_text(0)
        session = Session()
        session.add_text(descriptor)
        wallet = session.wallets[0]
    accounts = [wallet.accounts[fp] for fp in wallet.fingerprints]
    sources = [_output(session, wallet, accounts, i % 2, i + 4, 100_000)
               for i in range(3)]
    previous = [Transaction(
        version=2, vin=[TransactionInput(bytes([i + 1]) * 32, 0)],
        vout=[source.vout],
    ) for i, source in enumerate(sources)]
    psbt = PSBT(Transaction(
        version=2,
        vin=[TransactionInput(tx.txid(), 0, sequence=0xFFFFFFFD) for tx in previous],
        vout=[TransactionOutput(290_000, sources[0].script_pubkey)],
    ))
    for scope, source in zip(psbt.inputs, sources):
        scope.witness_utxo = source.vout
        scope.witness_script = source.witness_script
        scope.bip32_derivations.update(source.bip32_derivations)
        scope.taproot_bip32_derivations.update(source.taproot_bip32_derivations)
    return session, psbt, previous


def _origins(scope, purpose):
    return scope.taproot_bip32_derivations if purpose == 86 else scope.bip32_derivations


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("watch_only", [False, True])
def test_all_inputs_can_use_different_receive_change_indexes(purpose, watch_only):
    session, psbt, _ = _fixture(purpose, watch_only=watch_only)
    checked = check_loaded_psbt(session, 0, psbt.serialize())
    assert checked.serialize() == psbt.serialize()
    assert len(review_psbt(session, 0, psbt.serialize())["inputs"]) == 3
    if not watch_only:
        assert sign_with(session, 0, checked, session.wallets[0].fingerprints[0])
        verify_existing_signatures(checked)


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("input_index", [0, 1, 2])
@pytest.mark.parametrize("loader", ["check", "review"])
def test_a_forged_public_key_is_rejected_on_every_input(purpose, input_index, loader):
    session, psbt, _ = _fixture(purpose, watch_only=True)
    origins = _origins(psbt.inputs[input_index], purpose)
    pubkey, origin = origins.popitem(last=False)
    forged = root_of(LEGAL).derive("m/84h/0h/17h/0/21").to_public().key
    assert forged.sec() != pubkey.sec()
    origins[forged] = origin
    with pytest.raises(ReviewError, match="public key does not match"):
        if loader == "check":
            check_loaded_psbt(session, 0, psbt.serialize())
        else:
            review_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_a_later_input_with_a_foreign_fingerprint_is_rejected(purpose):
    session, psbt, _ = _fixture(purpose)
    origins = _origins(psbt.inputs[2], purpose)
    pubkey, origin = origins.popitem(last=False)
    path = origin[1] if purpose == 86 else origin
    changed = DerivationPath(b"\x12\x34\x56\x78", list(path.derivation))
    origins[pubkey] = ([], changed) if purpose == 86 else changed
    with pytest.raises(ReviewError, match="does not belong to this wallet"):
        check_loaded_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_a_later_input_cannot_spend_another_account(purpose):
    session, psbt, _ = _fixture(purpose)
    origins = _origins(psbt.inputs[2], purpose)
    for origin in origins.values():
        (origin[1] if purpose == 86 else origin).derivation[2] += 1
    with pytest.raises(ReviewError, match="more than one account or wallet"):
        check_loaded_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("step,value", [(-2, 1), (-1, 99)])
def test_multisig_participants_must_share_the_branch_and_address_index(step, value):
    session, psbt, _ = _fixture(48)
    origins = psbt.inputs[2].bip32_derivations
    pubkey, origin = list(origins.items())[1]
    origin.derivation[step] = value
    fingerprint = origin.fingerprint
    stored = _public_for(session, fingerprint, session.wallets[0].role, 0)
    correct_for_claimed_path = stored.xpub.derive(origin.derivation[-2:]).key
    del origins[pubkey]
    origins[correct_for_claimed_path] = origin
    with pytest.raises(ReviewError, match="same branch and address index"):
        check_loaded_psbt(session, 0, psbt.serialize())


def test_duplicate_multisig_fingerprints_cannot_hide_a_missing_participant():
    session, psbt, _ = _fixture(48)
    origins = psbt.inputs[2].bip32_derivations
    origins.popitem()
    origin = next(iter(origins.values()))
    stored = _public_for(session, origin.fingerprint, session.wallets[0].role, 0)
    other = stored.xpub.derive([0, 99]).key
    origins[other] = DerivationPath(origin.fingerprint, list(stored.path) + [0, 99])
    with pytest.raises(ReviewError, match="more than one derivation for the same key"):
        check_loaded_psbt(session, 0, psbt.serialize())


def test_multisig_origin_order_does_not_change_the_account_sequence():
    session, psbt, _ = _fixture(48, watch_only=True, accounts=(0, 1, 2))
    origins = psbt.inputs[2].bip32_derivations
    items = list(origins.items())
    origins.clear()
    origins.update(reversed(items))
    assert check_loaded_psbt(session, 0, psbt.serialize()).serialize() == psbt.serialize()


@pytest.mark.parametrize("participant", [0, 1, 2])
def test_every_multisig_participants_public_key_is_checked(participant):
    session, psbt, _ = _fixture(48, watch_only=True, accounts=(0, 1, 2))
    origins = psbt.inputs[2].bip32_derivations
    key, origin = list(origins.items())[participant]
    del origins[key]
    forged = root_of(LEGAL).derive("m/48h/0h/99h/2h/0/99").to_public().key
    origins[forged] = origin
    with pytest.raises(ReviewError, match="public key does not match"):
        check_loaded_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("forged", [False, True])
def test_repeated_origin_metadata_still_checks_each_supplied_public_key(forged):
    session, psbt, _ = _fixture(86)
    scope = psbt.inputs[2]
    key, (_, origin) = next(iter(scope.taproot_bip32_derivations.items()))
    scope.bip32_derivations[key] = origin
    if forged:
        key = root_of(LEGAL).to_public().key
        scope.bip32_derivations.clear()
        scope.bip32_derivations[key] = origin
        with pytest.raises(ReviewError, match="public key does not match"):
            check_loaded_psbt(session, 0, psbt.serialize())
    else:
        scope.taproot_internal_key = key
        check_loaded_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_optional_full_previous_transactions_are_supported_with_witness_utxos(purpose):
    session, psbt, previous = _fixture(purpose)
    for scope, tx in zip(psbt.inputs, previous):
        scope.non_witness_utxo = tx
    checked = check_loaded_psbt(session, 0, psbt.serialize())
    assert sign_with(session, 0, checked, session.wallets[0].fingerprints[0])
    verify_existing_signatures(checked)
    assert review_psbt(session, 0, checked.serialize())["fee"] == 10_000


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("input_index", [0, 1, 2])
@pytest.mark.parametrize("with_previous", [False, True])
def test_every_input_requires_a_witness_utxo_even_with_a_full_previous_transaction(
    purpose, input_index, with_previous,
):
    session, psbt, previous = _fixture(purpose)
    scope = psbt.inputs[input_index]
    scope.witness_utxo = None
    if with_previous:
        scope.non_witness_utxo = previous[input_index]
    raw = psbt.serialize()
    for load in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError, match="without witness UTXO data"):
            load(session, 0, raw)


@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_witness_utxo_must_match_the_derived_wallet_script_even_with_a_full_previous_transaction(purpose):
    session, psbt, previous = _fixture(purpose)
    scope = psbt.inputs[2]
    tx = previous[2]
    tx.vout[0] = TransactionOutput(100_000, Script(b"\x00\x14" + b"\x42" * 20))
    scope.non_witness_utxo = tx
    scope.txid = tx.txid()
    scope.witness_utxo = tx.vout[0]
    with pytest.raises(ReviewError, match="derived address does not match"):
        check_loaded_psbt(session, 0, psbt.serialize())


@pytest.mark.parametrize("problem", ["txid", "vout", "amount", "script"])
def test_supplied_full_previous_transactions_must_be_consistent(problem):
    session, psbt, previous = _fixture()
    scope = psbt.inputs[2]
    scope.non_witness_utxo = previous[2]
    if problem == "txid":
        scope.txid = b"\x42" * 32
    elif problem == "vout":
        scope.vout = 1
    elif problem == "amount":
        scope.witness_utxo = TransactionOutput(110_000, scope.witness_utxo.script_pubkey)
    else:
        scope.witness_utxo = TransactionOutput(100_000, Script(b"\x00\x14" + b"\x42" * 20))
    with pytest.raises(ReviewError, match="previous transaction|previous output"):
        check_loaded_psbt(session, 0, psbt.serialize())


def test_a_multisig_witness_script_must_match_the_trusted_wallet_descriptor():
    session, psbt, _ = _fixture(48)
    psbt.inputs[2].witness_script = Script(b"\x51")
    with pytest.raises(ReviewError, match="witness script does not match"):
        check_loaded_psbt(session, 0, psbt.serialize())


def test_a_missing_multisig_witness_script_is_derived_before_signing():
    session, psbt, _ = _fixture(48)
    expected = psbt.inputs[2].witness_script
    psbt.inputs[2].witness_script = None
    checked = check_loaded_psbt(session, 0, psbt.serialize())
    assert checked.inputs[2].witness_script == expected
    assert sign_with(session, 0, checked, session.wallets[0].fingerprints[0])
    # Verify against the trusted witness script, not a witness program used in
    # its place by embit when witness_script is absent.
    verify_existing_signatures(checked)


@pytest.mark.parametrize("field", ["internal_key", "merkle_root", "leaf_hashes"])
def test_taproot_input_metadata_must_match_the_key_path_wallet(field):
    session, psbt, _ = _fixture(86)
    scope = psbt.inputs[2]
    if field == "internal_key":
        scope.taproot_internal_key = root_of(LEGAL).to_public().key
    elif field == "merkle_root":
        scope.taproot_merkle_root = b"\x42" * 32
    else:
        key, (_, origin) = next(iter(scope.taproot_bip32_derivations.items()))
        scope.taproot_bip32_derivations[key] = ([b"\x42" * 32], origin)
    with pytest.raises(ReviewError, match="Taproot"):
        check_loaded_psbt(session, 0, psbt.serialize())

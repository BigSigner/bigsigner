"""Supported origins identify another wallet even when its keys are unavailable."""

import pytest
from embit.bip39 import mnemonic_from_bytes
from embit.psbt import DerivationPath, PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.paths import HARDENED
from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.psbt_review import ReviewError
from bigsigner.session import Session
from bigsigner.ui.app import App
from test_address_search import ZOO
from test_domain import ABANDON, LEGAL, root_of
from test_path_networks import MAIN_TO_TEST, _expression
from test_psbt_output_accounts import _output

OTHER = mnemonic_from_bytes(b"\x12" * 16)
DIFFERENT_WALLET = "This transaction does not belong to this wallet."


def _wallet(words, purpose=84, network="main"):
    session = Session()
    session.set_network(network)
    session.add_mnemonic(words[0].split())
    keys = [_expression(seed, network, purpose) for seed in words]
    if purpose == 48:
        descriptor = f"wsh(sortedmulti(2,{','.join(keys)}))"
    else:
        descriptor = f"{'tr' if purpose == 86 else 'wpkh'}({keys[0]})"
    session.add_text(descriptor)
    return session


def _transaction(source):
    wallet = source.wallets[0]
    accounts = [wallet.accounts[fingerprint] for fingerprint in wallet.fingerprints]
    funding = _output(source, wallet, accounts, 0, 7, 100_000)
    psbt = PSBT(Transaction(
        version=2, vin=[TransactionInput(b"\x53" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[TransactionOutput(90_000, funding.script_pubkey)],
    ))
    psbt.inputs[0].witness_utxo = funding.vout
    psbt.inputs[0].witness_script = funding.witness_script
    psbt.inputs[0].bip32_derivations.update(funding.bip32_derivations)
    psbt.inputs[0].taproot_bip32_derivations.update(funding.taproot_bip32_derivations)
    # Every fixture is a valid PSBT when its actual wallet is selected.
    check_loaded_psbt(source, 0, psbt)
    return psbt


@pytest.mark.parametrize("purpose,words", [(84, (LEGAL,)), (86, (LEGAL,)), (48, (LEGAL, ZOO))])
@pytest.mark.parametrize("network", ["main", "test", "regtest"])
def test_unloaded_wallets_with_valid_paths_have_a_wallet_error(purpose, words, network):
    selected = _wallet((ABANDON,), network=network)
    source = _wallet(words, purpose, network)
    psbt = _transaction(source)
    assert not set(source.wallets[0].fingerprints) & set(selected.fingerprints)
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, psbt)
    assert str(error.value) == DIFFERENT_WALLET
    app = App()
    app.session = selected
    app.wallet_index = 0
    app._accept_psbt_text(psbt.serialize(), "file")
    assert app.screen == "psbt-error"
    app.render()
    assert DIFFERENT_WALLET in " ".join(mark["text"] for mark in app.texts)
    hit = next(hit for hit in app.hits if hit["label"] == "OK")
    app.tap((hit["box"][0] + hit["box"][2]) // 2, (hit["box"][1] + hit["box"][3]) // 2)
    assert app.screen == "load-psbt"


def test_a_loaded_external_key_without_its_wallet_has_the_same_clear_error():
    selected = _wallet((ABANDON,))
    selected.commit_external_key(selected.prepare_external_key(_expression(LEGAL, "main")))
    assert root_of(LEGAL).my_fingerprint in selected.fingerprints
    assert len(selected.wallets) == 1
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, _transaction(_wallet((LEGAL,))))
    assert str(error.value) == DIFFERENT_WALLET


def test_an_unloaded_wallet_type_with_the_same_fingerprint_is_a_different_wallet():
    selected = _wallet((ABANDON,))
    source = _wallet((ABANDON,), purpose=86)
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, _transaction(source))
    assert str(error.value) == DIFFERENT_WALLET


def test_a_multisig_with_only_some_matching_participants_is_a_different_wallet():
    selected = _wallet((ABANDON, LEGAL, ZOO), purpose=48)
    source = _wallet((ABANDON, LEGAL, OTHER), purpose=48)
    psbt = _transaction(source)
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, psbt)
    assert str(error.value) == DIFFERENT_WALLET
    selected.add_text(source.descriptor_text(0))
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, psbt)
    assert str(error.value) == (
        f"This transaction does not belong to wallet {selected.wallet_short_name_of(selected.wallets[0])}. "
        f"It belongs to wallet {selected.wallet_short_name_of(selected.wallets[1])}."
    )


def test_a_fully_loaded_other_wallet_still_has_its_name_in_the_error():
    selected = _wallet((ABANDON,))
    source = _wallet((LEGAL,))
    selected.add_text(source.descriptor_text(0))
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, _transaction(source))
    assert str(error.value) == (
        f"This transaction does not belong to wallet {selected.wallet_short_name_of(selected.wallets[0])}. "
        f"It belongs to wallet {selected.wallet_short_name_of(selected.wallets[1])}."
    )


def test_a_multisig_with_additional_unloaded_participants_is_a_different_wallet():
    selected = _wallet((ABANDON, LEGAL), purpose=48)
    source = _wallet((ABANDON, LEGAL, OTHER), purpose=48)
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, _transaction(source))
    assert str(error.value) == DIFFERENT_WALLET


def test_a_valid_unknown_fingerprint_path_on_the_other_network_keeps_the_network_error():
    selected = _wallet((ABANDON,))
    source = _wallet((LEGAL,), network="test")
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, _transaction(source))
    assert str(error.value) == MAIN_TO_TEST


@pytest.mark.parametrize("step,value", [(0, 44 | HARDENED), (1, 2 | HARDENED), (2, 0),
                                        (3, 2), (3, HARDENED), (4, HARDENED)])
def test_malformed_unknown_wallet_paths_keep_the_unsupported_path_error(step, value):
    selected = _wallet((ABANDON,))
    psbt = _transaction(_wallet((LEGAL,)))
    origin = next(iter(psbt.inputs[0].bip32_derivations.values()))
    origin.derivation[step] = value
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(selected, 0, psbt)
    assert "unrecognized derivation path" in str(error.value)
    assert DIFFERENT_WALLET not in str(error.value)


def test_unknown_extra_origins_do_not_reject_a_transaction_that_matches_the_selected_wallet():
    selected = _wallet((ABANDON,))
    psbt = _transaction(selected)
    unknown = root_of(LEGAL)
    public = unknown.derive("m/84h/0h/0h/0/7").to_public().key
    psbt.inputs[0].bip32_derivations[public] = DerivationPath(
        unknown.my_fingerprint, [84 | HARDENED, HARDENED, HARDENED, 0, 7],
    )
    assert check_loaded_psbt(selected, 0, psbt).serialize() == psbt.serialize()


def test_unloaded_wallet_error_saves_screenshots():
    from pathlib import Path

    from test_ui import ScreenRecord

    app = App()
    app.session = _wallet((ABANDON,))
    app.wallet_index = 0
    app._accept_psbt_text(_transaction(_wallet((LEGAL,))).serialize(), "file")
    record = ScreenRecord(Path("artifacts/screenshots/test_unloaded_wallet_error_saves_screenshots"))
    record.shot(app, "unloaded-wallet")
    assert DIFFERENT_WALLET in " ".join(mark["text"] for mark in app.texts)
    button = next(hit for hit in app.hits if hit["label"] == "OK")
    assert all(mark["box"][3] < button["box"][1] for mark in app.texts)

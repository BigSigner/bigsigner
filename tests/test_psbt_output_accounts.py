"""Known recipients are payments unless both wallet and spending accounts match."""

import pytest
from embit.psbt import DerivationPath, OutputScope, PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.paths import SINGLESIG_TAPROOT
from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.psbt_view import ALL_TO_WALLET, account_line, describe_psbt
from bigsigner.session import _public_for
from bigsigner.ui.app import App
from test_address_search import _mixed_multisig
from test_domain import ABANDON, LEGAL, expression
from test_psbt_load import _native


def _output(session, wallet, indexes, branch, index, value):
    accounts = dict(zip(wallet.fingerprints, indexes))
    descriptor = session._parsed_descriptor(wallet, accounts).derive(index, branch_index=branch)
    output = OutputScope(vout=TransactionOutput(value, descriptor.script_pubkey()))
    output.witness_script = descriptor.witness_script()
    for fingerprint, account in accounts.items():
        stored = _public_for(session, fingerprint, wallet.role, account)
        child = stored.xpub.derive([branch, index])
        origin = DerivationPath(fingerprint, list(stored.path) + [branch, index])
        if wallet.role == SINGLESIG_TAPROOT:
            output.taproot_bip32_derivations[child.key] = ([], origin)
        else:
            output.bip32_derivations[child.key] = origin
    return output


def _spend(session, destination):
    wallet = session.wallets[0]
    accounts = [wallet.accounts[fingerprint] for fingerprint in wallet.fingerprints]
    source = _output(session, wallet, accounts, 0, 0, 100_000)
    psbt = PSBT(Transaction(
        version=2,
        vin=[TransactionInput(b"\x46" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[destination.vout],
    ))
    psbt.inputs[0].witness_utxo = source.vout
    psbt.inputs[0].witness_script = source.witness_script
    psbt.inputs[0].bip32_derivations.update(source.bip32_derivations)
    psbt.outputs[0] = destination
    return check_loaded_psbt(session, 0, psbt)


@pytest.mark.parametrize("spending,receiving", [
    ((0,), (0,)), ((0,), (1,)), ((0,), (3,)), ((3,), (0,)), ((3,), (3,)),
    ((0, 4, 0), (0, 4, 0)), ((0, 4, 0), (1, 4, 0)),
    ((0, 4, 0), (0, 5, 0)), ((0, 4, 0), (1, 5, 0)),
])
@pytest.mark.parametrize("branch", [0, 1])
def test_change_requires_the_complete_spending_account_sequence(spending, receiving, branch):
    session = _native() if len(spending) == 1 else _mixed_multisig()
    wallet = session.wallets[0]
    wallet.accounts.update(zip(wallet.fingerprints, spending))
    selected = dict(wallet.accounts)
    destination = _output(session, wallet, receiving, branch, 120, 90_000)
    checked = _spend(session, destination)
    view = describe_psbt(session, 0, checked)
    same_accounts = spending == receiving
    assert len(view["change_outputs"]) == int(same_accounts)
    assert len(view["outputs"]) == int(not same_accounts)
    assert view["outputs_note"] == (ALL_TO_WALLET if same_accounts else "")
    card = (view["change_outputs"] or view["outputs"])[0]
    assert card["change"] == same_accounts
    assert card["accounts"] == dict(zip(wallet.fingerprints, receiving))
    assert not card["receive_change"]
    if not same_accounts:
        owned = card["owned"]
        assert owned["wallet_index"] == 0
        assert owned["name"] == session.wallet_short_name_of(wallet)
        assert owned["account_line"] == account_line(wallet.fingerprints, card["accounts"])
        assert owned["place"] == ("Receive" if branch == 0 else "Change") + " Address #120"
    assert view["warnings"] == []
    assert view["fee"] == 10_000
    assert wallet.accounts == selected


@pytest.mark.parametrize("other", ["seed", "type", "threshold"])
@pytest.mark.parametrize("branch", [0, 1])
def test_another_wallet_with_matching_accounts_is_a_known_payment(other, branch):
    session = _mixed_multisig() if other == "threshold" else _native()
    if other == "seed":
        session.add_text(f"wpkh({expression(LEGAL, 'm/84h/0h/0h')})")
    elif other == "type":
        session.add_text(f"tr({expression(ABANDON, 'm/86h/0h/0h')})")
    else:
        descriptor = session.descriptor_text(0).split("#")[0]
        session.add_text(descriptor.replace("sortedmulti(2,", "sortedmulti(1,"))
    wallet = session.wallets[1]
    receiving = [wallet.accounts[fingerprint] for fingerprint in wallet.fingerprints]
    destination = _output(session, wallet, receiving, branch, 120, 90_000)
    # Load without the destination's origins, then discover the other wallet.
    hidden = OutputScope(vout=destination.vout)
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(_spend(session, hidden).serialize(), "file")
    app._act("psbt-search-0-0")
    app.psbt_search_start = 120
    app._act("psbt-search-start")
    for _ in range(200):
        if not app.psbt_search_active():
            break
        app._advance_psbt_search()
    assert app.screen == "address-search" and app.confirm == "psbt-found"
    app._act("psbt-search-confirm")
    assert app.screen == "psbt-yaml"
    view = app.psbt_view
    assert view["change_outputs"] == []
    assert view["outputs_note"] == ""
    owned = view["outputs"][0]["owned"]
    assert owned["wallet_index"] == 1
    assert owned["name"] == session.wallet_short_name_of(wallet)
    assert owned["account_line"] == account_line(wallet.fingerprints, wallet.accounts)
    assert view["warnings"] == []

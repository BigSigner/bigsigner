"""Change requires derived keys and scripts, not a coordinator's ownership labels."""

import pytest
from embit.descriptor import Descriptor
from embit.psbt import OutputScope
from embit.script import Script

from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.paths import HARDENED
from bigsigner.psbt_review import ReviewError, review_psbt
from bigsigner.psbt_view import describe_psbt
from bigsigner.ui.app import App
from test_domain import LEGAL, root_of
from test_psbt_input_validation import _fixture
from test_psbt_output_accounts import _output
from psbt_output_vectors import MULTI_DESCRIPTOR, MULTI_VECTOR, SINGLE_ACCOUNT1_VECTOR, SINGLE_VECTOR, VECTORS, spoofed_change_vector


def _destination(session, psbt, branch=0):
    wallet = session.wallets[0]
    accounts = [wallet.accounts[fp] for fp in wallet.fingerprints]
    return _output(session, wallet, accounts, branch, 120, psbt.outputs[0].value)


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("branch", [0, 1])
@pytest.mark.parametrize("watch_only", [False, True])
def test_change_can_be_receive_or_change_but_must_derive_from_the_wallet(purpose, branch, watch_only):
    session, psbt, _ = _fixture(purpose, watch_only=watch_only)
    psbt.outputs[0] = _destination(session, psbt, branch)
    checked = check_loaded_psbt(session, 0, psbt.serialize())
    view = describe_psbt(session, 0, checked)
    assert view["outputs"] == []
    assert view["change_outputs"][0]["place"] == ("Receive" if branch == 0 else "Change") + " Address #120"


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("branch", [0, 1])
def test_correct_origins_cannot_hide_an_attackers_output_script(purpose, branch):
    session, psbt, _ = _fixture(purpose)
    claimed = _destination(session, psbt, branch)
    claimed.script_pubkey = Script(b"\x00\x14" + b"\x42" * 20)
    psbt.outputs[0] = claimed
    for load in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError, match="An output claims to belong to this wallet"):
            load(session, 0, psbt.serialize())
    assert describe_psbt(session, 0, psbt)["change_outputs"] == []


@pytest.mark.parametrize("purpose,participant", [(84, 0), (86, 0), (48, 0), (48, 1), (48, 2)])
def test_every_public_key_claimed_by_an_output_must_match_its_path(purpose, participant):
    session, psbt, _ = _fixture(purpose, watch_only=True)
    scope = _destination(session, psbt)
    origins = scope.taproot_bip32_derivations if purpose == 86 else scope.bip32_derivations
    key, origin = list(origins.items())[participant]
    del origins[key]
    forged = root_of(LEGAL).derive("m/84h/0h/99h/0/9").to_public().key
    origins[forged] = origin
    psbt.outputs[0] = scope
    for load in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError, match="output.*public key does not match"):
            load(session, 0, psbt.serialize())
    assert describe_psbt(session, 0, psbt)["change_outputs"] == []


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("branch", [0, 1])
def test_additional_output_origins_are_checked_without_changing_the_psbt(purpose, branch):
    session, psbt, _ = _fixture(purpose)
    info = _destination(session, psbt, branch)
    psbt.outputs[0] = OutputScope(vout=info.vout)
    raw = psbt.serialize()
    checked = check_loaded_psbt(session, 0, raw, output_info={0: info})
    assert checked.serialize() == raw
    assert describe_psbt(session, 0, checked)["change_outputs"] == []
    view = describe_psbt(session, 0, checked, output_info={0: info})
    assert len(view["change_outputs"]) == 1
    assert view["outputs"] == []


@pytest.mark.parametrize("problem", ["script", "key", "path"])
def test_additional_information_is_never_trusted_as_an_ownership_flag(problem):
    session, psbt, _ = _fixture()
    info = _destination(session, psbt)
    psbt.outputs[0] = OutputScope(vout=info.vout)
    key, origin = next(iter(info.bip32_derivations.items()))
    if problem == "script":
        psbt.outputs[0].script_pubkey = Script(b"\x00\x14" + b"\x42" * 20)
    elif problem == "key":
        info.bip32_derivations.clear()
        info.bip32_derivations[root_of(LEGAL).to_public().key] = origin
    else:
        origin.derivation[-1] += 1
    with pytest.raises(ReviewError):
        check_loaded_psbt(session, 0, psbt.serialize(), output_info={0: info})
    assert describe_psbt(session, 0, psbt, output_info={0: info})["change_outputs"] == []


def test_additional_information_cannot_override_forged_psbt_origins():
    session, psbt, _ = _fixture()
    info = _destination(session, psbt)
    forged = _destination(session, psbt)
    next(iter(forged.bip32_derivations.values())).derivation[-1] += 1
    psbt.outputs[0] = forged
    with pytest.raises(ReviewError):
        check_loaded_psbt(session, 0, psbt.serialize(), output_info={0: info})


@pytest.mark.parametrize("forged", [False, True])
def test_additional_information_can_fill_missing_multisig_participants_without_overriding_claims(forged):
    session, psbt, _ = _fixture(48)
    info = _destination(session, psbt)
    partial = _destination(session, psbt)
    partial.bip32_derivations.popitem()
    if forged:
        next(iter(partial.bip32_derivations.values())).derivation[-1] += 1
    psbt.outputs[0] = partial
    assert describe_psbt(session, 0, psbt)["change_outputs"] == []
    raw = psbt.serialize()
    if forged:
        with pytest.raises(ReviewError):
            check_loaded_psbt(session, 0, raw, output_info={0: info})
    else:
        checked = check_loaded_psbt(session, 0, raw, output_info={0: info})
        assert checked.serialize() == raw
        assert len(describe_psbt(session, 0, checked, output_info={0: info})["change_outputs"]) == 1


@pytest.mark.parametrize("problem", ["missing", "duplicate", "branch", "index"])
def test_incomplete_or_inconsistent_multisig_origins_never_qualify_as_change(problem):
    session, psbt, _ = _fixture(48)
    scope = _destination(session, psbt)
    origins = scope.bip32_derivations
    items = list(origins.items())
    if problem == "missing":
        origins.popitem()
    elif problem == "duplicate":
        items[1][1].fingerprint = items[0][1].fingerprint
    elif problem == "branch":
        items[1][1].derivation[-2] = 1
    else:
        items[1][1].derivation[-1] += 1
    psbt.outputs[0] = scope
    assert describe_psbt(session, 0, psbt)["change_outputs"] == []


def test_every_multisig_participant_must_use_the_wallets_derivation_template():
    session, psbt, _ = _fixture(48)
    scope = _destination(session, psbt)
    origin = list(scope.bip32_derivations.values())[1]
    origin.derivation = [84 | HARDENED, HARDENED, HARDENED, 0, 120]
    psbt.outputs[0] = scope
    with pytest.raises(ReviewError):
        check_loaded_psbt(session, 0, psbt.serialize())
    assert describe_psbt(session, 0, psbt)["change_outputs"] == []


@pytest.mark.parametrize("field", ["witness_script", "internal_key", "tree", "leaf_hashes"])
@pytest.mark.parametrize("additional", [False, True])
def test_script_metadata_is_checked_even_when_origins_come_from_address_search(field, additional):
    purpose = 48 if field == "witness_script" else 86
    session, psbt, _ = _fixture(purpose)
    info = _destination(session, psbt)
    scope = OutputScope(vout=info.vout) if additional else info
    if field == "witness_script":
        scope.witness_script = Script(b"\x51")
    elif field == "internal_key":
        scope.taproot_internal_key = root_of(LEGAL).to_public().key
    elif field == "tree":
        scope.unknown = {b"\x06": b"\x00"}
    else:
        key, (_, origin) = next(iter(info.taproot_bip32_derivations.items()))
        info.taproot_bip32_derivations[key] = ([b"\x42" * 32], origin)
    psbt.outputs[0] = scope
    extra = {0: info} if additional else {}
    with pytest.raises(ReviewError):
        check_loaded_psbt(session, 0, psbt.serialize(), output_info=extra)
    assert describe_psbt(session, 0, psbt, output_info=extra)["change_outputs"] == []


@pytest.mark.parametrize("multisig,name,account", [(False, SINGLE_VECTOR, 0),
                                                  (False, SINGLE_ACCOUNT1_VECTOR, 1),
                                                  (True, MULTI_VECTOR, 0)])
def test_spoofed_change_vectors_reject_genuine_origins_on_foreign_scripts(multisig, name, account):
    session, psbt = spoofed_change_vector(multisig, account=account)
    assert (VECTORS / name).read_bytes() == psbt.serialize()
    scope = psbt.outputs[1]
    wallet = session.wallets[0]
    assert all(index == 0 for index in wallet.accounts.values())
    assert all(origin.derivation[2] == HARDENED for origin in psbt.inputs[0].bip32_derivations.values())
    assert {origin.fingerprint for origin in scope.bip32_derivations.values()} == set(wallet.fingerprints)
    assert all(origin.derivation[2] == account | HARDENED for origin in scope.bip32_derivations.values())
    assert all(origin.derivation[-2:] == [0, 120] for origin in scope.bip32_derivations.values())
    accounts = {fingerprint: account for fingerprint in wallet.fingerprints}
    expected = session._parsed_descriptor(wallet, accounts).derive(120, branch_index=0)
    assert scope.script_pubkey != expected.script_pubkey()
    assert {key.sec() for key in scope.bip32_derivations} == {key.sec() for key in expected.keys}
    # Merely displaying this unvalidated PSBT must never hide the attack.
    view = describe_psbt(session, 0, psbt)
    assert view["change_outputs"] == []
    assert view["outputs"][1]["owned"] is None
    for load in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError) as error:
            load(session, 0, psbt.serialize())
        account_note = " (on a different account)" if account != 0 else ""
        assert str(error.value) == (
            f"An output claims to belong to this wallet{account_note}, but its address does not match "
            "the supplied derivation path. This may be an attempt to spoof a change output."
        )
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(psbt.serialize(), "file")
    assert app.screen == "psbt-error"
    assert app.psbt_error == str(error.value)
    assert all(index == 0 for index in wallet.accounts.values())
    if multisig:
        descriptor = (VECTORS / MULTI_DESCRIPTOR).read_text().strip()
        assert descriptor == session.descriptor_text(0)
        assert Descriptor.from_string(descriptor).derive(120, branch_index=0).script_pubkey() == expected.script_pubkey()


@pytest.mark.parametrize("claim", [(0, 1, 2), (1, 1, 2)])
def test_spoofed_multisig_outputs_compare_the_complete_spending_account_mapping(claim):
    session, psbt, _ = _fixture(48, accounts=(0, 1, 2))
    wallet = session.wallets[0]
    scope = _output(session, wallet, claim, 0, 120, psbt.outputs[0].value)
    scope.script_pubkey = Script(b"\x00\x14" + b"\x42" * 20)
    psbt.outputs[0] = scope
    for load in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError) as error:
            load(session, 0, psbt.serialize())
        assert ("(on a different account)" in str(error.value)) == (claim != (0, 1, 2))
        assert "spoof a change output" in str(error.value)


@pytest.mark.parametrize("account", [0, 1])
def test_spoofing_message_uses_the_captured_spending_accounts(account):
    session, psbt = spoofed_change_vector(account=account)
    wallet = session.wallets[0]
    captured = dict(wallet.accounts)
    wallet.accounts[wallet.fingerprints[0]] = 1
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(session, 0, psbt.serialize(), accounts=captured)
    assert ("(on a different account)" in str(error.value)) == (account != 0)
    # The legacy review derives its spending-account mapping from the inputs.
    with pytest.raises(ReviewError) as error:
        review_psbt(session, 0, psbt.serialize())
    assert ("(on a different account)" in str(error.value)) == (account != 0)

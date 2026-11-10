"""A search result is acknowledged on Address Search, then checked from scratch."""

from pathlib import Path

import pytest
from embit.psbt import OutputScope

import bigsigner.ui.app as app_module
from bigsigner.psbt_review import review_psbt
from bigsigner.ui.app import App
from test_domain import LEGAL, root_of
from test_psbt_input_validation import _fixture
from test_psbt_output_accounts import _output


def _app(purpose=84):
    app = App()
    app.session, psbt, _ = _fixture(purpose)
    app.wallet_index = 0
    wallet = app.session.wallets[0]
    accounts = [wallet.accounts[fp] for fp in wallet.fingerprints]
    psbt.outputs = [OutputScope(vout=_output(app.session, wallet, accounts, branch, index, amount).vout)
                    for branch, index, amount in ((0, 6, 140_000), (1, 7, 150_000))]
    raw = psbt.serialize()
    app.screen = "load-psbt"
    app.back = ["wallet"]
    app._accept_psbt_text(raw, "file")
    return app, raw


def _find(app, output=0, address_index=6):
    app._act(f"psbt-search-{output}-0")
    app.psbt_search_first = app.psbt_search_last = 0
    app.psbt_search_start = address_index
    app._act("psbt-search-start")
    for _ in range(100):
        if not app.psbt_search_active():
            break
        app._advance_psbt_search()
    assert app.confirm == "psbt-found"
    assert app.screen == "address-search"


def _finish_reload(app):
    messages = []
    for _ in range(100):
        if app.screen != "psbt-progress":
            break
        app.render()
        messages.append(app.psbt_progress_text)
    return messages


@pytest.mark.parametrize("purpose", [84, 86, 48])
@pytest.mark.parametrize("deferred", [False, True])
def test_confirming_search_reruns_every_check_and_keeps_origins_separate(purpose, deferred, monkeypatch):
    app, raw = _app(purpose)
    original_view = app.psbt_view
    _find(app)
    assert app.psbt_view is original_view
    assert app.psbt_checked.serialize() == raw == app.psbt_loaded
    assert app.psbt_output_info == {}
    app.render()
    assert next(hit for hit in app.hits if hit["label"] == "OK")["action"] == "psbt-search-confirm"
    monkeypatch.setattr(app_module, "PSBT_PROGRESS_PAINT_S", 0)
    app.defer_psbt_progress = deferred
    messages = []
    if not deferred:
        app.flush_display = lambda: messages.append(app.psbt_progress_text)
    app._act("psbt-search-confirm")
    if deferred:
        assert app.screen == "psbt-progress"
        assert app.psbt_view is original_view
        messages.extend(_finish_reload(app))
    assert app.screen == "psbt-yaml"
    assert app.psbt_view is not original_view
    for index in range(1, 4):
        assert f"Parsing input {index} of 3" in messages
        assert f"Checking input {index} of 3" in messages
    assert "Checking output 1 of 2" in messages
    assert "Checking output 2 of 2" in messages
    assert any(message.startswith("Checking signatures") for message in messages)
    assert app.psbt_checked.serialize() == raw == app.psbt_loaded
    assert set(app.psbt_output_info) == {0}
    assert app.psbt_view["change_outputs"][0]["place"] == "Receive Address #6"
    assert [item["index"] for item in app.psbt_view["outputs"]] == [1]
    assert app.back == ["wallet", "load-psbt"]
    assert app._discard_queued_touch


@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_multiple_searches_accumulate_and_a_new_psbt_clears_the_information(purpose):
    app, raw = _app(purpose)
    _find(app)
    app._act("psbt-search-confirm")
    _find(app, output=1, address_index=7)
    assert set(app.psbt_output_info) == {0}
    app._act("psbt-search-confirm")
    assert set(app.psbt_output_info) == {0, 1}
    assert app.psbt_checked.serialize() == raw
    assert len(app.psbt_view["change_outputs"]) == 2
    assert app.psbt_view["outputs"] == []
    reviewed = review_psbt(app.session, 0, raw, output_info=app.psbt_output_info)
    assert all(output["change"] for output in reviewed["outputs"])
    app._restore_loaded_psbt()
    assert app.psbt_checked.serialize() == raw
    assert len(app.psbt_view["change_outputs"]) == 2
    app._accept_psbt_text(raw, "file")
    assert app.psbt_output_info == {}
    assert app.psbt_view["change_outputs"] == []


def test_dismissing_the_popup_does_not_accept_or_apply_the_discovery():
    app, raw = _app()
    _find(app)
    app._act("confirm-no")
    assert app.screen == "address-search"
    assert app.confirm is None and app.psbt_search_hit is None
    assert app.psbt_output_info == {}
    app.back_one()
    assert app.screen == "psbt-yaml"
    assert app.psbt_checked.serialize() == raw
    assert app.psbt_view["change_outputs"] == []


@pytest.mark.parametrize("problem", ["input", "discovery", "signature"])
@pytest.mark.parametrize("deferred", [False, True])
def test_reloading_after_a_search_cannot_bypass_validation(problem, deferred, monkeypatch):
    app, _raw = _app()
    _find(app)
    if problem == "discovery":
        info = app.psbt_search_hit["output_info"]
        next(iter(info.bip32_derivations.values())).derivation[-1] += 1
    else:
        scope = app.psbt_checked.inputs[1]
        key, origin = next(iter(scope.bip32_derivations.items()))
        if problem == "input":
            scope.bip32_derivations.clear()
            scope.bip32_derivations[root_of(LEGAL).to_public().key] = origin
        else:
            scope.partial_sigs[key] = b"\x01" * 10
    monkeypatch.setattr(app_module, "PSBT_PROGRESS_PAINT_S", 0)
    app.defer_psbt_progress = deferred
    app._act("psbt-search-confirm")
    _finish_reload(app)
    assert app.screen == "psbt-error"
    assert app.psbt_view["change_outputs"] == []


def test_reload_preserves_the_selected_account_sequence():
    app, _raw = _app()
    selected = dict(app.psbt_accounts)
    _find(app)
    wallet = app.session.wallets[0]
    wallet.accounts[wallet.fingerprints[0]] = 3
    app._act("psbt-search-confirm")
    assert app.screen == "psbt-yaml"
    assert app.psbt_accounts == selected
    assert app.psbt_view["account_line"] == "Account: 0 (default)"
    assert app.psbt_view["change_outputs"][0]["accounts"] == selected
    assert wallet.accounts[wallet.fingerprints[0]] == 3


def test_search_confirmation_and_revalidation_save_screenshots(monkeypatch):
    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_search_confirmation_and_revalidation_save_screenshots"))
    app, _raw = _app()
    _find(app)
    record.shot(app, "found-on-address-search")
    monkeypatch.setattr(app_module, "PSBT_PROGRESS_PAINT_S", 0)
    app.defer_psbt_progress = True
    app._act("psbt-search-confirm")
    record.shot(app, "rechecking")
    _finish_reload(app)
    assert app.screen == "psbt-yaml"
    record.shot(app, "verified-review")

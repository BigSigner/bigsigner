"""Account combinations, cached branch derivation, and interruptible search controls."""

from itertools import product

import pytest
from embit import bip32
from embit.networks import NETWORKS
from embit.script import Script

from bigsigner.address_search import AddressSearch, MAX_CREATORS, MAX_INDEX
from bigsigner.session import Session, SessionError
from bigsigner.ui.app import App
from bigsigner.ui.canvas import BLUE, RED
from test_domain import ABANDON, LEGAL, expression, root_of
from test_psbt_load import _native, _native_taproot, _psbt

ZOO = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"


def _finish(search, limit=10000):
    for _ in range(limit):
        search.step()
        if search.done:
            return search.result
    raise AssertionError("Search did not finish")


def _mixed_multisig():
    session = Session()
    session.add_mnemonic(ABANDON.split())
    keys = [expression(words, f"m/48h/0h/{account}h/2h")
            for words, account in ((ABANDON, 0), (LEGAL, 4), (ZOO, 0))]
    session.add_text(f"wsh(sortedmulti(2,{','.join(keys)}))")
    for account in (5, 6):
        session.add_text(expression(LEGAL, f"m/48h/0h/{account}h/2h"))
    return session


def _address(session, accounts, branch=0, index=0):
    wallet = session.wallets[0]
    descriptor = session._parsed_descriptor(wallet, dict(zip(wallet.fingerprints, accounts)))
    return descriptor.derive(index, branch_index=branch).address(NETWORKS[session.network])


def _app(address=None):
    app = App()
    app.session = _native()
    app.wallet_index = 0
    app.screen = "psbt-yaml"
    app.psbt_view = {"outputs": [{"index": 0, "address": address or app.session.addresses(0, 0, 30, 1)[0]}]}
    app._act("psbt-search-0-0")
    return app


def _tap(app, action):
    app.render()
    box = next(hit["box"] for hit in app.hits if hit["action"] == action)
    return app.tap((box[0] + box[2]) // 2, (box[1] + box[3]) // 2)


@pytest.mark.parametrize("network,coin", [("main", 0), ("test", 1), ("regtest", 1)])
@pytest.mark.parametrize("kind", ["wpkh", "tr"])
@pytest.mark.parametrize("branch", [0, 1])
def test_decoded_address_type_selects_matching_wallets(network, coin, kind, branch):
    session = Session()
    session.set_network(network)
    session.add_mnemonic(ABANDON.split())
    root = root_of(ABANDON)
    for wallet_kind, number in (("wpkh", 84), ("tr", 86)):
        path = f"{number}h/{coin}h/2h"
        public = root.derive(path).to_public().to_base58(version=NETWORKS[network]["xpub"])
        key = f"[{root.my_fingerprint.hex()}/{path}]{public}/<0;1>/*"
        session.add_text(f"{wallet_kind}({key})")
    wallet_index = 0 if kind == "wpkh" else 1
    target = session.addresses(wallet_index, branch, 3, 1)[0]
    search = AddressSearch(session, target, 2, 2, 3, 3)
    assert search.creator_count == 2
    found = _finish(search)
    assert (found["wallet_index"], found["account_indexes"], found["branch"], found["address_index"]) == (
        wallet_index, [2], branch, 3,
    )


def test_multisig_uses_the_full_product_of_seed_and_loaded_external_accounts():
    session = _mixed_multisig()
    wallet = session.wallets[0]
    selected = dict(wallet.accounts)
    target = _address(session, (5, 5, 0), branch=1, index=2)
    search = AddressSearch(session, target, 0, 5, 2, 2)
    assert search.creator_count == 24  # Six seed accounts × two external accounts × one external account × two branches.
    for _ in range(search.creator_count):
        search.step()
    assert {(tuple(indexes), branch) for _, _, indexes, branch, _ in search.creators} == {
        (indexes, branch) for indexes in product(range(6), (4, 5), (0,)) for branch in (0, 1)
    }
    assert _finish(search)["account_indexes"] == [5, 5, 0]
    assert wallet.accounts == selected


def test_each_account_and_branch_is_derived_once_and_leaf_work_uses_one_step(monkeypatch):
    import bigsigner.address_search as module

    session = _mixed_multisig()
    target = _address(session, (5, 5, 0), branch=1, index=2)
    public_calls, paths = [], []
    public_for, derive = module._public_for, bip32.HDKey.derive

    def public(*args):
        public_calls.append(args[1:])
        return public_for(*args)

    def child(key, path):
        paths.append(path)
        return derive(key, path)

    monkeypatch.setattr(module, "_public_for", public)
    monkeypatch.setattr(bip32.HDKey, "derive", child)
    search = AddressSearch(session, target, 0, 5, 0, 0)
    for _ in range(search.creator_count):
        search.step()
    assert len(public_calls) == len(set(public_calls)) == 9
    branch_paths = [path for path in paths if isinstance(path, list) and len(path) == 1]
    assert len(branch_paths) == 18
    assert branch_paths.count([0]) == branch_paths.count([1]) == 9
    paths.clear()
    assert _finish(search) is None
    assert len(paths) == 24 * 3
    assert paths == [[0]] * (24 * 3)


def test_address_index_is_the_outer_loop_and_branch_nodes_are_cached(monkeypatch):
    session = _native()
    target = session.addresses(0, 1, 3, 1)[0]
    search = AddressSearch(session, target, 0, 1, 1, 2)
    paths = []
    derive = bip32.HDKey.derive

    def child(key, path):
        paths.append(path)
        return derive(key, path)

    monkeypatch.setattr(bip32.HDKey, "derive", child)
    for _ in range(4):
        search.step()
    # Each of the two account nodes is expanded to Receive and Change just once.
    assert paths[-1] == [1]
    paths.clear()
    assert _finish(search) is None
    assert paths == [[1]] * 4 + [[2]] * 4


def test_creator_limit_is_checked_before_derivation_and_512_is_allowed(monkeypatch):
    session = _native()
    target = session.addresses(0, 0, 0, 1)[0]
    monkeypatch.setattr("bigsigner.address_search._public_for", lambda *_: pytest.fail("Derived before checking limit"))
    assert AddressSearch(session, target, 0, 255).creator_count == MAX_CREATORS
    with pytest.raises(SessionError, match="range is too large"):
        AddressSearch(session, target, 0, 256)
    with pytest.raises(SessionError, match="range is too large"):
        AddressSearch(session, target, 0, MAX_INDEX)
    session.wallets *= 257
    with pytest.raises(SessionError, match="too many loaded wallets"):
        AddressSearch(session, target, 0, 0)


def test_an_empty_participant_range_skips_the_wallet_without_expanding_seed_ranges():
    session = _mixed_multisig()
    target = _address(session, (0, 4, 0))
    with pytest.raises(SessionError, match="No loaded wallets"):
        AddressSearch(session, target, 7, MAX_INDEX)


@pytest.mark.parametrize("first,last,start", [(-1, 5, 0), (5, 4, 0), (0, MAX_INDEX + 1, 0), (0, 0, -1), (0, 0, MAX_INDEX + 1)])
def test_invalid_indexes_are_refused(first, last, start):
    with pytest.raises(SessionError, match="indexes must be between"):
        AddressSearch(_native(), "invalid", first, last, start)


def test_invalid_or_unsupported_address_is_refused():
    for address in ("invalid", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"):
        with pytest.raises(SessionError):
            AddressSearch(_native(), address, 0, 0)


def test_last_nonhardened_account_and_address_are_inclusive():
    session = _native()
    target = _address(session, (MAX_INDEX,), branch=1, index=MAX_INDEX)
    search = AddressSearch(session, target, MAX_INDEX, MAX_INDEX, MAX_INDEX)
    assert _finish(search)["address_index"] == MAX_INDEX
    other = session.addresses(0, 0, 0, 1)[0]
    search = AddressSearch(session, other, MAX_INDEX, MAX_INDEX, MAX_INDEX)
    assert _finish(search) is None
    assert search.address_index == MAX_INDEX


@pytest.mark.parametrize("selected,first,last", [(0, 0, 5), (2, 0, 5), (3, 1, 6), (10, 8, 13), (MAX_INDEX, MAX_INDEX - 2, MAX_INDEX)])
def test_screen_defaults_follow_selected_account(selected, first, last):
    app = _app()
    app.back_one()
    wallet = app.session.wallets[0]
    wallet.accounts[wallet.fingerprints[0]] = selected
    app._act("psbt-search-0-0")
    assert (app.screen, app.psbt_search_first, app.psbt_search_last, app.psbt_search_start) == (
        "address-search", first, last, 0,
    )


def test_multisig_defaults_use_the_lowest_selected_account():
    app = _app()
    app.back_one()
    app.session = _mixed_multisig()
    wallet = app.session.wallets[0]
    wallet.accounts.update(zip(wallet.fingerprints, (9, 5, 3)))
    app._act("psbt-search-0-0")
    assert (app.psbt_search_first, app.psbt_search_last) == (1, 6)


def test_selectors_support_taps_numeric_entry_bounds_and_an_inclusive_range():
    app = _app()
    _tap(app, "search-field-first-inc")
    assert app.psbt_search_first == 1
    _tap(app, "search-field-first-edit")
    app.account_text = "7"
    _tap(app, "account-save")
    assert (app.psbt_search_first, app.psbt_search_last) == (7, 7)
    app.render()
    assert "search-field-last-dec" not in {hit["action"] for hit in app.hits}
    _tap(app, "search-field-last-edit")
    app.account_text = "6"
    _tap(app, "account-save")
    assert app.screen == "account"
    assert app.psbt_search_last == 7
    app._act("dismiss-notice")
    app.account_text = str(MAX_INDEX + 1)
    _tap(app, "account-save")
    assert app.screen == "account"
    app._act("dismiss-notice")
    app.account_text = str(MAX_INDEX)
    _tap(app, "account-save")
    assert app.psbt_search_last == MAX_INDEX
    _tap(app, "search-field-start-edit")
    app.account_text = "100"
    _tap(app, "account-save")
    assert app.psbt_search_start == 100


def test_search_controls_stay_responsive_and_selectors_are_disabled():
    app = _app()
    _tap(app, "psbt-search-start")
    job = app.psbt_search
    image = app.render()
    assert {hit["action"] for hit in app.hits} == {"back", "psbt-search-stop"}
    assert image.getpixel((30, 730)) == RED
    assert app.notice_delay() == 0
    app._act("search-field-first-inc")  # A stale action cannot change an active search.
    assert app.psbt_search_first == 0
    for _ in range(15):
        app._advance_psbt_search()
    _tap(app, "psbt-search-stop")
    assert job.done and not job.creators
    assert not app.psbt_search_active()
    assert app.screen == "address-search"
    assert app.render().getpixel((30, 730)) == BLUE
    _tap(app, "psbt-search-start")
    job = app.psbt_search
    _tap(app, "back")
    assert job.done and app.screen == "psbt-yaml"
    assert not app.psbt_search_active()


def test_result_is_applied_to_the_original_psbt_output_after_search():
    app = App()
    app.session = _native()
    app.wallet_index = 0
    psbt = _psbt(app.session)
    target = app.session.addresses(0, 1, 61, 1)[0]
    psbt.outputs[0].script_pubkey = Script.from_address(target)
    app._accept_psbt_text(psbt.serialize(), "file")
    app._act("psbt-search-0-0")
    app.psbt_search_first = app.psbt_search_last = 0
    app.psbt_search_start = 60
    _tap(app, "psbt-search-start")
    while app.psbt_search_active():
        app._advance_psbt_search()
    assert app.screen == "psbt-yaml" and app.confirm == "psbt-found"
    assert app.psbt_search_hit["address_index"] == 61
    assert app.psbt_view["change_outputs"][0]["place"] == "Change Address #61"
    assert next(iter(app.psbt_checked.outputs[0].bip32_derivations.values())).derivation[-2:] == [1, 61]
    app._act("confirm-no")


def test_address_search_saves_screenshots():
    from pathlib import Path

    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_address_search_saves_screenshots"))
    app = _app()
    record.shot(app, "settings")
    _tap(app, "psbt-search-start")
    record.shot(app, "preparing")
    for _ in range(app.psbt_search.creator_count + 1):
        app._advance_psbt_search()
    record.shot(app, "searching")
    app.psbt_search.address_index = MAX_INDEX
    app.psbt_search_first = app.psbt_search_last = app.psbt_search_start = MAX_INDEX
    app._advance_psbt_search()
    record.shot(app, "maximum-index")
    button_top = next(hit["box"][1] for hit in app.hits if hit["action"] == "psbt-search-stop")
    for mark in app.texts:
        left, top, right, bottom = mark["box"]
        assert 0 <= left < right <= 480
        assert bottom < button_top
    _tap(app, "psbt-search-stop")
    record.shot(app, "stopped")
    assert app.psbt_search_last_checked == MAX_INDEX
    app._act("search-field-first-dec")
    record.shot(app, "range-changed")
    assert not any("Last Searched" in mark["text"] for mark in app.texts)


def test_watch_only_singlesig_searches_only_loaded_accounts_for_its_type():
    session = Session()
    session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/4h')})")
    session.add_text(expression(ABANDON, "m/84h/0h/5h"))
    session.add_text(f"tr({expression(ABANDON, 'm/86h/0h/7h')})")
    target = _address(session, (5,), branch=1, index=9)
    search = AddressSearch(session, target, 0, 7, 9, 9)
    assert search.creator_count == 4
    found = _finish(search)
    assert found["account_indexes"] == [5] and found["branch"] == 1
    with pytest.raises(SessionError, match="No loaded wallets"):
        AddressSearch(session, target, 6, 7)


@pytest.mark.parametrize("single_account,message", [(False, "range is too large"), (True, "too many loaded wallets")])
def test_search_capacity_errors_leave_the_settings_available(single_account, message):
    app = _app()
    if single_account:
        app.psbt_search_last = 0
        app.session.wallets *= 257
    else:
        app.psbt_search_last = 256
    _tap(app, "psbt-search-start")
    assert not app.psbt_search_active()
    assert message in app.notice
    assert app.screen == "address-search"
    app._act("dismiss-notice")
    app.render()
    assert "search-field-first-edit" in {hit["action"] for hit in app.hits}


def _search_then_stop(app):
    _tap(app, "psbt-search-start")
    for _ in range(app.psbt_search.creator_count + 1):
        app._advance_psbt_search()
    _tap(app, "psbt-search-stop")
    assert app.psbt_search_last_checked == 0


def test_search_and_stopped_progress_have_centered_labels_and_indexes():
    app = _app()
    _tap(app, "psbt-search-start")
    assert app.psbt_search.last_index is None
    for _ in range(app.psbt_search.creator_count):
        app._advance_psbt_search()
    assert app.psbt_search.last_index is None
    app._advance_psbt_search()
    app.render()

    def centered_progress(label):
        marks = [mark for mark in app.texts if mark["text"] == label]
        assert len(marks) == 1  # The label fits one line.
        label_box = marks[0]["box"]
        index_box = next(mark["box"] for mark in app.texts if mark["text"] == "0")
        assert abs((label_box[0] + label_box[2]) / 2 - 240) < 2
        assert abs((index_box[0] + index_box[2]) / 2 - 240) < 2
        assert label_box[3] < index_box[1]
        assert label_box[3] - label_box[1] <= 32

    centered_progress("Searching Address Index:")
    _tap(app, "psbt-search-stop")
    app.render()
    centered_progress("Last Searched Address Index:")
    assert app.psbt_search_last_checked == 0
    _tap(app, "search-field-start-inc")
    assert app.psbt_search_last_checked == 0  # Only account range changes clear it.
    _tap(app, "psbt-search-start")
    assert app.psbt_search_last_checked is None
    app.render()
    assert not any("Last Searched" in mark["text"] for mark in app.texts)
    _tap(app, "psbt-search-stop")
    app.render()
    assert app.psbt_search_last_checked is None  # Stopped before checking an address.
    assert not any("Last Searched" in mark["text"] for mark in app.texts)


@pytest.mark.parametrize("field,operation,value", [("first", "inc", 1), ("last", "inc", 6),
                                                   ("first", "edit", 1), ("last", "edit", 6)])
def test_changing_either_account_range_value_clears_stopped_progress(field, operation, value):
    app = _app()
    _search_then_stop(app)
    _tap(app, f"search-field-{field}-{operation}")
    if operation == "edit":
        app.account_text = str(value)
        _tap(app, "account-save")
    assert getattr(app, "psbt_search_" + field) == value
    assert app.psbt_search_last_checked is None
    app.render()
    assert not any("Last Searched" in mark["text"] for mark in app.texts)


def test_unchanged_or_invalid_account_range_values_preserve_stopped_progress():
    app = _app()
    _search_then_stop(app)
    assert app._set_search_index("first", 0)
    assert app._set_search_index("last", 5)
    assert not app._set_search_index("last", -1)
    assert app.psbt_search_last_checked == 0


@pytest.mark.parametrize("make_session", [_native, _native_taproot, _mixed_multisig])
def test_each_address_check_derives_exactly_one_child_per_participant(monkeypatch, make_session):
    session = make_session()
    target = session.addresses(0, 1, 9, 1)[0]
    search = AddressSearch(session, target, 0, 5, 7, 8)
    for _ in range(search.creator_count):
        search.step()
    for _, wallet, accounts, branch, creator in search.creators:
        for fingerprint, account, key in zip(wallet.fingerprints, accounts, creator.keys):
            purpose = 48 if wallet.multisig else (86 if wallet.role == "singlesig_taproot" else 84)
            path = f"m/{purpose}h/0h/{account}h" + ("/2h" if wallet.multisig else "") + f"/{branch}"
            assert key.origin.fingerprint == fingerprint
            assert key.origin.derivation == bip32.parse_path(path)
    calls = []
    child = bip32.HDKey.child

    def counted_child(key, index, hardened=False):
        calls.append((key.depth, index, hardened))
        return child(key, index, hardened)

    monkeypatch.setattr(bip32.HDKey, "child", counted_child)
    assert _finish(search) is None
    participants = len(session.wallets[0].fingerprints)
    per_index = search.creator_count * participants
    depth = 5 if session.wallets[0].multisig else 4
    assert calls == [(depth, 7, False)] * per_index + [(depth, 8, False)] * per_index

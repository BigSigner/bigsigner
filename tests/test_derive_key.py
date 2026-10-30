from bigsigner.paths import format_path
from bigsigner.session import _public_for
from bigsigner.ui.app import App, XPUB_ACCOUNT_PREVIEW
from bigsigner.ui.canvas import HEADER, HEIGHT, Frame

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _seed_app():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    return app, added["fingerprint"]


def test_a_seed_offers_three_derive_buttons_and_no_wallet_buttons():
    app, _fingerprint = _seed_app()
    app.scroll["key"] = 10_000
    app.render()
    labels = {hit["label"] for hit in app.hits}
    actions = {hit["action"] for hit in app.hits}
    assert "Derive a Native-Segwit SingleSig Key" in labels
    assert "Derive a Native-Segwit MultiSig Key" in labels
    assert "Derive a Taproot SingleSig Key" in labels
    height = next(hit["box"] for hit in app.hits if hit["action"] == "derive-taproot")
    native = next(hit["box"] for hit in app.hits if hit["action"] == "derive-native")
    multisig = next(hit["box"] for hit in app.hits if hit["action"] == "derive-multisig")
    assert height[3] - height[1] == native[3] - native[1] == multisig[3] - multisig[1]
    assert height[3] - height[1] > Frame().button_height("Derive a Taproot")
    assert "make-xpub-wallet" not in actions
    assert "derive-wallet" not in actions
    assert not any("SingleSig Wallet" in label for label in labels)


def test_the_derive_screen_shows_the_account_selector_and_the_derived_key():
    app, fingerprint = _seed_app()
    app._act("derive-native")
    assert app.screen == "derive"
    assert app.derive_account == 0
    app.render()
    actions = {hit["action"] for hit in app.hits}
    assert "derive-inc" in actions
    assert "derive-dec" not in actions
    assert "derive-edit" in actions
    assert "derive-wallet" in actions
    assert "derive-details" in actions
    assert "delete-key" not in actions
    key = app._derived_key()
    assert format_path(list(key.path)) == "m/84h/0h/0h"
    assert key.xpub.to_string() == _public_for(app.session, fingerprint, app.derive_role, 0).xpub.to_string()
    assert len(app.session.fingerprints[fingerprint].keys) == 1

    app._act("derive-inc")
    assert app.derive_account == 1
    app.render()
    assert "derive-dec" in {hit["action"] for hit in app.hits}
    assert format_path(list(app._derived_key().path)) == "m/84h/0h/1h"

    app._act("derive-edit")
    assert app.screen == "account"
    app._act("account-key-backspace")
    app._act("account-key-4")
    app._act("account-save")
    assert app.screen == "derive"
    assert app.derive_account == 4
    derived = app._derived_key()
    assert format_path(list(derived.path)) == "m/84h/0h/4h"
    assert derived.xpub.to_string() == _public_for(app.session, fingerprint, app.derive_role, 4).xpub.to_string()
    account_zero = _public_for(app.session, fingerprint, app.derive_role, 0).xpub.to_string()
    assert derived.xpub.to_string()[:XPUB_ACCOUNT_PREVIEW] != account_zero[:XPUB_ACCOUNT_PREVIEW]


def test_the_next_account_repaints_only_the_changed_lines(monkeypatch):
    import bigsigner.session as session

    calls = {"n": 0}
    original = session.bip39.mnemonic_to_seed

    def counted(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(session.bip39, "mnemonic_to_seed", counted)
    app, _fingerprint = _seed_app()
    loaded = calls["n"]
    app._act("derive-native")
    app.render()
    app._act("derive-inc")
    app.render()
    app._act("derive-inc")
    app.render()
    assert calls["n"] == loaded
    assert app.derive_account == 2
    top, bottom = app.dirty
    assert top >= HEADER
    assert bottom < HEIGHT
    assert format_path(list(app._derived_key().path)) == "m/84h/0h/2h"


def test_the_account_control_sits_between_the_type_and_the_path():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    account = app._derive_account_box
    path = app._derive_path_box
    assert account[3] <= path[1]
    assert account[1] > HEADER + 80


def test_back_from_the_account_editor_repaints_the_derive_page():
    from bigsigner.ui.canvas import NAVY, WIDTH

    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    app._act("derive-edit")
    app.render()
    assert app.screen == "account"
    back = next(item for item in app.hits if item["action"] == "back")
    app.tap((back["box"][0] + back["box"][2]) // 2, (back["box"][1] + back["box"][3]) // 2)
    image = app.render()
    assert app.screen == "derive"
    assert app.dirty is None
    assert image.getpixel((400, 44))[:3] == NAVY
    assert not any(item["action"] == "account-save" for item in app.hits)
    assert any(item["action"] == "derive-inc" for item in app.hits)


def test_a_slide_on_plus_changes_the_account_and_does_not_scroll():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    app.scroll_max["derive"] = 300
    hit = next(item for item in app.hits if item["action"] == "derive-inc")
    x = (hit["box"][0] + hit["box"][2]) // 2
    y = (hit["box"][1] + hit["box"][3]) // 2
    app.pointer_down(x, y)
    app.pointer_move(x, y + 90)
    app.pointer_up(x, y + 90)
    assert app.derive_account == 1
    assert app.scroll.get("derive", 0) == 0


def test_a_short_move_stays_a_click_and_a_long_move_scrolls():
    app = App()
    app.screen = "keys"
    app.render()
    app.scroll_max["keys"] = 400
    app.pointer_down(200, 400)
    assert app.pointer_move(200, 388) is False
    app.pointer_up(200, 388)
    assert app.scroll.get("keys", 0) == 0
    app.pointer_down(200, 400)
    assert app.pointer_move(200, 280)
    assert app.scroll["keys"] == 120


def test_a_drag_that_returns_stays_a_scroll():
    app = App()
    app.screen = "keys"
    app.render()
    app.scroll_max["keys"] = 400
    app.pointer_down(200, 400)
    assert app.pointer_move(200, 250)
    app.pointer_move(200, 390)
    app.pointer_up(200, 390)
    assert app.screen == "keys"
    assert app.scroll["keys"] == 10


def test_a_drag_on_the_account_number_scrolls_the_page():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    box = app._derive_account_box
    x = (box[0] + box[2]) // 2
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    app.pointer_move(x, y - 80)
    app.pointer_up(x, y - 80)
    assert app.screen == "derive"
    assert app.derive_account == 0
    assert app.scroll["derive"] == 80


def test_a_long_hold_on_the_account_number_does_not_open_it():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    box = app._derive_account_box
    x = (box[0] + box[2]) // 2
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    app._press_at -= 1
    app.pointer_up(x, y)
    assert app.screen == "derive"
    assert app.derive_account == 0


def test_a_quiet_press_on_the_account_number_opens_it():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    box = app._derive_account_box
    x = (box[0] + box[2]) // 2
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    app._press_last -= 1
    assert app.pointer_idle()
    assert app.screen == "account"


def test_the_account_field_stays_under_the_title():
    from bigsigner.ui.canvas import NAVY, WIDTH

    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app._act("derive-inc")
    app.scroll["derive"] = 180
    app.render()
    app._act("derive-inc")
    image = app.render()
    assert image.getpixel((WIDTH // 2, 30))[:3] == NAVY
    assert image.getpixel((WIDTH // 2, 70))[:3] == NAVY


def test_a_press_just_above_plus_still_raises_the_account():
    app, _fingerprint = _seed_app()
    app._act("derive-native")
    app.render()
    drawn = max(hit["box"][1] for hit in app.hits if hit["action"] == "derive-inc")
    app.tap(428, drawn - 10)
    assert app.derive_account == 1


def test_a_singlesig_derivation_creates_a_wallet_at_the_selected_account():
    app, fingerprint = _seed_app()
    app._act("derive-native")
    app._act("derive-inc")
    app._act("derive-inc")
    app._act("derive-wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].accounts[fingerprint] == 2
    assert "/2h" in app.session.descriptor_text(0)
    assert app.session.fingerprints[fingerprint].keys[0].has_seed
    assert len(app.session.fingerprints[fingerprint].keys) == 1

    app.back_one()
    assert app.screen == "wallets"
    assert app.back == []
    app.screen = "key"
    app._act("derive-native")
    app.render()
    assert any(hit["label"] == "Go to Native-Segwit SingleSig Wallet" for hit in app.hits)
    app._act("derive-wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].accounts[fingerprint] == 2


def test_multisig_and_taproot_use_their_own_paths_and_only_singlesig_creates_a_wallet():
    app, fingerprint = _seed_app()
    app._act("derive-multisig")
    app.render()
    assert format_path(list(app._derived_key().path)) == "m/48h/0h/0h/2h"
    assert "derive-wallet" not in {hit["action"] for hit in app.hits}
    assert "delete-key" not in {hit["action"] for hit in app.hits}
    app._act("derive-details")
    assert app.screen == "qr"
    assert app.qr_kind == "key"
    payload = app._key_qr_formats()[0][1]
    assert "48h/0h/0h/2h" in payload
    assert app._derived_key().xpub.to_string() in payload
    assert "abandon" not in payload

    app.back_one()
    app.back_one()
    app._act("derive-taproot")
    assert format_path(list(app._derived_key().path)) == "m/86h/0h/0h"
    app.render()
    assert "derive-wallet" in {hit["action"] for hit in app.hits}
    app._act("derive-wallet")
    assert app.session.wallets[0].accounts[fingerprint] == 0
    assert app.session.descriptor_text(0).startswith("tr(")

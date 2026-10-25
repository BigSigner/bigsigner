from bigsigner.paths import format_path
from bigsigner.session import _public_for
from bigsigner.ui.app import App, XPUB_ACCOUNT_PREVIEW
from bigsigner.ui.canvas import Frame

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
    assert "Derive a Native-Segwit SingleSig key" in labels
    assert "Derive a Native-Segwit MultiSig key" in labels
    assert "Derive a Taproot SingleSig key" in labels
    height = next(hit["box"] for hit in app.hits if hit["action"] == "derive-taproot")
    native = next(hit["box"] for hit in app.hits if hit["action"] == "derive-native")
    multisig = next(hit["box"] for hit in app.hits if hit["action"] == "derive-multisig")
    assert height[3] - height[1] == native[3] - native[1] == multisig[3] - multisig[1]
    assert height[3] - height[1] > Frame().button_height("Derive a Taproot")
    assert "make-xpub-wallet" not in actions
    assert "derive-wallet" not in actions
    assert not any(label.startswith("Create a SingleSig") or label.startswith("Go to SingleSig") for label in labels)


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


def test_a_singlesig_derivation_creates_a_wallet_at_the_selected_account():
    app, fingerprint = _seed_app()
    app._act("derive-native")
    app._act("derive-inc")
    app._act("derive-inc")
    app._act("derive-wallet")
    assert app.screen == "wallet"
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].accounts[fingerprint] == 2
    assert "/2h" in app.session.descriptor_text(0)
    assert app.session.fingerprints[fingerprint].keys[0].has_seed
    assert len(app.session.fingerprints[fingerprint].keys) == 1

    app.back_one()
    app.render()
    assert any(hit["label"] == "Go to SingleSig\nNative Segwit wallet" for hit in app.hits)
    app._act("derive-wallet")
    assert app.screen == "wallet"
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

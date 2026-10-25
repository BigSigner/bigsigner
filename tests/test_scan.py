from bigsigner.seedqr import compact_bytes, standard_digits
from bigsigner.ui.app import App

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _open_scan():
    app = App()
    app.screen = "keys"
    app.render()
    _tap(app, "plus")
    _tap(app, "Scan QR code")
    assert app.screen == "scan"
    assert "not available" not in app.notice
    return app


def _tap(app, label):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(label)


def test_plus_menu_opens_the_scan_screen():
    app = _open_scan()
    app.render()


def test_scanned_words_and_seedqr_open_the_key():
    app = _open_scan()
    app.accept_qr(ABANDON)
    assert app.screen == "key"
    assert app.notice == "The seed was added successfully."

    other = _open_scan()
    other.accept_qr(standard_digits(ABANDON))
    assert other.screen == "key"
    assert next(iter(other.session.fingerprints)) == next(iter(app.session.fingerprints))

    compact = _open_scan()
    compact.accept_qr(compact_bytes(ABANDON).decode("latin-1"))
    assert compact.screen == "key"


def test_scanned_transaction_or_unknown_text_opens_an_error_screen():
    app = _open_scan()
    app.accept_qr("cHNidP8BAH0CAAAA")
    assert app.screen == "load-error"
    assert app.load_error == "That QR code is a transaction, not a key."
    assert app.notice == ""
    _tap(app, "OK")
    assert app.screen == "keys"

    app = _open_scan()
    app.accept_qr("https://example.com")
    assert app.screen == "load-error"
    assert app.load_error == "That QR code is not a seed, key expression or wallet descriptor."
    _tap(app, "OK")
    assert app.screen == "keys"


def test_key_scan_offers_a_multisig_descriptor_choice():
    from bigsigner.parse import parse_wallet

    source = App()
    first = source.session.add_mnemonic(ABANDON)
    second = source.session.add_mnemonic(ABANDON, passphrase="second")
    source.screen = "multisig"
    source.multisig_m = 2
    source.multisig_selected = {first["fingerprint"], second["fingerprint"]}
    source._create_selected_multisig()
    descriptor = source.session.descriptor_text(source.wallet_index)
    parsed = parse_wallet(descriptor, "main")
    expected = [f"{key.fingerprint.hex()} {key.canonical[:10]}..." for key in parsed.keys]
    app = App()
    app.screen = "scan"
    app.scan_kind = "key"
    app.accept_qr(descriptor)
    assert app.screen == "descriptor-choice"
    assert app.confirm is None
    assert app.load_error == ""
    assert "Bitcoin Wallets" not in app._descriptor_choice_message()
    assert app._descriptor_choice_message().startswith("This is a multisig wallet descriptor.")
    assert app.descriptor_choice["labels"] == expected
    assert app.session.wallets == []
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert "Both Wallet And All Keys" in labels
    assert "Load Selected Key" in labels
    _tap(app, "dropdown-descriptor-key")
    assert app.open_dropdown == "descriptor-key"
    app.render()
    shown = {hit["label"] for hit in app.hits}
    assert expected[0] in shown and expected[1] in shown
    _tap(app, "dropdown-pick-descriptor-key-1")
    assert app.descriptor_key_index == 1
    assert app.open_dropdown is None
    _tap(app, "Load Selected Key")
    assert app.screen == "external-review"
    assert app.wallet_plan is None
    assert app.pending_external.fingerprint == parsed.keys[1].fingerprint
    assert app.session.wallets == []

    both = App()
    both.screen = "scan"
    both.scan_kind = "key"
    both.accept_qr(descriptor)
    _tap(both, "Both Wallet And All Keys")
    assert both.screen == "external-review"
    assert both.wallet_plan is not None
    assert both.back == ["wallets"]


def test_an_unsupported_descriptor_from_keys_opens_an_error_screen():
    from test_domain import expression

    descriptor = f"sh(wpkh({expression(ABANDON, 'm/84h/0h/0h')}))"
    app = _open_scan()
    app.accept_qr(descriptor)
    assert app.screen == "load-error"
    assert "not supported" in app.load_error
    assert "Bitcoin Wallets" not in app.load_error
    assert app.session.wallets == []
    assert not app.session.fingerprints
    _tap(app, "OK")
    assert app.screen == "keys"


def test_a_qr_is_ignored_after_leaving_the_scan_screen():
    app = _open_scan()
    app.back_one()
    app.accept_qr(ABANDON)
    assert app.screen == "keys"
    assert not app.session.fingerprints

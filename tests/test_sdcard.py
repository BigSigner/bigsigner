import pytest

from bigsigner.sdcard import SdError, list_folder, read_text, write_text
from test_domain import LEGAL, expression
from bigsigner.ui.app import App

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _tap(app, label):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(label)


def test_sd_card_folder_lists_subdirectories_and_loads_a_seed(tmp_path, monkeypatch):
    seeds = tmp_path / "seeds"
    nested = seeds / "nested"
    nested.mkdir(parents=True)
    (seeds / "abandon.txt").write_text(f"\n  {ABANDON}\n")
    (nested / "note.txt").write_text("hello")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))

    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD card")
    assert app.screen == "sd"
    app.render()
    assert any(hit["label"] == "seeds/" for hit in app.hits)
    _tap(app, "seeds/")
    assert app.sd_dir == "seeds"
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert ".." in labels
    assert "abandon.txt" in labels
    assert "nested/" in labels
    _tap(app, "nested/")
    assert app.sd_dir == "seeds/nested"
    _tap(app, "..")
    assert app.sd_dir == "seeds"
    _tap(app, "abandon.txt")
    assert app.screen == "key"
    assert app.notice == "The seed was added successfully."
    saved = next(iter(app.session.fingerprints.values()))
    assert " ".join(saved.keys[0].mnemonic) == ABANDON


def test_a_file_that_is_not_a_key_opens_an_error_screen(tmp_path, monkeypatch):
    (tmp_path / "note.txt").write_text("hello from the card")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD card")
    _tap(app, "note.txt")
    assert app.screen == "load-error"
    assert app.load_error == "That file is not a seed, key expression or wallet descriptor."
    assert app.notice == ""
    assert not app.session.fingerprints
    _tap(app, "OK")
    assert app.screen == "keys"


def test_missing_sd_card_path_is_reported(monkeypatch):
    monkeypatch.delenv("BIGSIGNER_SDCARD_PATH", raising=False)
    app = App()
    app.screen = "sd"
    app.render()
    assert app.screen == "sd"
    try:
        list_folder("")
    except SdError as exc:
        assert "No SD card" in str(exc)
    else:
        raise AssertionError("A missing card should be reported.")


def test_reading_outside_the_card_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    secret = tmp_path.parent / "secret.txt"
    secret.write_text("nope")
    try:
        read_text("../secret.txt")
    except SdError as exc:
        assert "outside" in str(exc)
    else:
        raise AssertionError("A path outside the card should be refused.")
    secret.unlink()


def test_a_singlesig_descriptor_from_keys_asks_before_loading_both(tmp_path, monkeypatch):
    from test_domain import expression

    descriptor = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    (tmp_path / "wallet.txt").write_text(descriptor + "\n")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD card")
    _tap(app, "wallet.txt")
    assert app.screen == "descriptor-choice"
    assert app.confirm is None
    assert app.session.wallets == []
    assert not app.session.fingerprints
    assert app._descriptor_choice_message() == (
        "This is a singlesig wallet descriptor. "
        "Do you want to load both the wallet and the key, or only the key?"
    )
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert "Both Wallet And Key" in labels
    assert "Only The Key" in labels
    app.back_one()
    assert app.screen == "sd"
    assert app.session.wallets == []
    _tap(app, "wallet.txt")
    _tap(app, "Only The Key")
    assert app.screen == "external-review"
    assert app.wallet_plan is None
    assert app.pending_external is not None
    _tap(app, "external-next")
    _tap(app, "external-continue")
    assert app.screen == "key"
    assert not app.session.wallets
    assert app.selected_fp in app.session.fingerprints

    both = App()
    both.screen = "keys"
    _tap(both, "plus")
    _tap(both, "Load from SD card")
    _tap(both, "wallet.txt")
    _tap(both, "Both Wallet And Key")
    assert both.screen == "external-review"
    assert both.wallet_plan is not None
    assert both.back == ["wallets"]
    _tap(both, "external-next")
    _tap(both, "external-continue")
    assert both.screen == "wallet"
    assert both.session.wallets

    scanned = App()
    scanned.screen = "scan"
    scanned.scan_kind = "key"
    scanned.accept_qr(descriptor)
    assert scanned.screen == "descriptor-choice"
    assert scanned._descriptor_choice_message().startswith("This is a singlesig wallet descriptor.")
    _tap(scanned, "Only The Key")
    assert scanned.screen == "external-review"
    assert scanned.wallet_plan is None


def test_descriptor_load_rejects_a_seed_file(tmp_path, monkeypatch):
    (tmp_path / "seed.txt").write_text(ABANDON)
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.screen = "wallets"
    _tap(app, "plus")
    _tap(app, "Load descriptor from SD card")
    assert app.sd_expect == "descriptor"
    _tap(app, "seed.txt")
    assert app.screen == "load-error"
    assert app.load_error == "This is a seed, not a wallet descriptor."
    _tap(app, "OK")
    assert app.screen == "wallets"


def test_write_text_stays_on_the_card(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    write_text("note.txt", "hello")
    assert (tmp_path / "note.txt").read_text() == "hello\n"
    with pytest.raises(SdError):
        write_text("../note.txt", "nope")


def test_export_to_sd_card_chooses_a_format_then_a_file(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    (tmp_path / "old.txt").write_text("old\n")
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    fingerprint = added["fingerprint"]
    app.selected_fp = fingerprint
    app.screen = "key"
    app._act("derive-native")
    app.scroll["derive"] = 10_000
    app.render()
    shown = [hit["label"] for hit in app.hits if hit["action"] in ("derive-details", "export-derived")]
    assert shown == ["Show Full Details", "Export to SD Card"]
    assert "delete-key" not in {hit["action"] for hit in app.hits}

    app._act("export-derived")
    assert app.screen == "export-format"
    app.render()
    names = [hit["label"] for hit in app.hits if str(hit["action"]).startswith("export-format-")]
    assert names == ["Key Expression", "xpub only", "zpub"]

    app._act("export-format-2")
    assert app.screen == "sd"
    app.render()
    assert "New file" in {hit["label"] for hit in app.hits}
    app._act("sd-write:old.txt")
    assert app.confirm == "replace-file"
    assert app._confirm_message() == 'Replace "old.txt"?'
    app._act("confirm-yes")
    assert app.screen == "derive"
    assert (tmp_path / "old.txt").read_text().startswith("zpub")

    app._act("export-derived")
    app._act("export-format-0")
    app._act("export-new")
    assert app.screen == "export-name"
    assert app.filename == f"{fingerprint.hex()}-key-expression.txt"
    app._act("export-save-new")
    body = (tmp_path / app.filename).read_text().strip()
    assert body.startswith(f"[{fingerprint.hex()}/84h/0h/0h]xpub")
    assert body.endswith("/<0;1>/*")
    assert app.screen == "derive"
    app.back_one()
    assert app.screen == "key"
    app._act("derive-taproot")
    app._act("export-derived")
    app.render()
    taproot = [hit["label"] for hit in app.hits if str(hit["action"]).startswith("export-format-")]
    assert taproot[0] == "Key Expression"
    assert "zpub" not in taproot

    external = app.session.add_text(expression(LEGAL, "m/84h/0h/0h"))
    app.selected_fp = external["fingerprint"]
    app.screen = "key"
    app.scroll["key"] = 10_000
    app.render()
    buttons = [
        (hit["box"][1], hit["label"])
        for hit in app.hits
        if hit["action"] in ("show-qr", "export-key", "delete-key")
    ]
    assert [label for _top, label in sorted(buttons)] == ["Show Full Details", "Export to SD Card", "Delete Key"]

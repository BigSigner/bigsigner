import pytest

from bigsigner.sdcard import (
    SdError,
    consume_memory_change,
    list_folder,
    mount_memory,
    read_text,
    unmount_memory,
    write_text,
)
from test_domain import LEGAL, expression
from bigsigner.ui.app import App


@pytest.fixture(autouse=True)
def _no_memory_card():
    unmount_memory()
    yield
    unmount_memory()

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _tap(app, label):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(label)


def test_sd_card_folder_lists_subdirectories_and_loads_a_seed():
    mount_memory(
        {
            "files": {
                "seeds/abandon.txt": f"\n  {ABANDON}\n",
                "seeds/nested/note.txt": "hello",
            }
        }
    )

    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
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


def test_a_file_that_is_not_a_key_opens_an_error_screen():
    mount_memory({"files": {"note.txt": "hello from the card\n"}})
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
    _tap(app, "note.txt")
    assert app.screen == "load-error"
    assert app.load_error == "That file is not a seed, key expression or wallet descriptor."
    assert app.notice == ""
    assert not app.session.fingerprints
    _tap(app, "OK")
    assert app.screen == "keys"


def test_a_missing_card_is_reported():
    app = App()
    app.screen = "sd"
    app.render()
    assert app.screen == "sd"
    with pytest.raises(SdError, match="No SD card"):
        list_folder("")


def test_reading_outside_the_card_is_refused():
    mount_memory({"files": {}})
    with pytest.raises(SdError, match="outside"):
        read_text("../secret.txt")


def test_a_singlesig_descriptor_from_keys_asks_before_loading_both():
    from test_domain import expression

    descriptor = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    mount_memory({"files": {"wallet.txt": descriptor + "\n"}})
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
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
    assert "Both Wallet and Key" in labels
    assert "Only the Key" in labels
    app.back_one()
    assert app.screen == "sd"
    assert app.session.wallets == []
    _tap(app, "wallet.txt")
    _tap(app, "Only the Key")
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
    _tap(both, "Load from SD Card")
    _tap(both, "wallet.txt")
    _tap(both, "Both Wallet and Key")
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
    _tap(scanned, "Only the Key")
    assert scanned.screen == "external-review"
    assert scanned.wallet_plan is None


def test_descriptor_load_rejects_a_seed_file():
    mount_memory({"files": {"seed.txt": ABANDON + "\n"}})
    app = App()
    app.screen = "wallets"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
    assert app.sd_expect == "descriptor"
    _tap(app, "seed.txt")
    assert app.screen == "load-error"
    assert app.load_error == "This is a seed, not a wallet descriptor."
    _tap(app, "OK")
    assert app.screen == "wallets"


def test_write_text_stays_on_the_card():
    mount_memory({"files": {}})
    write_text("note.txt", "hello")
    assert read_text("note.txt") == "hello"
    with pytest.raises(SdError):
        write_text("../note.txt", "nope")


def test_export_to_sd_card_chooses_a_format_then_a_file():
    mount_memory({"files": {"old.txt": "old\n"}})
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
    assert "New File" in {hit["label"] for hit in app.hits}
    app._act("sd-write:old.txt")
    assert app.confirm == "replace-file"
    assert app._confirm_message() == 'Replace "old.txt"?'
    app._act("confirm-yes")
    assert app.screen == "derive"
    assert read_text("old.txt").startswith("zpub")

    app._act("export-derived")
    app._act("export-format-0")
    app._act("export-new")
    assert app.screen == "export-name"
    assert app.filename == f"{fingerprint.hex()}-key-expression.txt"
    app._act("export-save-new")
    body = read_text(app.filename)
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


def test_a_long_filename_wraps_at_the_overflowing_character():
    from PIL import ImageDraw

    from bigsigner.ui.app import _filename_lines
    from bigsigner.ui.canvas import MARGIN, TITLE_SIZE, WIDTH, font

    short = "hello.txt"
    spaced = "My SeedSigner Trezor " + "backup" * 8 + ".txt"
    huge = "multisig-key-expression-" + "x" * 90 + ".txt"
    mount_memory({"files": {name: "hello\n" for name in (short, spaced, huge)}})
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
    image = app.render()
    draw = ImageDraw.Draw(image)
    face = font(TITLE_SIZE)
    width = WIDTH - 2 * MARGIN - 32
    short_lines = _filename_lines(draw, short, face, width)
    spaced_lines = _filename_lines(draw, spaced, face, width)
    huge_lines = _filename_lines(draw, huge, face, width)
    assert short_lines == [short]
    assert len(spaced_lines) > 1
    _assert_packed(draw, face, width, spaced, spaced_lines)
    assert len(huge_lines) == 3
    assert huge_lines[-1].endswith("\u2026")
    _assert_packed(draw, face, width, huge, huge_lines)
    boxes = {hit["label"]: hit["box"] for hit in app.hits}
    assert boxes[short][3] - boxes[short][1] == 76
    assert boxes[spaced][3] - boxes[spaced][1] > boxes[short][3] - boxes[short][1]
    assert boxes[huge][3] - boxes[huge][1] >= boxes[spaced][3] - boxes[spaced][1]
    _tap(app, huge)
    assert app.screen == "load-error"


def _assert_packed(draw, face, width, text, lines):
    consumed = 0
    for index, line in enumerate(lines):
        assert draw.textlength(line, font=face) <= width
        last = index == len(lines) - 1 and line.endswith("\u2026")
        body = line[:-1] if last else line
        assert text.startswith(body, consumed)
        consumed += len(body)
        if last:
            assert consumed < len(text)
            assert draw.textlength(body + text[consumed] + "\u2026", font=face) > width
            continue
        if consumed < len(text):
            assert draw.textlength(line + text[consumed], font=face) > width
    if not lines[-1].endswith("\u2026"):
        assert consumed == len(text)


def test_an_empty_memory_card_is_inserted():
    mount_memory({"dirs": [], "files": {}})
    assert list_folder("") == []
    app = App()
    app.screen = "sd"
    app.render()
    assert app.screen == "sd"


def test_a_memory_card_lists_folders_and_loads_a_seed():
    mount_memory({"files": {"seeds/nested/note.txt": "hello\n", "seeds/abandon.txt": ABANDON + "\n"}})
    assert list_folder("") == [{"name": "seeds", "kind": "dir"}]
    assert list_folder("seeds") == [
        {"name": "nested", "kind": "dir"},
        {"name": "abandon.txt", "kind": "file"},
    ]
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD Card")
    _tap(app, "seeds/")
    _tap(app, "abandon.txt")
    assert app.screen == "key"
    assert app.notice == "The seed was added successfully."


def test_write_text_on_a_memory_card_is_reported_once():
    mount_memory({"dirs": ["keep"], "files": {}})
    assert consume_memory_change() is None
    write_text("keep/note.txt", "hello")
    assert read_text("keep/note.txt") == "hello"
    changed = consume_memory_change()
    assert changed["files"]["keep/note.txt"] == "hello\n"
    assert "keep" in changed["dirs"]
    assert consume_memory_change() is None
    with pytest.raises(SdError):
        write_text("missing/note.txt", "nope")
    with pytest.raises(SdError):
        write_text("../note.txt", "nope")
    assert consume_memory_change() is None


def test_memory_card_rejects_a_bad_shape():
    with pytest.raises(SdError):
        mount_memory({"dirs": "seeds", "files": {}})


def test_export_seed_writes_words_that_load_from_the_card():
    mount_memory({"files": {}})
    app = App()
    added = app.session.add_mnemonic(ABANDON.split(), passphrase="secret")
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app.scroll["key"] = 10_000
    app.render()
    tops = {hit["label"]: hit["box"][1] for hit in app.hits}
    assert tops["Show Seed"] < tops["Show Passphrase"] < tops["Export Seed to SD Card"]
    assert tops["Export Seed to SD Card"] < tops["Derive an Extended Public Key"]
    assert tops["Derive an Extended Public Key"] < tops["Create a Copy of This Seed with a Different Passphrase"]
    assert tops["Create a Copy of This Seed with a Different Passphrase"] < tops["Derive a BIP85 Child Seed"]
    app._act("export-seed")
    assert app.screen == "seed-backup"
    app.render()
    assert any(hit["label"] == "Continue" for hit in app.hits)
    app._act("seed-backup-continue")
    assert app.screen == "sd"
    app._act("export-new")
    assert app.filename == f"{added['fingerprint'].hex()}-seed.txt"
    app._act("export-save-new")
    body = read_text(app.filename)
    assert body == ABANDON
    assert "secret" not in body
    assert app.screen == "key"

    write_text("spaced.txt", "  " + ABANDON.replace(" ", "\n"))
    fresh = App()
    fresh.screen = "keys"
    _tap(fresh, "plus")
    _tap(fresh, "Load from SD Card")
    _tap(fresh, app.filename)
    assert fresh.notice == "The seed was added successfully."
    again = App()
    again.screen = "keys"
    _tap(again, "plus")
    _tap(again, "Load from SD Card")
    _tap(again, "spaced.txt")
    assert again.notice == "The seed was added successfully."


def test_a_long_filename_scrolls_sideways():
    app = App()
    app.screen = "export-name"
    name = "native-segwit-singlesig-wallet-export.bsms"
    app.filename = name
    app.filename_cursor = len(name)
    app.render()
    assert app.hscroll == app.hscroll_max > 0
    box = app._hscroll_box
    y = (box[1] + box[3]) // 2
    before = app.hscroll
    app.pointer_down(box[0] + 40, y)
    assert app.pointer_move(box[2] - 40, y)
    assert app.hscroll < before
    app.pointer_up(box[2] - 40, y)
    assert app.filename_cursor == len(name)
    app.render()
    app.pointer_down(box[2] - 24, y)
    app.pointer_up(box[2] - 24, y)
    assert app.filename_cursor < len(name)

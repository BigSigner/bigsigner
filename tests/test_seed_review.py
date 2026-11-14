"""Imported words are reviewed before choosing a passphrase and loading a seed."""

from pathlib import Path

import pytest
from embit.bip39 import mnemonic_from_bytes

from bigsigner.sdcard import mount_memory
from bigsigner.seedqr import compact_bytes, standard_digits
from bigsigner.session import Session
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEIGHT, WIDTH
from test_sdcard import _tap


def _open_review(words, source):
    app = App()
    app.screen = "keys"
    if source == "file":
        mount_memory({"files": {"seed.txt": words}})
        app._act("add-sd")
        _tap(app, "SD Card")
        _tap(app, "seed.txt")
    else:
        app._act("add-scan")
        payload = words
        if source == "numeric":
            payload = standard_digits(words)
        elif source == "compact":
            payload = compact_bytes(words).decode("latin-1")
        app.accept_qr(payload)
    return app


@pytest.mark.parametrize("count", [12, 18, 24])
@pytest.mark.parametrize("source", ["file", "words", "numeric", "compact"])
def test_imported_seed_reviews_all_words_and_starts_at_the_bottom(count, source):
    words = mnemonic_from_bytes(bytes(count * 4 // 3))
    app = _open_review(words, source)
    app.render()
    assert app.screen == "seed-review"
    assert app.seed_words == words.split()
    assert not app.session.fingerprints
    assert app.seed_grid_scroll == app.seed_grid_max > 0
    assert any(item["text"] == f"{count} Words Seed" for item in app.texts)
    assert any(hit["label"] == "Continue" for hit in app.hits)
    assert not any(hit["action"] == "dropdown-seed-length" for hit in app.hits)
    assert app.camera_preview_box() is None


@pytest.mark.parametrize("passphrase", [None, "reviewed phrase"])
@pytest.mark.parametrize("source", ["file", "words"])
def test_imported_seed_loads_only_after_its_passphrase_choice(source, passphrase):
    words = mnemonic_from_bytes(bytes(16))
    app = _open_review(words, source)
    _tap(app, "Continue")
    assert app.screen == "passphrase-ask"
    assert not app.session.fingerprints
    if passphrase is None:
        _tap(app, "No Passphrase")
    else:
        _tap(app, "Enter a Passphrase")
        app.passphrase_text = passphrase
        _tap(app, "Save Passphrase")
    assert app.screen == "key"
    expected = Session().add_mnemonic(words, passphrase)["fingerprint"]
    assert app.selected_fp == expected
    seed = app.session.fingerprints[expected].keys[0]
    assert seed.mnemonic == words.split()
    assert seed.passphrase == passphrase


def test_imported_words_scroll_without_moving_the_heading_or_continue():
    app = _open_review(mnemonic_from_bytes(bytes(32)), "words")
    bottom = app.render()
    label = next(item for item in app.texts if item["text"] == "24 Words Seed")
    button = next(hit for hit in app.hits if hit["label"] == "Continue")
    box = app.seed_grid_box
    x, y = 50, (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y + 120)
    app.pointer_up(x, y + 120)
    earlier = app.render()
    assert 0 <= app.seed_grid_scroll < app.seed_grid_max
    assert bottom.tobytes() != earlier.tobytes()
    assert label == next(item for item in app.texts if item["text"] == "24 Words Seed")
    assert button == next(hit for hit in app.hits if hit["label"] == "Continue")


@pytest.mark.parametrize("source,origin", [("file", "sd"), ("words", "scan")])
def test_back_from_passphrase_keeps_words_and_back_from_review_returns_to_source(source, origin):
    words = mnemonic_from_bytes(bytes(16))
    app = _open_review(words, source)
    _tap(app, "Continue")
    _tap(app, "back")
    assert app.screen == "seed-review" and app.seed_words == words.split()
    _tap(app, "back")
    assert app.screen == origin
    assert not app.session.fingerprints


def test_imported_seed_review_saves_screenshots():
    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_imported_seed_review_saves_screenshots"))
    for count, source in ((12, "file"), (24, "words")):
        app = _open_review(mnemonic_from_bytes(bytes(count * 4 // 3)), source)
        record.shot(app, f"{count}-words-bottom")
        app.seed_grid_stick = False
        app.seed_grid_scroll = 0
        record.shot(app, f"{count}-words-top")
        _tap(app, "Continue")
        record.shot(app, f"{count}-passphrase-choice")
        for item in app.texts:
            left, top, right, bottom = item["box"]
            assert 0 <= left < right <= WIDTH and 0 <= top < bottom <= HEIGHT

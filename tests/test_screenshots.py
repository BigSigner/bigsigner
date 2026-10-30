"""Flows recorded as screenshots. Steps done in code get a pink note frame."""

from embit.psbt import DerivationPath, PSBT
from embit.script import Script, address_to_scriptpubkey
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.psbt_review import review_psbt
from bigsigner.session import _account_path, _derive_public
from bigsigner.ui.app import (
    QR_BRIGHTNESS_DEFAULT,
    QR_BRIGHTNESS_MAX,
    App,
    _qr_light,
    load_psbt,
)
from PIL import Image

from bigsigner.ui.canvas import HEADER, HEIGHT, MARGIN, NAVY, PAPER, WIDTH
from test_ui import ABANDON, PINK, ScreenRecord, tap

RED = (168, 36, 42)


def type_word(app, word, record=None, shot_name=None):
    """Tap letters until the word itself is offered, then tap that word."""
    for _letter in word:
        app.render()
        labels = {hit["label"] for hit in app.hits}
        if word in labels and len(app._seed_matches()) <= 6:
            if record is not None and shot_name:
                record.shot(app, shot_name)
            tap(app, word)
            return
        tap(app, _letter)
    raise AssertionError(f"Could not enter {word}.")


def test_key_list_scroll_saves_screenshots():
    from embit.bip39 import mnemonic_from_bytes

    app = App()
    app.screen = "keys"
    record = ScreenRecord(__folder("test_key_list_scroll_saves_screenshots"))
    for index in range(8):
        app.session.add_mnemonic(mnemonic_from_bytes(bytes([index + 1]) + b"\x5a" * 15).split())
    record.note("Added 8 seeds in code and opened Bitcoin Keys.")
    record.shot(app, "keys")
    start = (200, 520)
    end = (200, 280)
    record.drag(app, start, end)
    assert app.scroll.get("keys", 0) > 0
    def marked(name, point):
        hits = []
        for path in sorted(record.folder.glob(f"*-{name}.png")):
            image = Image.open(path)
            if image.getpixel(point)[:3] == PINK:
                hits.append(image)
        assert len(hits) == 1
        return hits[0]

    down_marked = marked("scroll-down", start)
    up_marked = marked("scroll-up", end)
    assert down_marked.getpixel(end)[:3] != PINK
    assert up_marked.getpixel(start)[:3] != PINK
    assert list(down_marked.getdata()) != list(up_marked.getdata())


def test_manual_seed_entry_saves_screenshots():
    app = _keys(None)
    record = ScreenRecord(__folder("test_manual_seed_entry_saves_screenshots"))
    record.note("Opened Bitcoin Keys in code.")
    record.shot(app, "keys")
    record.click(app, "plus")
    record.shot(app, "add-menu")
    record.click(app, "Manual Entry")
    record.shot(app, "keyboard")
    app.seed_length = 12
    type_word(app, "abandon", record, "suggestions")
    for _ in range(10):
        type_word(app, "abandon")
    record.shot(app, "checksum")
    type_word(app, "about")
    record.shot(app, "passphrase-ask")
    record.click(app, "No Passphrase")
    record.shot(app, "saved")
    assert app.screen == "key"
    assert app.notice == "The seed was added successfully."
    saved = next(iter(app.session.fingerprints.values()))
    assert " ".join(saved.keys[0].mnemonic) == ABANDON
    assert (record.folder / "index.html").is_file()


def test_duplicate_seed_warning_saves_screenshots():
    app = _keys(ABANDON)
    record = ScreenRecord(__folder("test_duplicate_seed_warning_saves_screenshots"))
    app.screen = "seed"
    app.seed_length = 12
    app.seed_words = ["abandon"] * 11
    record.note(
        "Loaded the Abandon seed in code, opened manual entry, and filled the first 11 words in code."
    )
    record.shot(app, "checksum")
    type_word(app, "about")
    record.shot(app, "passphrase-ask")
    record.click(app, "No Passphrase")
    record.shot(app, "already-loaded")
    assert app.screen == "passphrase-ask"
    assert app.notice == "This seed is already loaded."
    assert _has_color(record.image, (18, 36, 58))


def test_delete_key_warnings_save_screenshots():
    app = _keys(ABANDON)
    record = ScreenRecord(__folder("test_delete_key_warnings_save_screenshots"))
    _open_seed_key(app, record)
    record.click(app, "delete-key")
    record.shot(app, "delete-unused")
    assert app.session.deletion_message(app.selected_fp, 0) == "Delete this key?"
    record.click(app, "Cancel")
    record.click(app, "derive-native")
    record.click(app, "derive-wallet")
    record.click(app, "back")
    record.click(app, "menu")
    record.click(app, "Bitcoin Keys")
    record.click(app, app.session.fingerprints[app.selected_fp].nickname)
    app.notice_until = 0
    record.click(app, "delete-key")
    record.shot(app, "delete-wallet")
    name = app.session.wallet_short_name_of(app.session.wallets[0])
    assert app.session.deletion_message(app.selected_fp, 0) == (
        f'Delete this key? Wallet "{name}" depends on it and will be removed.'
    )


def test_transaction_warnings_save_screenshots():
    app = _keys(ABANDON)
    record = ScreenRecord(__folder("test_transaction_warnings_save_screenshots"))
    _open_seed_key(app, record)
    record.click(app, "derive-native")
    record.click(app, "derive-wallet")
    app.notice_until = 0
    record.note(
        "Loaded a transaction in code. It has an OP_RETURN output, "
        "an input that does not signal replace-by-fee, and a large fee."
    )
    load_psbt(app, _psbt(app, sequence=0xFFFFFFFE, send_sats=50_000, op_return=True))
    record.shot(app, "op-return-and-fee")
    text = " ".join(app.review["warnings"])
    assert "OP_RETURN" in text
    assert "replace-by-fee" in text
    assert "5%" in text
    assert _has_color(record.image, RED)

    record.note("Loaded another transaction in code. One input has a relative locktime.")
    load_psbt(app, _psbt(app, sequence=16, send_sats=99_000, op_return=False))
    record.shot(app, "relative-locktime")
    assert any("BIP68" in warning for warning in app.review["warnings"])
    assert _has_color(record.image, RED)


def test_camera_without_a_picture_saves_screenshots():
    app = _keys(None)
    record = ScreenRecord(__folder("test_camera_without_a_picture_saves_screenshots"))
    record.note("Opened Bitcoin Keys in code.")
    record.shot(app, "keys")
    record.click(app, "plus")
    record.click(app, "Generate New Seed")
    record.shot(app, "generate")
    record.click(app, "Camera")
    record.shot(app, "camera")
    record.click(app, "Capture")
    record.shot(app, "no-picture")
    assert app.notice == "The camera has not captured a picture yet."
    assert _has_color(record.image, (18, 36, 58))


def test_seed_qr_brightness_saves_screenshots():
    app = _keys(ABANDON)
    app.screen = "key"
    app._act("show-seed")
    app._act("confirm-yes")
    app._act("seed-format-next")
    record = ScreenRecord(__folder("test_seed_qr_brightness_saves_screenshots"))
    record.note("Opened the Compact SeedQR seed view in code.")
    record.shot(app, "default")
    default_quiet = _quiet_zone(record.image)
    default_page = record.image.getpixel((8, HEADER + 40))[:3]
    assert default_quiet == default_page == _qr_light(QR_BRIGHTNESS_DEFAULT)
    assert default_quiet != (255, 255, 255)
    record.click(app, "+")
    record.shot(app, "brighter")
    brighter = _quiet_zone(record.image)
    assert brighter == record.image.getpixel((8, HEADER + 40))[:3]
    assert sum(brighter) > sum(default_quiet)
    record.click(app, "+")
    record.shot(app, "brightest")
    assert app.qr_brightness == QR_BRIGHTNESS_MAX
    assert not any(hit["label"] == "+" for hit in app.hits)
    plus = record.image.getpixel((WIDTH - MARGIN - 32, HEIGHT - 252 + 26))[:3]
    assert plus != NAVY
    while app.qr_brightness > 0:
        record.click(app, "-")
    record.shot(app, "darkest")
    darkest = _quiet_zone(record.image)
    assert darkest == record.image.getpixel((8, HEADER + 40))[:3]
    assert sum(darkest) < sum(default_quiet)
    assert not any(hit["label"] == "-" for hit in app.hits)
    record.click(app, "back")
    assert app.screen == "key"
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT
    key = app.render()
    assert key.getpixel((8, HEADER + 40))[:3] == PAPER


def _quiet_zone(image):
    return image.getpixel(((WIDTH - 360) // 2 + 4, HEADER + 16))[:3]


def _keys(mnemonic):
    app = App()
    app.screen = "keys"
    if mnemonic:
        added = app.session.add_mnemonic(mnemonic.split())
        app.selected_fp = added["fingerprint"]
    return app


def _open_seed_key(app, record):
    app.screen = "key"
    app.back = ["keys"]
    record.note("Loaded the Abandon seed in code and opened its key screen.")
    record.shot(app, "key")


def _psbt(app, sequence: int, send_sats: int, op_return: bool) -> bytes:
    receive = app.session.addresses(app.wallet_index, 0, 0, 1)[0]
    script = address_to_scriptpubkey(receive)
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    outputs = [TransactionOutput(send_sats, destination)]
    if op_return:
        outputs.append(TransactionOutput(0, Script(b"\x6a\x05hello")))
    transaction = Transaction(
        version=2,
        vin=[TransactionInput(b"\x11" * 32, 0, sequence=sequence)],
        vout=outputs,
    )
    psbt = PSBT(transaction)
    wallet = app.session.wallets[app.wallet_index]
    fingerprint = wallet.fingerprints[0]
    public = app.session._seed_for(fingerprint)
    derived = _derive_public(public, _account_path("main", wallet.role, 0))
    child = derived.derive("m/0/0")
    path = _account_path("main", wallet.role, 0) + [0, 0]
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script)
    psbt.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    raw = psbt.serialize()
    review_psbt(app.session, app.wallet_index, raw)
    return raw


def _has_color(image, color) -> bool:
    return any(pixel[:3] == color for pixel in image.getdata())


def __folder(name):
    from pathlib import Path

    return Path("artifacts/screenshots") / name

"""Stills of Transaction Signing. The PSBTs are built in code."""

import base64
import time
from pathlib import Path

from PIL import Image, ImageDraw
from embit.psbt import DerivationPath, OutputScope, PSBT
from embit.script import Script, address_to_scriptpubkey
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from bigsigner.sdcard import mount_memory, unmount_memory
from bigsigner.ui.app import QR_BRIGHTNESS_STOPS, App
from bigsigner.ui.canvas import WIDTH, font
from bigsigner.ui.psbt_screen import TITLE_SIZE
from test_psbt_load import _child, _psbt
from test_psbt_view import _native, _pay_this_wallet
from test_ui import ScreenRecord


def _folder(name):
    return Path("artifacts/screenshots") / name


def _load(app, psbt):
    app._accept_psbt_text(base64.b64encode(psbt.serialize()).decode(), "file")
    app.notice = ""
    app.notice_until = None


def _shot(record, app, name, scroll=0):
    app.scroll["psbt-yaml"] = scroll
    record.shot(app, name)


def _qr_frames(record, app):
    """One still per format, and one still per frame when the code cycles."""
    names = ("animated-ur", "ur", "base64", "specter", "bbqr")
    labels = ("Animated UR", "Static UR", "Base64", "Specter Animated", "BBQr")
    for index, name in enumerate(names):
        app.psbt_qr_format = index
        app.psbt_qr_part = 0
        app._psbt_qr_at = time.monotonic()
        app.render()
        count = len(app._psbt_qr_parts())
        for part in range(max(count, 1)):
            app.psbt_qr_part = part
            app._psbt_qr_at = time.monotonic()
            suffix = name if count <= 1 else f"{name}-{part + 1}-of-{count}"
            record.shot(app, f"qr-{suffix}")
        assert any(item["text"] == labels[index] for item in app.texts)


def test_transaction_signing_saves_screenshots():
    record = ScreenRecord(_folder("test_transaction_signing_saves_screenshots"))
    app = App()
    app.session = _native()
    app.wallet_index = 0
    record.note("Each still is a PSBT built in code and opened on Transaction Signing.")

    _load(app, _psbt(app.session))
    _shot(record, app, "plain-top")
    _shot(record, app, "plain-bottom", scroll=10**9)
    app.scroll["psbt-yaml"] = 0
    app.render()
    assert any(item["text"] == "Spending from Wallet:" for item in app.texts)

    height = _psbt(app.session)
    height.locktime = 159_408
    _load(app, height)
    _shot(record, app, "block-height")
    assert "block height 159408" in " ".join(item["text"] for item in app.texts)

    stamped = _psbt(app.session)
    stamped.locktime = 1_700_000_000
    _load(app, stamped)
    _shot(record, app, "timestamp-top")
    _shot(record, app, "timestamp-bottom", scroll=10**9)

    zero = _psbt(app.session)
    zero.outputs.append(OutputScope(vout=TransactionOutput(0, Script(b"\x6a\x05hello"))))
    _load(app, zero)
    _shot(record, app, "op-return-zero")
    app._act("psbt-opreturn-1")
    record.shot(app, "op-return-ascii")
    app._act("psbt-op-next")
    record.shot(app, "op-return-hex")
    hex_line = next(item for item in app.texts if item["text"] == "68 65 6c 6c 6f")
    probe = ImageDraw.Draw(Image.new("RGB", (WIDTH, 10)))
    full = probe.textlength("00 11 22 33 44 55 66 77", font=font(TITLE_SIZE, mono=True))
    assert hex_line["box"][0] == round((WIDTH - full) / 2)
    app.back_one()

    paid = _psbt(app.session)
    paid.outputs.append(OutputScope(vout=TransactionOutput(5, Script(b"\x6a\x01\xff"))))
    _load(app, paid)
    _shot(record, app, "op-return-paid")
    assert "non-zero amount" in " ".join(item["text"] for item in app.texts)

    costly = _psbt(app.session, amount=200_000, output=50_000)
    _load(app, costly)
    _shot(record, app, "high-fee")
    assert "extremely high fee" in " ".join(item["text"] for item in app.texts)
    _shot(record, app, "high-fee-amount", scroll=10**9)

    disabled = _psbt(app.session, sequence=0xFFFFFFFE)
    _load(app, disabled)
    _shot(record, app, "rbf-disabled")
    assert "RBF" in " ".join(item["text"] for item in app.texts)
    _shot(record, app, "rbf-input", scroll=10**9)

    blocks = _psbt(app.session, sequence=1)
    _load(app, blocks)
    _shot(record, app, "relative-blocks")
    assert app.psbt_view["inputs"][0]["relative"]["duration"] == "1 block"
    _shot(record, app, "relative-input", scroll=10**9)

    app.scroll["psbt-yaml"] = 10**9
    app.render()
    app.qr_brightness = 0
    app._open_input_qr(0)
    for index, name in enumerate(("raw", "mempool", "blockstream")):
        app.input_qr_format = index
        record.shot(app, f"input-qr-{name}")
    dimmed = app.render()
    assert dimmed.getpixel((8, 400))[:3] == QR_BRIGHTNESS_STOPS[0]
    assert dimmed.getpixel((240, 40))[:3] != (18, 36, 58)
    app.back_one()

    app._act("psbt-sign")
    record.shot(app, "sign-export")
    mount_memory({"files": {}})
    try:
        app._act("psbt-export")
        record.shot(app, "export-format")
        app._act("psbt-export-binary")
        assert app.screen == "sd"
        assert app.export_binary is True
        assert app.export_bytes.startswith(b"psbt\xff")
        record.shot(app, "export-binary")
        app._act("export-new")
        assert app.filename == "transaction.psbt"
        record.shot(app, "export-binary-name")
        app.back_one()
        app.back_one()
        app._act("psbt-export-base64")
        assert app.export_binary is False
        assert app.export_text.startswith("cHNidP")
        record.shot(app, "export-base64")
        app._act("export-new")
        record.shot(app, "export-base64-name")
        app.back_one()
        app.back_one()
    finally:
        unmount_memory()
    app._act("psbt-show-qr")
    _qr_frames(record, app)
    assert app.qr_brightness == 0
    assert any(item["text"] == "Signed Transaction" for item in app.texts)

    returning = _psbt(app.session)
    _pay_this_wallet(returning, app.session, branch=1, index=0)
    _load(app, returning)
    _shot(record, app, "all-change")
    assert "same wallet" in " ".join(item["text"] for item in app.texts)
    _shot(record, app, "all-change-card", scroll=10**9)

    mixed = _psbt(app.session, output=40_000)
    _pay_this_wallet(mixed, app.session, branch=1, index=0, amount=25_000)
    _pay_this_wallet(mixed, app.session, branch=0, index=1, amount=25_000)
    _load(app, mixed)
    _shot(record, app, "change-warnings")
    assert "more than one change output" in " ".join(item["text"] for item in app.texts)
    _shot(record, app, "change-cards", scroll=10**9)
    assert "Receive Address #1" in " ".join(item["text"] for item in app.texts)


def _joined(app) -> str:
    return " ".join(item["text"] for item in app.texts)


def _op_return(payload: bytes, amount: int = 0) -> OutputScope:
    if len(payload) <= 75:
        raw = bytes([0x6A, len(payload)]) + payload
    else:
        raw = bytes([0x6A, 0x4C, len(payload)]) + payload
    return OutputScope(vout=TransactionOutput(amount, Script(raw)))


def _many_inputs(session, sequences):
    """Several inputs of the same address, each spending a different output."""
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    vins = [
        TransactionInput(bytes([index + 1]) * 32, 0, sequence=sequence)
        for index, sequence in enumerate(sequences)
    ]
    tx = Transaction(version=2, vin=vins, vout=[TransactionOutput(40_000, destination)])
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(200_000, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        inp.sighash_type = SIGHASH.ALL
    return psbt


def _scroll_all(record, app, name) -> str:
    """Save every step from the top of the screen through the bottom."""
    app.scroll["psbt-yaml"] = 0
    seen = []
    for index in range(100):
        record.shot(app, f"{name}-{index + 1}")
        seen.append(_joined(app))
        limit = app.scroll_max["psbt-yaml"]
        if app.scroll["psbt-yaml"] >= limit:
            break
        app.scroll["psbt-yaml"] = min(limit, app.scroll["psbt-yaml"] + 340)
    else:
        raise AssertionError("the signing screen did not reach the bottom")
    return " ".join(seen)


def test_combined_warnings_save_screenshots():
    record = ScreenRecord(_folder("test_combined_warnings_saves_screenshots"))
    app = App()
    app.session = _native()
    app.wallet_index = 0
    record.note(
        "One transaction with every warning that can appear together, "
        "and one input of each sequence kind: 0xFFFFFFFD, 0xFFFFFFFE, "
        "a block relative locktime, and a time relative locktime. "
        "One time lock is 0x0040FFFF, the top of that range."
    )
    psbt = _many_inputs(
        app.session,
        (0xFFFFFFFD, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFE, 1, 144, 0x00400002, 0x0040FFFF),
    )
    psbt.locktime = 1_700_000_000
    _pay_this_wallet(psbt, app.session, branch=1, index=0, amount=40_000)
    _pay_this_wallet(psbt, app.session, branch=0, index=1, amount=40_000)
    psbt.outputs.append(_op_return(b"meta", 1_000))
    _load(app, psbt)
    warnings = [item["text"] for item in app.psbt_view["warnings"]]
    assert any("non-zero amount" in text for text in warnings)
    assert any(text == "This transaction uses an extremely high fee." for text in warnings)
    assert any(text.startswith("This transaction uses a timestamp locktime.") for text in warnings)
    assert any(text.startswith("Some inputs use a relative locktime.") for text in warnings)
    assert any("additional requirement" in text for text in warnings)
    assert any(text.startswith("Some inputs are marked as Replace-by-Fee") for text in warnings)
    assert any(text.startswith("This transaction has more than one change output.") for text in warnings)
    assert any("receive address instead of a change address" in text for text in warnings)
    places = [card["place"] for card in app.psbt_view["change_outputs"]]
    assert "Change Address #0" in places
    assert "Receive Address #1" in places
    by_sequence = {item["sequence"]: item for item in app.psbt_view["inputs"]}
    assert 0xFFFFFFFD in by_sequence
    assert by_sequence[0xFFFFFFFE]["rbf_disabled"] is True
    assert by_sequence[1]["relative"]["duration"] == "1 block"
    assert by_sequence[144]["relative"]["duration"] == "144 blocks"
    assert by_sequence[0x00400002]["relative"]["kind"] == "time"
    assert by_sequence[0x0040FFFF]["relative"]["duration"] == "388 days, 8 hours, 32 minutes"
    app.psbt_more_open = True
    app.psbt_outputs_open = True
    app.psbt_inputs_open = True
    app.psbt_change_open = True
    shown = _scroll_all(record, app, "signing")
    for phrase in (
        "non-zero amount",
        "extremely high fee",
        "timestamp locktime",
        "2023-11-14",
        "Some inputs use a relative locktime",
        "additional requirement",
        "Some inputs are marked",
        "more than one change output",
        "receive address instead of a change address",
        "Receive Address #1",
        "0xFFFFFFFD",
        "0xFFFFFFFE",
        "1 block",
        "144 blocks",
        "17 minutes, 4 seconds",
        "388 days, 8 hours, 32 minutes",
    ):
        assert phrase in shown, phrase

    op_return = next(card for card in app.psbt_view["outputs"] if card["kind"] == "op_return")
    app._act(f"psbt-opreturn-{op_return['index']}")
    record.shot(app, "op-return-ascii")
    app._act("psbt-op-next")
    record.shot(app, "op-return-hex")
    assert "6d 65 74 61" in _joined(app)
    app.back_one()

    time_input = next(card for card in app.psbt_view["inputs"] if card["sequence"] == 0x0040FFFF)
    app._open_input_qr(time_input["index"])
    for index, name in enumerate(("raw", "mempool", "blockstream")):
        app.input_qr_format = index
        record.shot(app, f"input-qr-{name}")
    app.back_one()

    app._act("psbt-sign")
    record.shot(app, "sign-export")
    mount_memory({"files": {}})
    try:
        app._act("psbt-export")
        record.shot(app, "export-format")
        app._act("psbt-export-binary")
        record.shot(app, "export-binary")
        app._act("export-new")
        record.shot(app, "export-binary-name")
        app.back_one()
        app.back_one()
        app._act("psbt-export-base64")
        record.shot(app, "export-base64")
        app._act("export-new")
        record.shot(app, "export-base64-name")
        app.back_one()
        app.back_one()
    finally:
        unmount_memory()
    app._act("psbt-show-qr")
    _qr_frames(record, app)


def _open_op_return(app, payload: bytes, amount: int = 0):
    psbt = _psbt(app.session)
    psbt.outputs.append(_op_return(payload, amount))
    _load(app, psbt)
    app._act("psbt-opreturn-1")


def test_op_return_content_saves_screenshots():
    record = ScreenRecord(_folder("test_op_return_content_saves_screenshots"))
    app = App()
    app.session = _native()
    app.wallet_index = 0
    record.note("OP_RETURN content that is not ASCII, wraps a long line, or needs scrolling.")

    _open_op_return(app, b"hello\xff")
    assert app.psbt_op_mode == "hex"
    record.shot(app, "non-ascii-hex")
    assert "68 65 6c 6c 6f ff" in _joined(app)
    app._act("psbt-op-next")
    record.shot(app, "non-ascii-ascii")
    assert "The content is not ASCII text." in _joined(app)

    _open_op_return(app, b"W" * 80)
    assert app.psbt_op_mode == "ascii"
    record.shot(app, "long-line")
    shown = [item["text"] for item in app.texts if item["text"].startswith("W")]
    assert len(shown) >= 2
    assert "too long" not in _joined(app)

    long_text = "\n".join(f"Line {index:02d}" for index in range(1, 31))
    _open_op_return(app, long_text.encode("ascii"))
    record.shot(app, "long-ascii-top")
    assert "Scroll down to see the rest." in _joined(app)
    assert "Line 01" in _joined(app)
    app.scroll["psbt-opreturn"] = 10**9
    record.shot(app, "long-ascii-bottom")
    assert "Line 30" in _joined(app)
    assert "Line 01" not in _joined(app)
    assert "Scroll down" not in _joined(app)

    _open_op_return(app, bytes(range(240)))
    assert app.psbt_op_mode == "hex"
    record.shot(app, "long-hex-top")
    assert "Scroll down to see the rest." in _joined(app)
    assert "00 01 02 03 04 05 06 07" in _joined(app)
    app.scroll["psbt-opreturn"] = 10**9
    record.shot(app, "long-hex-bottom")
    assert "e8 e9 ea eb ec ed ee ef" in _joined(app)
    assert "00 01 02 03 04 05 06 07" not in _joined(app)
    assert "Scroll down" not in _joined(app)

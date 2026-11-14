"""Stills of Transaction Signing. The PSBTs are built in code."""

import base64
import time
from pathlib import Path

from PIL import Image, ImageDraw
from embit.descriptor.checksum import checksum
from embit.psbt import DerivationPath, OutputScope, PSBT
from embit.script import Script, address_to_scriptpubkey
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from bigsigner.sdcard import mount_memory, unmount_memory
from bigsigner.session import Session, _account_path, _public_for
from bigsigner.ui.app import QR_BRIGHTNESS_STOPS, App
from bigsigner.ui.canvas import WIDTH, font
from bigsigner.ui.psbt_screen import TITLE_SIZE
from test_large_tx_scroll import COMBINED_SEQUENCES, COMBINED_WARNINGS_VECTOR, _combined_warnings
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
    record.shot(app, "signing")
    app.render()
    record.shot(app, "sign-export")
    mount_memory({"files": {}})
    try:
        app._act("psbt-export")
        record.shot(app, "export-format")
        app._act("psbt-export-binary")
        app._act("storage-sd")
        assert app.screen == "sd"
        assert app.export_binary is True
        assert app.export_bytes.startswith(b"psbt\xff")
        record.shot(app, "export-binary")
        app._act("export-new")
        assert app.filename == "transaction-signed.psbt"
        record.shot(app, "export-binary-name")
        app.back_one()
        app.back_one()
        app.back_one()
        app._act("psbt-export-base64")
        app._act("storage-sd")
        assert app.export_binary is False
        assert app.export_text.startswith("cHNidP")
        record.shot(app, "export-base64")
        app._act("export-new")
        assert app.filename == "transaction-signed-base64.psbt"
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
        "One time lock is 0x0040FFFF, the top of that range. "
        "The committed binary is tests/vectors/native_segwit_combined_warnings.psbt."
    )
    assert COMBINED_SEQUENCES == (
        0xFFFFFFFD,
        0xFFFFFFFD,
        0xFFFFFFFE,
        0xFFFFFFFE,
        1,
        144,
        0x00400002,
        0x0040FFFF,
    )
    psbt = _combined_warnings(app.session)
    assert COMBINED_WARNINGS_VECTOR.read_bytes() == psbt.serialize()
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
    record.shot(app, "signing")
    app.render()
    record.shot(app, "sign-export")
    mount_memory({"files": {}})
    try:
        app._act("psbt-export")
        record.shot(app, "export-format")
        app._act("psbt-export-binary")
        app._act("storage-sd")
        record.shot(app, "export-binary")
        app._act("export-new")
        assert app.filename == "transaction-signed.psbt"
        record.shot(app, "export-binary-name")
        app.back_one()
        app.back_one()
        app.back_one()
        app._act("psbt-export-base64")
        app._act("storage-sd")
        record.shot(app, "export-base64")
        app._act("export-new")
        assert app.filename == "transaction-signed-base64.psbt"
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


ZOO = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
HIDDEN_INDEX = 73


def _address(session, wallet_index, account, branch, index) -> str:
    wallet = session.wallets[wallet_index]
    saved = dict(wallet.accounts)
    try:
        for fingerprint in wallet.fingerprints:
            wallet.accounts[fingerprint] = account
        session._descriptor_cache = None
        return session.addresses(wallet_index, branch, index, 1)[0]
    finally:
        wallet.accounts.clear()
        wallet.accounts.update(saved)
        session._descriptor_cache = None


def _derivations(session, wallet_index, account, branch, index):
    wallet = session.wallets[wallet_index]
    rows = []
    for fingerprint in wallet.fingerprints:
        stored = _public_for(session, fingerprint, wallet.role, account)
        child = stored.xpub.derive(f"m/{branch}/{index}")
        path = list(stored.path) + [branch, index]
        rows.append((child.key, DerivationPath(fingerprint, path)))
    return rows


def _output(session, wallet_index, account, branch, index, amount, with_origin: bool):
    script = address_to_scriptpubkey(_address(session, wallet_index, account, branch, index))
    scope = OutputScope(vout=TransactionOutput(amount, script))
    if with_origin:
        for key, origin in _derivations(session, wallet_index, account, branch, index):
            scope.bip32_derivations[key] = origin
    return scope


def _spend(session, wallet_index, account, amount):
    wallet = session.wallets[wallet_index]
    script = address_to_scriptpubkey(_address(session, wallet_index, account, 0, 0))
    txid = bytes([wallet_index + 3]) * 32
    vin = TransactionInput(txid, 0, sequence=0xFFFFFFFD)
    psbt_input_script = script
    sighash = None if wallet.role == "singlesig_taproot" else SIGHASH.ALL
    return vin, psbt_input_script, sighash, amount


def _gallery_psbt(session, spending, account):
    """One input, a hidden same-wallet address, another account, and another wallet."""
    vin, script, sighash, amount = _spend(session, spending, account, 200_000)
    hidden = _output(session, spending, account, 0, HIDDEN_INDEX, 40_000, False)
    other_account = 1 if account != 1 else 4
    same_wallet = _output(session, spending, other_account, 1, 4, 40_000, True)
    other = 1 if spending == 0 else 0
    other_wallet = _output(session, other, 0, 0, 2, 40_000, True)
    external = OutputScope(
        vout=TransactionOutput(20_000, address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"))
    )
    tx = Transaction(version=2, vin=[vin], vout=[item.vout for item in (hidden, other_wallet, same_wallet, external)])
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(amount, script)
    for key, origin in _derivations(session, spending, account, 0, 0):
        psbt.inputs[0].bip32_derivations[key] = origin
    if sighash is not None:
        psbt.inputs[0].sighash_type = sighash
    for index, scope in enumerate((hidden, other_wallet, same_wallet, external)):
        for key, origin in scope.bip32_derivations.items():
            psbt.outputs[index].bip32_derivations[key] = origin
    return psbt


def _scroll_until(app, phrase: str):
    app.scroll["psbt-yaml"] = 0
    app.render()
    for _ in range(40):
        if phrase in _joined(app):
            return
        limit = app.scroll_max["psbt-yaml"]
        if app.scroll["psbt-yaml"] >= limit:
            break
        app.scroll["psbt-yaml"] = min(limit, app.scroll["psbt-yaml"] + 280)
        app.render()
    raise AssertionError(phrase)


def _search_hidden_address(record, app):
    """The search runs continuously through index 73 and finds the hidden output."""
    _scroll_until(app, "Search for Address in Loaded Wallets")
    record.shot(app, "search-before")
    app._act("psbt-search-0-0")
    record.shot(app, "search-settings")
    app._act("psbt-search-start")
    record.shot(app, "search-preparing")
    for _ in range(100000):
        if not app.psbt_search_active():
            break
        app._advance_psbt_search()
    else:
        raise AssertionError("Address search did not finish")
    assert app._psbt_sheet is None
    record.shot(app, "search-found")
    assert app.screen == "address-search"
    assert app.confirm == "psbt-found"
    assert app._confirm_message() == f"Address found in Receive addresses: #{HIDDEN_INDEX}"
    app._act("psbt-search-confirm")
    assert app._psbt_heights == {}
    assert app.scroll["psbt-yaml"] == 0
    place = f"Receive Address #{HIDDEN_INDEX}"
    assert any(card["place"] == place and card["receive_change"] for card in app.psbt_view["change_outputs"])
    assert any("receive address" in item["text"] for item in app.psbt_view["warnings"])
    _scroll_until(app, place)
    record.shot(app, "search-result")
    assert place in _joined(app)


def _taproot_and_native():
    from test_domain import ABANDON, LEGAL, expression

    session = Session()
    session.add_mnemonic(ABANDON.split())
    session.add_mnemonic(LEGAL.split())
    taproot = expression(ABANDON, "m/86h/0h/0h")
    native = expression(LEGAL, "m/84h/0h/0h")
    session.add_text(f"tr({taproot})#{checksum('tr(' + taproot + ')')}")
    session.add_text(f"wpkh({native})#{checksum('wpkh(' + native + ')')}")
    wallet = session.wallets[0]
    wallet.accounts[wallet.fingerprints[0]] = 3
    session._descriptor_cache = None
    return session


def _multisig_and_native():
    from test_domain import ABANDON, LEGAL, expression

    session = Session()
    session.add_mnemonic(ABANDON.split())
    session.add_mnemonic(LEGAL.split())
    session.add_mnemonic(ZOO.split())
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    third = expression(ZOO, "m/48h/0h/0h/2h")
    body = f"wsh(sortedmulti(2,{first},{second},{third}))"
    session.add_text(f"{body}#{checksum(body)}")
    native = expression(ABANDON, "m/84h/0h/0h")
    session.add_text(f"wpkh({native})#{checksum('wpkh(' + native + ')')}")
    return session


def test_taproot_nonzero_account_saves_screenshots():
    record = ScreenRecord(_folder("test_taproot_nonzero_account_saves_screenshots"))
    session = _taproot_and_native()
    app = App()
    app.session = session
    app.wallet_index = 0
    record.note(
        "Taproot wallet on account 3. One output is this wallet's receive address 73 "
        "with no derivation, found by continuous address search. Another output pays account 1. "
        "One output is the other loaded wallet and keeps its derivation."
    )
    _load(app, _gallery_psbt(session, 0, 3))
    assert app.psbt_view["account_line"] == "Account: 3 (non-default)"
    assert app.psbt_view["change_outputs"] == []
    assert app.psbt_view["outputs"][2]["owned"]["account_line"] == "Account: 1 (non-default)"
    _scroll_all(record, app, "signing")
    _search_hidden_address(record, app)
    app.scroll["psbt-yaml"] = 10**9
    record.shot(app, "sign-transaction")
    assert any(hit["action"] == "psbt-sign" for hit in app.hits)


def test_multisig_sign_with_saves_screenshots():
    record = ScreenRecord(_folder("test_multisig_sign_with_saves_screenshots"))
    session = _multisig_and_native()
    app = App()
    app.session = session
    app.wallet_index = 0
    record.note(
        "2-of-3 native-segwit wallet with all three seeds loaded. "
        "Receive address 73 has no derivation and is found by continuous address search. "
        "The payment to account 1 keeps its derivation. Another output belongs to the "
        "singlesig wallet and keeps its derivation. Each loaded seed has its own "
        "Sign Transaction with button."
    )
    _load(app, _gallery_psbt(session, 0, 0))
    assert app.psbt_view["account_line"] == "Account: 0, 0, 0 (default)"
    assert "Some inputs have no signatures." in app.psbt_view["signature_note"]
    assert app.psbt_view["change_outputs"] == []
    assert app.psbt_view["outputs"][2]["owned"]["account_line"] == "Account: 1, 1, 1 (non-default)"
    _scroll_all(record, app, "signing")
    _search_hidden_address(record, app)
    _scroll_until(app, "Some inputs have no signatures.")
    record.shot(app, "sign-note")
    app.scroll["psbt-yaml"] = 10**9
    record.shot(app, "sign-with-before")
    sign_hits = [hit for hit in app.hits if hit["action"].startswith("psbt-sign-")]
    assert len(sign_hits) == 3
    assert all(hit["label"].startswith("Sign Transaction with\n") for hit in sign_hits)
    assert not any(hit["action"] == "psbt-continue" for hit in app.hits)
    app._act(sign_hits[0]["action"])
    _scroll_until(app, "Each input already has 1 signature.")
    record.shot(app, "sign-note-after")
    assert app.psbt_view["signature_note"] == (
        "Each input already has 1 signature. "
        "1 additional signature is required to complete this 2-of-3 wallet."
    )
    app.scroll["psbt-yaml"] = 10**9
    record.shot(app, "sign-with-after")
    assert any(hit["action"] == "psbt-continue" for hit in app.hits)
    assert sum(hit["action"].startswith("psbt-sign-") for hit in app.hits) == 2

"""The Transaction Signing text: amounts, warnings, and address search."""

import base64

from embit.psbt import DerivationPath, OutputScope
from embit.script import Script
from embit.transaction import TransactionOutput

from bigsigner.bbqr import encode_bbqr, join_bbqr, split_bbqr
from bigsigner.psbt_check import psbt_yaml
from bigsigner.psbt_qr import psbt_qr_parts, ur_parts_round_trip
from bigsigner.psbt_view import (
    ALL_TO_WALLET,
    account_line,
    input_qr_text,
    HIGH_FEE_WARNING,
    MANY_CHANGE_WARNING,
    OP_RETURN_VALUE_WARNING,
    OP_RETURN_WARNING,
    RELATIVE_EXTRA,
    RELATIVE_ONE,
    RBF_ONE,
    RECEIVE_CHANGE_ONE,
    describe_psbt,
    format_btc,
    format_duration,
    format_fee_rate,
    format_locktime,
    hex_lines,
    search_address,
)
from bigsigner.sdcard import mount_memory, read_bytes, unmount_memory, write_bytes
from bigsigner.ui.app import App
from test_psbt_load import _child, _native, _psbt


def test_a_two_letter_word_stays_with_the_word_before_it():
    from PIL import Image, ImageDraw

    from bigsigner.ui.canvas import font
    from bigsigner.ui.psbt_screen import _wrap_name

    draw = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    lines = _wrap_name(draw, "Grateful Ivory Impala 0A (Native-Segwit)", font(32), 300)
    assert lines == ["Grateful Ivory", "Impala 0A", "(Native-Segwit)"]
    assert all(not line.startswith("0A") for line in lines)
    from bigsigner.ui.canvas import WIDTH, MARGIN

    fingerprints = "2-of-3 73c5da0a,b8688df1,3f635a63"
    limit = WIDTH - 2 * MARGIN
    wrapped = _wrap_name(draw, fingerprints, font(32), limit)
    assert wrapped == ["2-of-3 73c5da0a,b8688df1,", "3f635a63"]
    assert all(draw.textlength(line, font=font(32)) <= limit for line in wrapped)
    found = _wrap_name(draw, f"Address found in wallet {fingerprints}", font(36), WIDTH - 88)
    assert any(line.endswith(",") for line in found)
    assert all(draw.textlength(line, font=font(36)) <= WIDTH - 88 for line in found)
    sequence = _wrap_name(draw, "Address found in account-sequence 0, 2, 0", font(36), WIDTH - 88)
    assert " ".join(sequence) == "Address found in account-sequence 0, 2, 0"
    assert all(not line.startswith(",") for line in sequence)


def test_a_found_address_notice_names_receive_account_or_wallet():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app.psbt_search_hit = {
        "wallet_index": 0,
        "branch": 0,
        "name": "2-of-3 aa,bb,cc",
        "account_indexes": [0],
    }
    assert app._found_address_message() == "Address found in Receive addresses"
    app.psbt_search_hit["branch"] = 1
    assert app._found_address_message() == "Address found in Change addresses"
    app.psbt_search_hit["account_indexes"] = [3]
    assert app._found_address_message() == "Address found in account #3"
    app.psbt_search_hit["account_indexes"] = [0, 2, 0]
    assert app._found_address_message() == "Address found in account-sequence 0, 2, 0"
    app.psbt_search_hit["wallet_index"] = 1
    assert app._found_address_message() == "Address was found in wallet 2-of-3 aa,bb,cc"


def test_btc_amounts_are_strings_with_eight_decimal_places():
    assert format_btc(1) == "0.00000001"
    assert format_btc(100_000_000) == "1.00000000"
    assert format_btc(2_100_000_000_000_000) == "21,000,000.00000000"
    assert format_btc(0, bare_zero=True) == "0"
    assert format_btc(0) == "0.00000000"
    assert format_fee_rate(34, 10) == "3.40"
    assert format_fee_rate(3403, 1000) == "3.40"
    assert format_duration(512) == "8 minutes, 32 seconds"
    assert format_locktime(1_700_000_000) == "2023-11-14 22:13:20 UTC"


def test_warnings_name_op_return_fee_locktime_and_rbf():
    session = _native()
    plain = describe_psbt(session, 0, _psbt(session))
    assert plain["warnings"] == []
    assert plain["account_line"] == "Account: 0 (default)"
    assert account_line([b"\x01", b"\x02", b"\x03"], {b"\x01": 0, b"\x02": 0, b"\x03": 0}) == (
        "Account: 0, 0, 0 (default)"
    )
    assert account_line([b"\x01", b"\x02", b"\x03"], {b"\x01": 0, b"\x02": 2, b"\x03": 0}) == (
        "Account: 0, 2, 0 (non-default)"
    )
    assert plain["inputs_open"] is False
    assert plain["outputs"][0]["owned"] is None
    assert plain["fee"] == 10_000
    assert plain["locktime_label"] == "No Locktimes: The transaction could be mined right away."

    height = _psbt(session)
    height.locktime = 159_408
    view = describe_psbt(session, 0, height)
    assert view["banner"] == "This transaction can be mined only after block height 159408."
    assert "above 159408" in view["more_info"]
    assert "equal" not in view["more_info"]
    assert view["locktime_label"] == "Absolute Locktime: After block height 159408"

    stamped = _psbt(session)
    stamped.locktime = 1_700_000_000
    view = describe_psbt(session, 0, stamped)
    assert view["warnings"][0]["tone"] == "yellow"
    assert view["warnings"][0]["text"].endswith("after:")
    assert view["warnings"][0]["center"] == "2023-11-14 22:13:20 UTC"
    assert "median timestamp reported in recent blocks" in view["warnings"][0]["after"]
    assert "See below" not in view["warnings"][0]["text"]
    assert view["locktime_label"].endswith("UTC")

    paid = _psbt(session)
    paid.outputs.append(OutputScope(vout=TransactionOutput(5, Script(b"\x6a\x02hi"))))
    view = describe_psbt(session, 0, paid)
    assert view["warnings"][0]["text"] == OP_RETURN_VALUE_WARNING
    assert view["warnings"][0]["tone"] == "red"
    card = next(item for item in view["outputs"] if item["kind"] == "op_return")
    assert card["payload"] == b"hi"
    assert hex_lines(card["payload"]) == ["68 69"]

    zero = _psbt(session)
    zero.outputs.append(OutputScope(vout=TransactionOutput(0, Script(b"\x6a\x05hello"))))
    view = describe_psbt(session, 0, zero)
    assert view["warnings"][0]["text"] == OP_RETURN_WARNING
    assert view["outputs"][-1]["ascii"] is True
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(zero.serialize(), "file")
    seen = set()
    for _ in range(12):
        app.render()
        seen.update(item["text"] for item in app.texts)
        app.scroll["psbt-yaml"] = app.scroll.get("psbt-yaml", 0) + 220
    assert "Amount (BTC): 0" in seen
    assert "0" not in seen

    costly = _psbt(session, amount=200_000, output=50_000)
    view = describe_psbt(session, 0, costly)
    assert view["fee"] == 150_000
    assert view["fee_high"] is True
    assert view["warnings"][0]["text"] == HIGH_FEE_WARNING

    disabled = _psbt(session, sequence=0xFFFFFFFE)
    view = describe_psbt(session, 0, disabled)
    assert view["warnings"][0]["text"] == RBF_ONE
    assert view["inputs"][0]["rbf_disabled"] is True
    assert f"0x{view['inputs'][0]['sequence']:08X}" == "0xFFFFFFFE"
    txid = view["inputs"][0]["txid"]
    assert input_qr_text("main", txid, 0, "raw") == f"{txid}:0"
    assert view["txid"] == disabled.tx.txid().hex()
    assert view["txid_rows"] == [view["txid"][index : index + 16] for index in range(0, 64, 16)]
    shown = _psbt(session)
    shown.inputs[0].txid = bytes(range(32))
    displayed = bytes(range(32)).hex()
    assert describe_psbt(session, 0, shown)["inputs"][0]["txid"] == displayed
    assert f"{displayed}:0" in psbt_yaml(shown)
    assert input_qr_text("main", txid, 0, "mempool") == f"https://mempool.space/tx/{txid}:0"
    assert input_qr_text("main", txid, 0, "mempool", "signet") == f"https://mempool.space/tx/{txid}:0"
    assert input_qr_text("test", txid, 1, "blockstream") == f"https://blockstream.info/testnet/tx/{txid}#output:1"
    assert input_qr_text("regtest", txid, 1, "mempool", "testnet4") == f"https://mempool.space/testnet4/tx/{txid}:1"
    assert input_qr_text("test", txid, 1, "blockstream", "signet") == f"https://blockstream.info/signet/tx/{txid}#output:1"
    assert view["inputs_open"] is True

    blocks = _psbt(session, sequence=1)
    view = describe_psbt(session, 0, blocks)
    assert view["warnings"][0]["text"] == RELATIVE_ONE + " See below for more details."
    assert view["inputs"][0]["relative"]["label"] == "Relative Locktime:"
    assert view["inputs"][0]["relative"]["duration"] == "1 block"
    assert "Inputs 0" not in view["relative_line"]
    assert view["relative_line"].startswith("Input 0")

    timed = _psbt(session, sequence=0x00400002)
    timed.locktime = 100
    view = describe_psbt(session, 0, timed)
    assert RELATIVE_EXTRA.strip() in view["warnings"][0]["text"]
    assert view["inputs"][0]["relative"]["duration"] == "17 minutes, 4 seconds"


def _pay_this_wallet(psbt, session, branch, index, amount=None):
    from embit.script import address_to_scriptpubkey

    fingerprint, child, path = _child(session, branch=branch, index=index)
    script = address_to_scriptpubkey(session.addresses(0, branch, index, 1)[0])
    if amount is None:
        scope = psbt.outputs[0]
        scope.script_pubkey = script
        scope.vout.script_pubkey = script
    else:
        scope = OutputScope(vout=TransactionOutput(amount, script))
        psbt.outputs.append(scope)
    scope.bip32_derivations[child.key] = DerivationPath(fingerprint, path)


def test_change_is_its_own_section_and_a_receive_address_is_warned():
    session = _native()
    hidden = _psbt(session)
    _pay_this_wallet(hidden, session, branch=1, index=0)
    view = describe_psbt(session, 0, hidden)
    assert view["outputs"] == []
    assert view["outputs_note"] == ALL_TO_WALLET
    assert view["change_outputs"][0]["place"] == "Change Address #0"
    assert view["change_outputs"][0]["receive_change"] is False
    assert view["warnings"] == []

    shown = _psbt(session)
    _pay_this_wallet(shown, session, branch=0, index=0)
    view = describe_psbt(session, 0, shown)
    assert view["outputs"] == []
    card = view["change_outputs"][0]
    assert card["place"] == "Receive Address #0"
    assert card["receive_change"] is False
    assert view["warnings"] == []

    several = _psbt(session, output=40_000)
    _pay_this_wallet(several, session, branch=1, index=0, amount=25_000)
    _pay_this_wallet(several, session, branch=0, index=1, amount=25_000)
    view = describe_psbt(session, 0, several)
    assert len(view["outputs"]) == 1
    assert [item["place"] for item in view["change_outputs"]] == ["Change Address #0", "Receive Address #1"]
    assert view["warnings"][0]["text"] == MANY_CHANGE_WARNING
    assert view["warnings"][1]["text"] == RECEIVE_CHANGE_ONE


def test_address_search_checks_both_branches_and_the_next_window():
    session = _native()
    receive = session.addresses(0, 0, 3, 1)[0]
    change = session.addresses(0, 1, 60, 1)[0]
    found = search_address(session, 0, receive, 0)
    assert found["place"] == "Receive Address #3"
    assert search_address(session, 0, change, 0) is None
    later = search_address(session, 0, change, 50)
    assert later["place"] == "Change Address #60"
    assert search_address(session, 0, "bc1qnot-an-address", 0) is None


def test_signed_psbt_qr_parts_and_a_binary_file_round_trip():
    raw = _psbt(_native()).serialize()
    assert psbt_qr_parts(raw, "base64")
    specter = psbt_qr_parts(raw, "specter")
    assert specter[0].startswith("p1of")
    animated = psbt_qr_parts(raw, "animated-ur")
    assert len(animated) > 1
    assert ur_parts_round_trip(raw, animated) == raw
    parts = encode_bbqr(raw, chunk=40)
    payloads = []
    encoding = None
    for part in parts:
        encoding, kind, _count, _index, payload = split_bbqr(part)
        assert kind == "P"
        payloads.append(payload)
    assert join_bbqr(payloads, encoding) == raw
    assert ur_parts_round_trip(raw) == raw

    mount_memory({"files": {}})
    try:
        write_bytes("signed.psbt", raw)
        assert read_bytes("signed.psbt") == raw
    finally:
        unmount_memory()


def _box_top(items, text):
    matches = [item for item in items if item.get("text") == text or item.get("label") == text]
    assert matches, text
    return min(item["box"][1] for item in matches)


def _ink_rows(image, box, x0, x1):
    pixels = image.load()
    rows = []
    for y in range(max(0, box[1] - 24), min(image.height, box[3] + 24)):
        if any(pixels[x, y][0] < 40 for x in range(x0, x1)):
            rows.append(y)
    assert rows
    return rows


def test_a_section_chevron_lines_up_with_the_middle_of_its_label():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(base64.b64encode(_psbt(session).serialize()).decode(), "file")
    image = app.render()
    for label in ("Transaction Id", "1 Output"):
        box = next(item["box"] for item in app.texts if item["text"] == label)
        text_mid = (box[1] + box[3] - 1) / 2
        rows = _ink_rows(image, box, max(0, box[0] - 36), box[0] - 4)
        chevron_mid = (rows[0] + rows[-1]) / 2
        assert abs(chevron_mid - text_mid) <= 1, (label, chevron_mid, text_mid)


def test_transaction_id_starts_closed_and_change_sits_above_inputs():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    psbt = _psbt(session)
    _pay_this_wallet(psbt, session, branch=1, index=1)
    app._accept_psbt_text(base64.b64encode(psbt.serialize()).decode(), "file")
    assert app.screen == "psbt-yaml"
    assert app.psbt_txid_open is False
    app.psbt_change_open = False
    app.render()
    assert any(hit["label"] == "Transaction Id" for hit in app.hits)
    rows = app.psbt_view["txid_rows"]
    assert rows[0] not in [item["text"] for item in app.texts]
    app._act("psbt-toggle-txid")
    app.render()
    assert [item["text"] for item in app.texts if item["text"] in rows] == rows

    app.psbt_txid_open = False
    app.scroll["psbt-yaml"] = 10**9
    app.render()
    change_top = _box_top(app.texts, "1 Change Output")
    input_top = _box_top(app.hits, "1 Input")
    assert change_top < input_top


def _marked_top(items, text):
    matches = [item for item in items if item.get("text") == text or item.get("label") == text]
    assert matches, text
    return min(item["box"][1] for item in matches)


def test_a_test_network_link_chooses_testnet_testnet4_or_signet():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(base64.b64encode(_psbt(session).serialize()).decode(), "file")
    app.session.network = "test"
    app._open_input_qr(0)
    app.input_qr_format = 1
    app.render()
    assert _marked_top(app.texts, "Testnet") < _marked_top(app.texts, "Brightness")
    assert _marked_top(app.texts, "Brightness") < _marked_top(app.texts, "Mempool.space")
    assert any(url.startswith("https://mempool.space/testnet/tx/") for url in app._input_qr_images)
    app._act("input-explorer-next")
    app.render()
    assert any(item["text"] == "Testnet4" for item in app.texts)
    assert any("/testnet4/tx/" in url for url in app._input_qr_images)
    app._act("input-explorer-next")
    app.input_qr_format = 2
    app.render()
    assert any(item["text"] == "Signet" for item in app.texts)
    assert any(url.startswith("https://blockstream.info/signet/tx/") for url in app._input_qr_images)
    app.input_qr_format = 0
    app.render()
    assert not any(item["text"] == "Signet" for item in app.texts)
    app.session.network = "main"
    app.input_qr_format = 1
    app.render()
    assert not any(item["text"] in ("Testnet", "Testnet4", "Signet") for item in app.texts)


def test_the_signing_screen_offers_a_signed_qr_and_an_sd_file():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(base64.b64encode(_psbt(session).serialize()).decode(), "file")
    assert app.screen == "psbt-yaml"
    app.scroll["psbt-yaml"] = 10**9
    app.render()
    app._act("psbt-sign")
    assert app.screen == "psbt-share"
    app._act("psbt-export")
    assert app.screen == "psbt-export-format"
    app.render()
    assert "Binary" in [hit["label"] for hit in app.hits]
    app._act("psbt-show-qr")
    assert app.screen == "psbt-qr"
    app.render()
    assert "Animated UR" in [item["text"] for item in app.texts]

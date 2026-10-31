from bigsigner.session import SessionError, normalize_address_text
from bigsigner.ui.app import (
    ADDRESS_GAP,
    ADDRESS_PATH_CHARS,
    ADDRESS_QR,
    ADDRESS_ROW,
    App,
    _address_path_lines,
    _address_screen_title,
)
from bigsigner.ui.canvas import BLUE, INK, MUTED, NAVY, WIDTH

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _wallet():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.notice = ""
    return app


def test_receive_is_selected_and_rows_do_not_wrap():
    app = _wallet()
    app._act("addresses")
    image = app.render()
    receive = next(hit for hit in app.hits if hit["action"] == "address-receive")
    change = next(hit for hit in app.hits if hit["action"] == "address-change")
    tools = next(hit for hit in app.hits if hit["action"] == "address-tools")
    rows = [hit for hit in app.hits if hit["action"].startswith("open-address-")]
    assert image.getpixel((receive["box"][0] + 24, (receive["box"][1] + receive["box"][3]) // 2))[:3] == BLUE
    assert image.getpixel((change["box"][0] + 24, (change["box"][1] + change["box"][3]) // 2))[:3] == NAVY
    assert rows[0]["label"].startswith("0. bc1")
    assert rows[0]["label"].endswith("\u2026")
    assert all("\n" not in hit["label"] for hit in rows)
    assert rows[-1]["box"][3] <= tools["box"][1]
    assert 0 in {index for branch, index in app._address_cache if branch == 0}
    assert all(branch == 0 for branch, _index in app._address_cache)


def test_scrolling_drops_rows_that_are_far_away():
    app = _wallet()
    app.screen = "addresses"
    app.address_branch = 0
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.scroll["addresses"] = 80 * stride
    app.render()
    indexes = [index for branch, index in app._address_cache if branch == 0]
    assert min(indexes) > 60
    assert 0 not in indexes


def test_export_address_writes_the_address_to_the_card(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = _wallet()
    app.address_branch = 0
    app.address_index = 0
    app.screen = "address"
    app.back = ["addresses"]
    app.scroll["address"] = 10_000
    app.render()
    assert any(hit["label"] == "Export to SD Card" for hit in app.hits)
    address = app.session.addresses(app.wallet_index, 0, 0, 1)[0]
    app._act("export-address")
    assert app.screen == "sd"
    app._act("export-new")
    fingerprint = app.session.wallets[app.wallet_index].fingerprints[0].hex()
    assert app.filename == f"{fingerprint}-receive-0.txt"
    app._act("export-save-new")
    assert (tmp_path / app.filename).read_text(encoding="utf-8").strip() == address
    assert app.screen == "address"
    assert app.notice == f"Saved {app.filename}."


def test_an_address_row_opens_its_qr_and_its_path():
    app = _wallet()
    app._act("addresses")
    app.render()
    app._act("open-address-0")
    assert app.screen == "address"
    image = app.render()
    text_top = 88 + 12 + ADDRESS_QR + 8
    band = [image.getpixel((x, y))[:3] for y in range(text_top, text_top + 120) for x in range(20, 460)]
    assert INK in band and MUTED in band
    # The first address group is centered, so both side margins stay empty.
    assert image.getpixel((12, text_top + 8))[:3] not in (INK, MUTED)
    assert image.getpixel((WIDTH - 12, text_top + 8))[:3] not in (INK, MUTED)
    assert app.session.address_paths(app.wallet_index, 0, 0) == [
        f"{app.selected_fp.hex()}/84h/0h/0h/0/0"
    ]


def test_find_address_by_index_opens_that_address():
    app = _wallet()
    app.screen = "addresses"
    app._act("address-tools")
    app._act("address-find")
    app._act("address-find-change")
    app._act("address-find-inc")
    app._act("address-find-show")
    assert app.screen == "address"
    assert app.address_branch == 1
    assert app.address_index == 1
    assert app.session.address_paths(app.wallet_index, 1, 1)[0].endswith("/84h/0h/0h/1/1")


def test_verify_address_accepts_a_bip21_uri_and_walks_ranges():
    app = _wallet()
    address = app.session.addresses(app.wallet_index, 0, 0, 1)[0]
    app.screen = "address-verify"
    app.back = ["address-verify"]
    app._verify_entered_address(f"  BITCOIN:{address.upper()}?amount=0.01&label=a/b")
    assert app.screen == "address-verify-result"
    assert app.verify_found == {"branch": "receive", "index": 0, "address": address}
    assert app.back == ["addresses"]
    app._act("address-go")
    assert app.screen == "address"
    assert app.address_index == 0
    assert app.back == ["addresses"]
    app._act("back")
    assert app.screen == "addresses"

    later = app.session.addresses(app.wallet_index, 1, 150, 1)[0]
    app._search_address(later, 0)
    assert app.verify_found is None
    app.render()
    assert any(hit["label"] == "Search 100-199" for hit in app.hits)
    app._act("address-search-100")
    image = app.render()
    assert not any(hit["action"].startswith("address-search-") for hit in app.hits)
    grey = (186, 190, 196)
    assert any(image.getpixel((240, y))[:3] == grey for y in range(200, 700))
    assert app.verify_found is None
    assert app.notice_delay() is not None
    app.render()
    assert app.verify_found["branch"] == "change"
    assert app.verify_found["index"] == 150


def test_the_address_title_names_the_branch_and_shortens_a_long_index():
    assert _address_screen_title(0, 5) == "Receive Address 5"
    assert _address_screen_title(1, 0) == "Change Address 0"
    assert _address_screen_title(0, 9999) == "Receive Address 9999"
    assert _address_screen_title(1, 10000) == "Change Address 100\u2026"
    assert _address_screen_title(0, 100000) == "Receive Address 100\u2026"


def test_a_path_of_25_characters_stays_on_one_line():
    short = "73c5da0a/84h/0h/0h/1/4900"
    assert len(short) == ADDRESS_PATH_CHARS
    assert _address_path_lines(short) == [short]
    longer = short + "/9"
    lines = _address_path_lines(longer)
    assert lines == [short, "/9"]
    assert all(len(line) <= ADDRESS_PATH_CHARS for line in lines)


def test_the_address_keyboard_is_digits_then_lowercase_letters():
    app = _wallet()
    app.screen = "address-verify"
    app._act("address-type")
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert {"1", "0", "q", "a", "z", "del"} <= labels
    assert "space" not in labels
    assert "ABC" not in labels
    assert ".?123" not in labels
    one = next(hit["box"] for hit in app.hits if hit["label"] == "1")
    cue = next(hit["box"] for hit in app.hits if hit["label"] == "q")
    assert one[1] < cue[1]
    app._type_address(" ")
    app._type_address("B")
    app._type_address("b")
    app._type_address("1")
    assert app.address_text == "b1"


def test_an_address_scan_names_the_content_it_found():
    from bigsigner.seedqr import compact_bytes

    app = _wallet()
    app.screen = "scan"
    app.scan_kind = "address"
    app.back = ["address-verify"]
    app.accept_qr(compact_bytes(ABANDON).decode("latin-1"))
    assert app.screen == "address-verify"
    assert app.notice == "This is a compact seed, not an address."

    app.screen = "scan"
    app.scan_kind = "address"
    app.back = ["address-verify"]
    app.accept_qr("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert app.notice == "This is a legacy address, not a bc1 address."


def test_an_invalid_typed_address_stays_on_the_entry_screen():
    app = _wallet()
    app.screen = "address-verify"
    app._act("address-type")
    app.address_text = "bc1qnot-an-address"
    app.address_cursor = len(app.address_text)
    app._act("address-verify-text")
    assert app.screen == "address-type"
    assert app.address_text == "bc1qnot-an-address"
    assert app.notice == "This address is not valid."


def test_verify_address_refuses_a_path_or_a_legacy_address():
    with pytest_raises("derivation path"):
        normalize_address_text("wpkh([73c5da0a/84h/0h/0h]xpub/0/*)", "main")
    with pytest_raises("bc1"):
        normalize_address_text("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "main")
    with pytest_raises("not valid"):
        normalize_address_text("bc1qnot-an-address", "main")
    with pytest_raises("tb1"):
        normalize_address_text("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", "test")


def pytest_raises(fragment):
    import pytest

    return pytest.raises(SessionError, match=fragment)

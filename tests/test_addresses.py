from bigsigner.session import SessionError, normalize_address_text
from bigsigner.ui.app import (
    ADDRESS_GAP,
    ADDRESS_PATH_CHARS,
    ADDRESS_QR,
    ADDRESS_ROW,
    ADDRESS_WINDOW,
    App,
    _address_path_lines,
    _address_screen_title,
    _address_text_groups,
)
from bigsigner.ui.canvas import BLUE, HEADER, INK, MUTED, NAVY, WIDTH

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


def _open_addresses(app):
    app._act("addresses")
    app.render()
    return app.render()


def test_the_addresses_button_shows_loading_before_the_list():
    app = _wallet()
    app.render()
    box = next(hit["box"] for hit in app.hits if hit["action"] == "addresses")
    app._act("addresses")
    assert app.screen == "wallet"
    loading = app.render()
    assert app.screen == "wallet"
    assert not any(hit["action"] == "addresses" for hit in app.hits)
    y = (box[1] + box[3]) // 2
    assert any(
        loading.getpixel((x, y))[:3] == (186, 190, 196) for x in range(box[0] + 8, box[2] - 8)
    )
    assert app.notice_delay() == 0
    app.render()
    assert app.screen == "addresses"


def test_opening_addresses_derives_sixteen_rows_on_each_branch():
    app = _wallet()
    _open_addresses(app)
    stride = ADDRESS_ROW + ADDRESS_GAP
    receive = sorted(index for branch, index in app._address_cache if branch == 0)
    change = sorted(index for branch, index in app._address_cache if branch == 1)
    assert receive == list(range(2 * ADDRESS_WINDOW))
    assert change == list(range(2 * ADDRESS_WINDOW))
    assert [start for start, _image in app._address_pages] == [0, ADDRESS_WINDOW]
    assert all(image.height == ADDRESS_WINDOW * stride for _start, image in app._address_pages)


def test_clicks_during_loading_do_nothing():
    app = _wallet()
    app.render()
    app._act("addresses")
    app.render()
    assert app.screen == "wallet"
    descriptor = next(hit for hit in app.hits if hit["action"] == "show-descriptor")
    box = descriptor["box"]
    app.tap((box[0] + box[2]) // 2, (box[1] + box[3]) // 2)
    assert app.screen == "wallet"
    assert app._addresses_loading
    app.pointer_down(40, 40)
    app.pointer_up(40, 40)
    assert app.screen == "wallet"
    app.render()
    assert app.screen == "addresses"
    row = next(hit for hit in app.hits if hit["action"] == "open-address-0")
    x = (row["box"][0] + row["box"][2]) // 2
    y = (row["box"][1] + row["box"][3]) // 2
    app.pointer_down(x, y)
    app.pointer_up(x, y)
    assert app.screen == "address"


def test_a_touch_queued_during_loading_is_not_a_click():
    app = _wallet()
    _open_addresses(app)
    row = next(hit for hit in app.hits if hit["action"] == "open-address-0")
    x = (row["box"][0] + row["box"][2]) // 2
    y = (row["box"][1] + row["box"][3]) // 2
    app.arm_queued_touch_discard()
    app.pointer_down(x, y)
    app.pointer_up(x, y)
    assert app.screen == "addresses"
    app.pointer_down(x, y)
    app.pointer_up(x, y)
    assert app.screen == "address"


def test_receive_is_selected_and_rows_do_not_wrap():
    app = _wallet()
    image = _open_addresses(app)
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
    assert 0 in {index for branch, index in app._address_cache if branch == 1}


def _top_index(app):
    indexes = [
        int(hit["action"].rsplit("-", 1)[1])
        for hit in app.hits
        if hit["action"].startswith("open-address-")
    ]
    return min(indexes)


def _drag(app, distance):
    app.pointer_down(240, 640)
    app.pointer_move(240, 640 - distance)
    app.render()
    app.pointer_up(240, 640 - distance)
    app.render()


def test_a_drag_follows_the_finger_across_cached_blocks():
    app = _wallet()
    app.screen = "addresses"
    app.address_branch = 0
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.render()
    assert [start for start, _image in app._address_pages] == [0, ADDRESS_WINDOW]
    assert all(image.height == ADDRESS_WINDOW * stride for _start, image in app._address_pages)
    app.pointer_down(240, 620)
    y = 620
    previous = 0
    while y > 260:
        y -= 40
        app.pointer_move(240, y)
        app.render()
        assert app.scroll["addresses"] == previous + 40
        previous = app.scroll["addresses"]
    assert app.scroll["addresses"] == previous
    place = app.scroll["addresses"]
    app.pointer_up(240, 0)
    app._act("address-receive")
    assert app.address_branch == 0
    assert app.scroll["addresses"] == place
    app._act("address-change")
    assert app.scroll["addresses"] == 0


def test_a_new_touch_does_not_jump_backward():
    app = _wallet()
    app.screen = "addresses"
    app.address_branch = 0
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.render()
    _drag(app, 600)
    place = app.scroll["addresses"]
    parked = _top_index(app)
    assert place > 0
    app.pointer_down(240, 500)
    app.pointer_move(240, 470)
    app.render()
    assert app.scroll["addresses"] >= place
    assert _top_index(app) >= parked
    app.pointer_up(240, 470)
    app.render()
    _drag(app, 600)
    _drag(app, 600)
    _drag(app, 600)
    _drag(app, 600)
    assert app.scroll["addresses"] > 30 * stride
    assert _top_index(app) > 30


def test_the_lift_after_a_scroll_does_not_open_an_address():
    app = _wallet()
    app.screen = "addresses"
    app.render()
    app.pointer_down(240, 500)
    app.pointer_move(240, 300)
    assert app.scroll["addresses"] > 0
    app.pointer_up(240, 300)
    assert app.screen == "addresses"


def test_a_button_is_ignored_just_after_a_scroll():
    app = _wallet()
    app.screen = "addresses"
    app.render()
    tools = next(hit for hit in app.hits if hit["action"] == "address-tools")
    x = (tools["box"][0] + tools["box"][2]) // 2
    y = (tools["box"][1] + tools["box"][3]) // 2
    app.pointer_down(240, 500)
    app.pointer_move(240, 300)
    assert app.scroll["addresses"] > 0
    app.pointer_up(240, 300)
    app.pointer_down(x, y)
    app.pointer_up(x, y)
    assert app.screen == "addresses"
    app._scroll_at -= 1
    app.pointer_down(x, y)
    app.pointer_up(x, y)
    assert app.screen == "address-tools"


def test_lifting_rebuilds_around_the_new_place_without_moving_it():
    app = _wallet()
    app.screen = "addresses"
    app.address_branch = 0
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.render()
    _drag(app, 600)
    place = app.scroll["addresses"]
    parked = _top_index(app)
    cursor = place
    for start, image in app._address_pages:
        top = start * stride
        bottom = top + image.height
        if bottom <= cursor:
            continue
        assert top <= cursor
        cursor = bottom
        if cursor >= place + app._address_view_h:
            break
    assert cursor >= place + app._address_view_h
    assert parked == place // stride
    app.pointer_down(240, 640)
    app.pointer_move(240, 120)
    app.render()
    assert app.scroll["addresses"] >= place
    app.pointer_up(240, 120)
    app.render()
    assert app.scroll["addresses"] >= place
    assert _top_index(app) >= parked
    assert _top_index(app) * stride <= app.scroll["addresses"] < (_top_index(app) + 1) * stride


def test_scrolling_drops_rows_that_are_far_away():
    app = _wallet()
    app.screen = "addresses"
    app.address_branch = 0
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.scroll["addresses"] = 80 * stride
    app.render()
    indexes = sorted(index for branch, index in app._address_cache if branch == 0)
    assert [start for start, _image in app._address_pages] == [0, 8, 72, 80, 88, 96]
    assert indexes == list(range(16)) + list(range(72, 104))


def test_a_scroll_keeps_the_neighbor_blocks_before_it_moves():
    app = _wallet()
    _open_addresses(app)
    stride = ADDRESS_ROW + ADDRESS_GAP
    block = ADDRESS_WINDOW * stride
    app.pointer_down(240, 500)
    app.pointer_move(240, 500 - (block + 10))
    assert app.scroll["addresses"] == block + 10
    assert [start for start, _image in app._address_pages] == [0, 8, 16, 24]
    indexes = sorted(index for branch, index in app._address_cache if branch == 0)
    assert indexes == list(range(32))


def test_the_list_stitches_two_blocks():
    app = _wallet()
    app.screen = "addresses"
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.scroll["addresses"] = ADDRESS_WINDOW * stride - 80
    image = app.render()
    rows = [hit for hit in app.hits if hit["action"].startswith("open-address-")]
    indexes = [int(hit["action"].rsplit("-", 1)[1]) for hit in rows]
    assert any(index < ADDRESS_WINDOW for index in indexes)
    assert any(index >= ADDRESS_WINDOW for index in indexes)
    later = next(hit for hit in rows if int(hit["action"].rsplit("-", 1)[1]) >= ADDRESS_WINDOW)
    y = (later["box"][1] + later["box"][3]) // 2
    assert any(
        image.getpixel((x, y))[:3] == INK
        for x in range(later["box"][0] + 16, later["box"][2] - 16)
    )


def test_export_address_writes_the_address_to_the_card():
    from bigsigner.sdcard import mount_memory, read_text

    mount_memory({"files": {}})
    app = _wallet()
    app.address_branch = 0
    app.address_index = 0
    app.screen = "address"
    app.back = ["addresses"]
    app.scroll["address"] = 10_000
    app.render()
    assert any(hit["label"] == "Export to File" for hit in app.hits)
    address = app.session.addresses(app.wallet_index, 0, 0, 1)[0]
    app._act("export-address")
    app._act("storage-sd")
    assert app.screen == "sd"
    app._act("export-new")
    fingerprint = app.session.wallets[app.wallet_index].fingerprints[0].hex()
    assert app.filename == f"{fingerprint}-receive-0.txt"
    app._act("export-save-new")
    assert read_text(app.filename) == address
    assert app.screen == "address"
    assert app.notice == f"Saved {app.filename}."


def test_switching_tabs_reuses_the_cached_screens():
    app = _wallet()
    receive = _open_addresses(app)
    assert set(app._address_tops) == {0, 1}
    calls = []
    real = app.session.addresses

    def wrapped(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    app.session.addresses = wrapped
    app._act("address-change")
    change = app.render()
    assert app.address_branch == 1
    assert app.scroll["addresses"] == 0
    assert calls == []
    change_tab = next(hit for hit in app.hits if hit["action"] == "address-change")
    assert change.getpixel((change_tab["box"][0] + 24, (change_tab["box"][1] + change_tab["box"][3]) // 2))[:3] == BLUE
    again = app.render()
    assert again.tobytes() == change.tobytes()
    app._act("address-receive")
    back = app.render()
    assert calls == []
    assert back.tobytes() == receive.tobytes()
    stride = ADDRESS_ROW + ADDRESS_GAP
    app.scroll["addresses"] = 80 * stride
    app.render()
    app._act("address-change")
    app.scroll["addresses"] = 80 * stride
    app.render()
    calls.clear()
    app._act("address-receive")
    app.render()
    app._act("address-change")
    app.render()
    assert calls == []
    for branch in (0, 1):
        kept = {index for item_branch, index in app._address_cache if item_branch == branch}
        assert set(range(2 * ADDRESS_WINDOW)) <= kept


def test_address_groups_are_four_characters():
    from bigsigner.ui.app import _address_rows

    assert _address_text_groups("abc") == ["abc ", "    ", "    ", "    "]
    assert _address_text_groups("abcd") == ["abcd", "    ", "    ", "    "]
    assert _address_rows("abcde") == [["abcd", "e   ", "    ", "    "]]
    rows = _address_rows("tb1q" * 9)
    assert rows
    assert all(len(row) == 4 and all(len(group) == 4 for group in row) for row in rows)
    assert "".join("".join(row) for row in rows).rstrip() == "tb1q" * 9


def test_the_address_page_scrolls_a_cached_picture():
    from bigsigner.ui.app import _qr_image

    app = _wallet()
    second = app.session.add_mnemonic(ABANDON.split(), passphrase="2")
    app.multisig_m = 2
    app.multisig_selected = {app.selected_fp, second["fingerprint"]}
    app._create_selected_multisig()
    app.address_branch = 0
    app.address_index = 1000
    app.screen = "address"
    first = app.render()
    address = app.session.addresses(app.wallet_index, 0, 1000, 1)[0]
    code = _qr_image(address, ADDRESS_QR)
    left = (WIDTH - ADDRESS_QR) // 2
    top = HEADER + 12
    assert first.crop((left, top, left + ADDRESS_QR, top + ADDRESS_QR)).tobytes() == code.tobytes()
    assert app.scroll_max["address"] > 40
    sheet = app._address_sheet
    calls = []
    real = app.session.addresses

    def wrapped(*args, **kwargs):
        calls.append(args)
        return real(*args, **kwargs)

    app.session.addresses = wrapped
    app.pointer_down(240, 640)
    app.pointer_move(240, 640 - 80)
    second_image = app.render()
    moved = app.scroll["address"]
    assert calls == []
    assert app._address_sheet is sheet
    assert moved == 80
    probe = None
    for y in range(top + ADDRESS_QR - 1, top, -1):
        if first.getpixel((WIDTH // 2, y))[:3] == (0, 0, 0) and y - moved >= HEADER:
            probe = y
            break
    assert probe is not None
    assert second_image.getpixel((WIDTH // 2, probe - moved))[:3] == (0, 0, 0)
    assert second_image.getpixel((16, 40))[:3] == NAVY


def test_an_address_row_opens_its_qr_and_its_path():
    app = _wallet()
    _open_addresses(app)
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

"""The layout dump the panel writes for a device test. These checks run on this machine."""

from bigsigner.hardware.ui_dump import snapshot
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEADER

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _one(items, text):
    found = [item for item in items if item.get("text") == text or item.get("label") == text]
    assert len(found) == 1, (text, items)
    return found[0]


def test_warning_marks_the_title_above_the_button():
    app = App()
    app.screen = "warning"
    app.render()
    snap = snapshot(app, 12, 1)
    title = _one(snap["texts"], "Remove SD Card")
    button = _one(snap["hits"], "Continue")
    body = next(item for item in snap["texts"] if "SD card" in item["text"])
    assert title["box"][1] >= 0
    assert title["box"][3] <= HEADER
    assert body["box"][1] >= title["box"][3]
    assert body["box"][3] <= button["box"][1]
    assert button["box"][1] > 640


def test_the_abandon_fingerprint_matches_the_panel_script():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    assert added["fingerprint"].hex() == "73c5da0a"


def test_a_disabled_account_minus_is_still_on_the_left():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app.notice = ""
    app.render()
    snap = snapshot(app, 8, 1)
    minus = _one(snap["texts"], "-")
    plus = _one(snap["texts"], "+")
    account = _one(snap["hits"], "Account")
    assert minus["box"][2] <= account["box"][0] <= account["box"][2] <= plus["box"][0]
    assert not any(hit["label"] == "-" for hit in snap["hits"])
    assert any(hit["label"] == "+" for hit in snap["hits"])


def test_descriptor_text_moves_up_when_the_qr_scrolls():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.notice = ""
    app.render()
    show = _one(app.hits, "Show")
    assert show["box"][1] < 790
    app._act("show-descriptor")
    app.qr_hint_until = 0
    app.render()
    before = snapshot(app, 40, 2)
    line = next(item for item in before["qr_texts"] if item["text"].startswith("wpkh"))
    assert before["qr_box"][1] < line["box"][1]
    assert before["qr_scroll_max"] > 80
    app.qr_scroll = 160
    app.render()
    after = snapshot(app, 30, 3)
    moved = next(item for item in after["qr_texts"] if item["text"].startswith("wpkh"))
    assert moved["box"][1] <= line["box"][1] - 100
    assert after["qr_box"][1] <= before["qr_box"][1] - 100


def test_wallet_buttons_stay_tappable_under_the_saved_notice():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.render()
    snap = snapshot(app, 20, 1)
    show = _one(snap["hits"], "Show")
    assert show["box"][1] < 790
    assert show["box"][3] > show["box"][1] + 20

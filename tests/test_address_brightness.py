"""Address QR brightness affects the entire page and respects its scroll position."""

from pathlib import Path

import pytest

from bigsigner.ui.app import ADDRESS_QR, QR_BRIGHTNESS_DEFAULT, QR_BRIGHTNESS_MAX, QR_BRIGHTNESS_STOPS
from bigsigner.ui.canvas import BLUE, HEADER, HEIGHT, NAVY, WIDTH
from test_addresses import ABANDON, _wallet


def _address(branch=0):
    app = _wallet()
    app.address_branch = branch
    app.address_index = 0
    app.screen = "address"
    app.back = ["addresses"]
    return app


def _tap(app, action):
    app.render()
    hit = next(hit for hit in app.hits if hit["action"] == action)
    left, top, right, bottom = hit["box"]
    app.tap((left + right) // 2, (top + bottom) // 2)


@pytest.mark.parametrize("branch", [0, 1])
def test_address_brightness_dims_the_header_qr_page_and_scrolled_buttons(branch):
    app = _address(branch)
    normal = app.render()
    sheet = app._address_sheet
    cached = sheet["image"].tobytes()
    brightness = next(mark for mark in app.texts if mark["text"] == "Brightness")
    assert brightness["box"][1] > HEADER + 12 + ADDRESS_QR
    assert brightness["box"][3] < HEIGHT
    assert normal.getpixel((16, 40)) == NAVY
    _tap(app, "brightness-down")
    dim = app.render()
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT - 1
    assert dim.getpixel((0, HEADER + 8)) == QR_BRIGHTNESS_STOPS[app.qr_brightness]
    assert sum(dim.getpixel((16, 40))) < sum(NAVY)
    qr_box = ((WIDTH - ADDRESS_QR) // 2, HEADER + 12,
              (WIDTH + ADDRESS_QR) // 2, HEADER + 12 + ADDRESS_QR)
    assert normal.crop(qr_box).getextrema() == ((0, 255), (0, 255), (0, 255))
    assert all(low == 0 and high < 255 for low, high in dim.crop(qr_box).getextrema())
    app.scroll["address"] = 100_000
    scrolled = app.render()
    export = next(hit for hit in app.hits if hit["action"] == "export-address")
    pixel = (export["box"][0] + 8, (export["box"][1] + export["box"][3]) // 2)
    assert sum(scrolled.getpixel(pixel)) < sum(BLUE)
    assert app._address_sheet is sheet
    assert sheet["image"].tobytes() == cached


def test_address_brightness_limits_update_live_and_back_restores_the_default():
    app = _address()
    app.render()
    sheet = app._address_sheet
    for _ in range(QR_BRIGHTNESS_DEFAULT):
        _tap(app, "brightness-down")
    app.render()
    assert app.qr_brightness == 0
    assert "brightness-down" not in {hit["action"] for hit in app.hits}
    for _ in range(QR_BRIGHTNESS_MAX):
        _tap(app, "brightness-up")
    app.render()
    assert app.qr_brightness == QR_BRIGHTNESS_MAX
    assert "brightness-up" not in {hit["action"] for hit in app.hits}
    assert app._address_sheet is sheet
    _tap(app, "back")
    assert app.screen == "addresses"
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT


def test_scrolling_brightness_under_the_title_bar_removes_its_hidden_hit_areas():
    app = _address()
    second = app.session.add_mnemonic(ABANDON.split(), passphrase="2")
    app.multisig_m = 2
    app.multisig_selected = {app.selected_fp, second["fingerprint"]}
    app._create_selected_multisig()
    wallet = app.session.wallets[app.wallet_index]
    wallet.accounts.update({fp: 0x7FFFFFFF for fp in wallet.fingerprints})
    app.address_index = 0x7FFFFFFF
    app.screen = "address"
    app.render()
    brightness_y = app._address_sheet["brightness_y"]
    app.scroll["address"] = brightness_y - HEADER + 20
    app.render()
    controls = [hit for hit in app.hits if hit["action"].startswith("brightness-")]
    assert controls and all(hit["box"][1] == HEADER for hit in controls)
    before = app.qr_brightness
    app.tap(WIDTH - 52, HEADER - 4)
    assert app.qr_brightness == before
    app.scroll["address"] = brightness_y + 52 - HEADER
    app.render()
    assert app.scroll["address"] == brightness_y + 52 - HEADER
    assert not any(hit["action"].startswith("brightness-") for hit in app.hits)


def test_receive_and_change_address_brightness_saves_screenshots():
    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_receive_and_change_address_brightness_saves_screenshots"))
    for branch, name in ((0, "receive"), (1, "change")):
        app = _address(branch)
        record.shot(app, name)
        _tap(app, "brightness-down")
        record.shot(app, name + "-dimmed")
    app.scroll["address"] = 100_000
    record.shot(app, "change-scrolled-dimmed")

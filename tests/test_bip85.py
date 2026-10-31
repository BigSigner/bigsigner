import pytest
from embit.bip32 import HDKey
from PIL import ImageDraw

from bigsigner.session import SessionError, bip85_mnemonic
from bigsigner.ui.app import App
from bigsigner.ui.canvas import BODY_SIZE, font

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SPEC_XPRV = (
    "xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb"
)
ABANDON_12 = "prosper short ramp prepare exchange stove life snack client enough purpose fold"
ABANDON_24 = (
    "stick exact spice sock filter ginger museum horse kit multiply manual wear "
    "grief demand derive alert quiz fault december lava picture immune decade jaguar"
)


def _seed_app(passphrase=None):
    app = App()
    added = app.session.add_mnemonic(ABANDON.split(), passphrase)
    app.selected_fp = added["fingerprint"]
    app.selected_key_index = 0
    app.screen = "key"
    app.back = ["keys"]
    return app, added["fingerprint"]


def test_bip85_matches_the_specification_vectors():
    root = HDKey.from_base58(SPEC_XPRV)
    assert bip85_mnemonic(root, 12, 0) == "girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose"
    assert (
        bip85_mnemonic(root, 24, 0)
        == "puppy ocean match cereal symbol another shed magic wrap hammer bulb intact gadget divorce twin tonight reason outdoor destroy simple truth cigar social volcano"
    )
    with pytest.raises(SessionError, match="12 or 24 words"):
        bip85_mnemonic(root, 18, 0)
    with pytest.raises(SessionError, match="too large"):
        bip85_mnemonic(root, 12, 0x80000000)


def test_the_abandon_seed_derives_its_bip85_children():
    app, fingerprint = _seed_app()
    assert app.session.bip85_child(fingerprint, 12, 0) == ABANDON_12
    assert app.session.bip85_child(fingerprint, 24, 0) == ABANDON_24
    with_secret, _fingerprint = _seed_app("secret")
    assert with_secret.session.bip85_child(with_secret.selected_fp, 24, 0) != ABANDON_24


def _ink_line_widths(image, box):
    """Width of each run of white text inside a button."""
    left, top, right, bottom = box
    rows = []
    for y in range(top + 4, bottom - 4):
        xs = [x for x in range(left + 8, right - 8) if image.getpixel((x, y))[0] > 200]
        if not xs:
            continue
        if rows and y > rows[-1][0] + 2:
            yield max(item[2] for item in rows) - min(item[1] for item in rows) + 1
            rows = []
        rows.append((y, min(xs), max(xs)))
    if rows:
        yield max(item[2] for item in rows) - min(item[1] for item in rows) + 1


def _assert_bip85_button_breaks_after_bip85(image, button):
    face = font(BODY_SIZE)
    draw = ImageDraw.Draw(image)
    widths = list(_ink_line_widths(image, button["box"]))
    expected = [draw.textlength(line, font=face) for line in ("Derive a BIP85", "Child Seed")]
    assert len(widths) == 2
    assert abs(widths[0] - expected[0]) < 12
    assert abs(widths[1] - expected[1]) < 12


def test_bip85_screen_adds_the_child_and_clears_the_back_stack():
    app, parent = _seed_app()
    app.scroll["key"] = 10_000
    image = app.render()
    tops = {hit["label"]: hit["box"][1] for hit in app.hits}
    assert tops["Derive an Extended Public Key"] < tops["Create a Copy of This Seed with a Passphrase"]
    assert tops["Create a Copy of This Seed with a Passphrase"] < tops["Derive a BIP85 Child Seed"]
    button = next(hit for hit in app.hits if hit["action"] == "derive-bip85")
    _assert_bip85_button_breaks_after_bip85(image, button)
    app._act("derive-bip85")
    assert app.screen == "bip85"
    assert app.bip85_words == 24
    assert app.bip85_index == 0
    assert app._bip85_path() == "m/83696968h/39h/0h/24h/0h"
    app.render()
    assert any(hit["label"] == "24 words" and hit["action"] == "dropdown-bip85-words" for hit in app.hits)
    assert "bip85-dec" not in {hit["action"] for hit in app.hits}
    assert "bip85-inc" in {hit["action"] for hit in app.hits}
    app._act("dropdown-bip85-words")
    app.render()
    assert {hit["label"] for hit in app.hits if hit["action"].startswith("dropdown-pick-bip85-words-")} == {
        "12 words",
        "24 words",
    }
    app._act("dropdown-pick-bip85-words-12")
    assert app.bip85_words == 12
    assert app.open_dropdown is None
    assert app._bip85_path() == "m/83696968h/39h/0h/12h/0h"
    app._act("bip85-inc")
    assert app.bip85_index == 1
    app.render()
    assert "bip85-dec" in {hit["action"] for hit in app.hits}
    app._act("bip85-edit")
    assert app.screen == "account"
    app.render()
    assert any(hit["label"] == "Use This Index" for hit in app.hits)
    app._act("account-key-backspace")
    app._act("account-key-7")
    app._act("account-save")
    assert app.screen == "bip85"
    assert app.bip85_index == 7
    assert app._bip85_path() == "m/83696968h/39h/0h/12h/7h"

    app.bip85_index = 0
    app._act("bip85-derive")
    assert app.screen == "key"
    assert app.back == ["keys"]
    assert app.notice == "BIP85 child seed was added successfully."
    child = app.selected_fp
    assert child != parent
    assert child in app.session.fingerprints
    assert app.session.fingerprints[child].keys[0].mnemonic == ABANDON_12.split()
    assert app.session.fingerprints[child].keys[0].passphrase is None
    app.back_one()
    assert app.screen == "keys"

    app.selected_fp = parent
    app.screen = "key"
    app._act("derive-bip85")
    app._act("dropdown-pick-bip85-words-12")
    app._act("bip85-derive")
    assert app.screen == "bip85"
    assert app.notice == "This seed is already loaded."
    assert set(app.session.fingerprints) == {parent, child}

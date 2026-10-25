from bigsigner.entropy import mnemonic_from_camera, mnemonic_from_dice
from bigsigner.ui.app import App

ROLLS = "65515223131652132161133154444123616466443112153441"


def _center(box):
    left, top, right, bottom = box
    return (left + right) // 2, (top + bottom) // 2


def test_new_seed_length_is_a_dropdown():
    app = App()
    app.screen = "generate"
    app.entropy_words = 12
    app.render()
    assert not any(hit["action"] in {"gen-12", "gen-24"} for hit in app.hits)
    field = next(hit for hit in app.hits if hit["action"] == "dropdown-entropy-words")
    app.tap(*_center(field["box"]))
    app.render()
    assert app.open_dropdown == "entropy-words"
    assert app.entropy_words == 12
    option = next(hit for hit in app.hits if hit["action"] == "dropdown-pick-entropy-words-24")
    outside = next(hit for hit in app.hits if hit["action"] == "dropdown-close")
    app.tap(outside["box"][0] + 4, outside["box"][1] + 4)
    assert app.open_dropdown is None
    assert app.entropy_words == 12
    app.render()
    app.tap(*_center(field["box"]))
    app.render()
    option = next(hit for hit in app.hits if hit["action"] == "dropdown-pick-entropy-words-24")
    app.tap(*_center(option["box"]))
    assert app.entropy_words == 24
    assert app.open_dropdown is None


def test_dice_buttons_are_faces_and_the_rolls_scroll():
    from bigsigner.ui.canvas import BLUE, INK

    app = App()
    app.screen = "dice"
    app.entropy_words = 12
    blank = app.render()
    one = next(hit for hit in app.hits if hit["action"] == "die-1")
    four = next(hit for hit in app.hits if hit["action"] == "die-4")
    six = next(hit for hit in app.hits if hit["action"] == "die-6")
    undo = next(hit for hit in app.hits if hit["action"] == "entropy-undo")
    assert one["box"][1] > 400
    assert six["box"][1] > one["box"][3]
    assert six["box"][3] < undo["box"][1]

    def white_in(box, x0, y0, x1, y1):
        left, top, right, bottom = box
        width = right - left
        height = bottom - top
        for y in range(top + int(height * y0), top + int(height * y1)):
            for x in range(left + int(width * x0), left + int(width * x1)):
                if blank.getpixel((x, y))[:3] == (255, 255, 255):
                    return True
        return False

    assert white_in(one["box"], 0.4, 0.4, 0.6, 0.6)
    assert not white_in(four["box"], 0.42, 0.42, 0.58, 0.58)
    assert white_in(four["box"], 0.12, 0.1, 0.38, 0.38)
    assert white_in(six["box"], 0.12, 0.4, 0.38, 0.6)
    assert blank.getpixel(((four["box"][0] + four["box"][2]) // 2, (four["box"][1] + four["box"][3]) // 2))[:3] == BLUE

    app.entropy_digits = "123456"
    few = app.render()
    assert few.tobytes() != blank.tobytes()
    assert app.entropy_scroll_max == 0
    digit_band = [(x, y) for x in range(20, 70) for y in range(180, 240)]
    assert any(few.getpixel(point)[:3] == INK for point in digit_band)
    assert not any(blank.getpixel(point)[:3] == INK for point in digit_band)

    app.entropy_words = 24
    app.entropy_digits = "123456" * 14
    app.entropy_scroll_stick = True
    bottom = app.render()
    assert app.entropy_scroll_max > 0
    assert app.entropy_scroll == app.entropy_scroll_max
    box = app.entropy_scroll_box
    x = 40
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y + 80)
    app.pointer_up(x, y + 80)
    earlier = app.render()
    assert app.entropy_scroll < app.entropy_scroll_max
    assert earlier.tobytes() != bottom.tobytes()
    app._act("die-3")
    app.render()
    assert app.entropy_digits.endswith("3")
    assert app.entropy_scroll_stick is True
    assert app.entropy_scroll == app.entropy_scroll_max


def test_dice_entry_offers_the_seedsigner_mnemonic():
    app = App()
    app.screen = "dice"
    app.entropy_words = 12
    for roll in ROLLS:
        app._act(f"die-{roll}")
    assert app.screen == "entropy"
    assert app.pending_mnemonic == mnemonic_from_dice(ROLLS)
    app._act("entropy-save")
    assert app.screen == "passphrase-ask"
    app._act("passphrase-no")
    assert app.screen == "key"
    assert app.session.fingerprints


def test_coin_flips_scroll_above_lower_buttons():
    from bigsigner.ui.canvas import INK

    app = App()
    app.screen = "coins"
    app.entropy_words = 12
    blank = app.render()
    zero = next(hit for hit in app.hits if hit["action"] == "coin-0")
    one = next(hit for hit in app.hits if hit["action"] == "coin-1")
    undo = next(hit for hit in app.hits if hit["action"] == "entropy-undo")
    assert zero["box"][1] > 480
    assert one["box"][1] == zero["box"][1]
    assert zero["box"][3] < undo["box"][1]

    app.entropy_digits = "01"
    few = app.render()
    assert few.tobytes() != blank.tobytes()
    assert app.entropy_scroll_max == 0
    digit_band = [(x, y) for x in range(20, 80) for y in range(160, 230)]
    assert any(few.getpixel(point)[:3] == INK for point in digit_band)
    assert not any(blank.getpixel(point)[:3] == INK for point in digit_band)

    app.entropy_words = 24
    app.entropy_digits = "01" * 80
    app.entropy_scroll_stick = True
    bottom = app.render()
    assert app.entropy_scroll_max > 0
    assert app.entropy_scroll == app.entropy_scroll_max
    box = app.entropy_scroll_box
    x = 40
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y + 90)
    app.pointer_up(x, y + 90)
    earlier = app.render()
    assert app.entropy_scroll < app.entropy_scroll_max
    assert earlier.tobytes() != bottom.tobytes()
    app._act("coin-1")
    app.render()
    assert app.entropy_digits.endswith("1")
    assert app.entropy_scroll_stick is True
    assert app.entropy_scroll == app.entropy_scroll_max


def test_coin_entry_waits_for_128_flips():
    app = App()
    app.screen = "coins"
    app.entropy_words = 12
    for _ in range(127):
        app._act("coin-0")
    assert app.screen == "coins"
    app._act("coin-1")
    assert app.screen == "entropy"
    assert len(app.pending_mnemonic.split()) == 12


def test_a_24_word_backup_scrolls_and_continue_follows_the_cards():
    from bigsigner.ui.canvas import HEADER, HEIGHT, MARGIN, WHITE, WIDTH

    words = ["abandon"] * 23 + ["art"]
    app = App()
    app.pending_mnemonic = " ".join(words)
    app.screen = "entropy"
    top = app.render()
    assert app.scroll_max["entropy"] > 0
    assert not any(hit["action"] == "entropy-save" for hit in app.hits)
    inset = MARGIN

    def card_rows(image, x):
        return [y for y in range(HEADER, HEIGHT) if image.getpixel((x, y))[:3] == WHITE]

    left_rows = card_rows(top, inset + 16)
    center_rows = card_rows(top, WIDTH // 2)
    assert left_rows and center_rows
    assert min(left_rows) == min(center_rows)
    row_y = min(left_rows) + 8
    assert top.getpixel((WIDTH - 4, row_y))[:3] != WHITE
    x = WIDTH // 2
    y = (HEADER + HEIGHT) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y - 120)
    assert app.scroll["entropy"] > 0

    app.scroll["entropy"] = app.scroll_max["entropy"]
    app.render()
    button = next(hit for hit in app.hits if hit["action"] == "entropy-save")
    assert button["label"] == "Continue"
    assert button["box"][3] < HEIGHT
    assert button["box"][1] > HEIGHT // 2


def test_camera_picture_changes_the_seed():
    common = dict(frames=[b"preview"], serial=b"serial", timestamp="1")
    twelve = mnemonic_from_camera(final=b"shot", words=12, **common)
    other = mnemonic_from_camera(final=b"other", words=12, **common)
    full = mnemonic_from_camera(final=b"shot", words=24, **common)
    assert twelve != other
    assert len(twelve.split()) == 12
    assert len(full.split()) == 24


def test_posted_camera_frames_make_a_seed():
    app = App()
    app.entropy_words = 12
    app.screen = "camera"
    app.render()
    app.tap(240, 400, camera={"frames": [b"preview"], "final": b"shot"})
    app._act("camera-capture")
    assert app.screen == "entropy"
    assert len(app.pending_mnemonic.split()) == 12

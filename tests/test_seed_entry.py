from PIL import Image, ImageDraw

from bigsigner.ui.app import App, _grid_font_size
from bigsigner.ui.canvas import HEADER, HEIGHT, MARGIN, MUTED, PAPER, TITLE_SIZE, WHITE, WIDTH, font as ui_font, wrap

WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()


def test_a_press_left_of_q_a_and_z_still_types_them():
    app = App()
    app.screen = "passphrase"
    app.passphrase_mode = "lower"
    app.render()
    for label in ("q", "a", "z"):
        hit = next(item for item in app.hits if item["label"] == label)
        assert hit["box"][0] == 0
        y = (hit["box"][1] + hit["box"][3]) // 2
        app.tap(10, y)
    assert app.passphrase_text == "qaz"


def test_a_passphrase_letter_repaints_only_the_field():
    app = App()
    app.screen = "passphrase"
    app.passphrase_mode = "lower"
    app.render()
    hit = next(item for item in app.hits if item["label"] == "q")
    x = (hit["box"][0] + hit["box"][2]) // 2
    y = (hit["box"][1] + hit["box"][3]) // 2
    app.tap(x, y)
    app.render()
    assert app.passphrase_text == "q"
    top, bottom = app.dirty
    assert bottom - top < 120


def test_a_vertical_twitch_on_the_keyboard_still_types():
    app = App()
    app.screen = "passphrase"
    app.passphrase_mode = "lower"
    app.render()
    assert app.keyboard_top == 470
    hit = next(item for item in app.hits if item["label"] == "q")
    x = (hit["box"][0] + hit["box"][2]) // 2
    y = (hit["box"][1] + hit["box"][3]) // 2
    app.scroll_max["passphrase"] = 400
    app.pointer_down(x, y)
    app.pointer_move(x, y + 80)
    app.pointer_up(x, y + 80)
    assert app.passphrase_text == "q"
    assert app.scroll.get("passphrase", 0) == 0


def test_a_sideways_twitch_still_types_the_passphrase_key():
    app = App()
    app.screen = "passphrase"
    app.passphrase_mode = "lower"
    app.render()
    hit = next(item for item in app.hits if item["label"] == "q")
    x = (hit["box"][0] + hit["box"][2]) // 2
    y = (hit["box"][1] + hit["box"][3]) // 2
    app.pointer_down(x, y)
    app.pointer_move(x + 40, y)
    app.pointer_up(x + 40, y)
    assert app.passphrase_text == "q"


def test_a_press_just_left_of_the_key_still_types_a():
    app = App()
    app.screen = "seed"
    app.render()
    hit = next(item for item in app.hits if item["label"] == "a")
    assert hit["box"][0] == 0
    y = (hit["box"][1] + hit["box"][3]) // 2
    app.tap(23, y)
    assert app.word_prefix == "a"


def test_seed_entry_starts_with_a_keyboard():
    app = App()
    app.screen = "seed"
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert "q" in labels
    assert "a" in labels
    assert "backspace" in labels
    assert "x" not in labels
    bottom = next(hit["box"] for hit in app.hits if hit["label"] == "b")
    assert bottom[3] == HEIGHT
    assert bottom[1] < app._seed_keyboard_top() + 2 * (64 + 6)
    app.seed_length = 24
    app.render()
    assert any(hit["label"] == "24 words" and hit["action"] == "dropdown-seed-length" for hit in app.hits)


def test_typing_a_letter_updates_the_keyboard_without_redrawing_the_screen():
    app = App()
    app.screen = "seed"
    app.render()
    app._seed_key("a")
    patched = app.render().copy()
    assert app.dirty is not None
    assert app.dirty[1] - app.dirty[0] < HEIGHT
    app._seed_picture = None
    full = app.render()
    assert patched.tobytes() == full.tobytes()
    app._act("dropdown-seed-length")
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert {"12 words", "18 words", "24 words"} <= labels
    assert "backspace" in labels


def test_changing_seed_length_keeps_entered_words():
    app = App()
    app.screen = "seed"
    app.seed_length = 24
    app.seed_words = ["abandon"] * 15
    app.word_prefix = "ab"
    app.word_cursor = 2
    app._act("dropdown-pick-seed-length-18")
    assert app.seed_length == 18
    assert app.seed_words == ["abandon"] * 15
    assert app.word_prefix == "ab"
    app._act("dropdown-pick-seed-length-12")
    assert app.seed_length == 12
    assert app.seed_words == ["abandon"] * 11
    assert app.word_prefix == ""
    app.seed_length = 24
    app.seed_words = ["abandon"] * 20
    app._act("dropdown-pick-seed-length-18")
    assert app.seed_words == ["abandon"] * 17
    app.seed_words = ["ability"] * 4
    app.word_prefix = "z"
    app._act("dropdown-pick-seed-length-24")
    assert app.seed_length == 24
    assert app.seed_words == ["ability"] * 4
    assert app.word_prefix == "z"


def test_short_prefix_replaces_the_keyboard_with_words():
    app = App()
    app.screen = "seed"
    for letter in "aban":
        app._seed_key(letter)
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert "abandon" in labels
    assert "q" not in labels
    assert "backspace" in labels


def test_last_word_choices_match_the_checksum_without_rescanning_every_letter():
    from embit.bip39 import mnemonic_is_valid

    from bigsigner.ui.app import _WORD_INDEX, _phrase_checksum_ok

    app = App()
    app.seed_words = ["abandon"] * 11
    choices = app._seed_choices()
    again = app._seed_choices()
    assert again is choices
    assert "about" in choices
    assert "abandon" not in choices
    indexes = [_WORD_INDEX[word] for word in app.seed_words]
    for word in ("about", "abandon", "zoo", "ability"):
        phrase = " ".join(app.seed_words + [word])
        assert _phrase_checksum_ok(indexes + [_WORD_INDEX[word]]) is mnemonic_is_valid(phrase)


def test_last_word_must_match_the_checksum():
    app = App()
    app.screen = "seed"
    app.seed_words = ["abandon"] * 11
    matches = app._seed_matches()
    assert "about" in matches
    assert "abandon" not in matches
    app._pick_word("abandon")
    assert app.seed_words == ["abandon"] * 11
    app._pick_word("about")
    assert app.seed_words[-1] == "about"
    assert app.screen == "passphrase-ask"
    app._act("passphrase-no")
    assert app.screen == "key"


def test_overflowing_seed_words_scroll_and_stay_on_the_last_word():
    app = App()
    app.screen = "seed"
    app.seed_length = 24
    app.seed_words = ["abandon"] * 14
    app.word_prefix = "fu"
    bottom = app.render()
    assert app.seed_grid_max > 0
    assert app.seed_grid_scroll == app.seed_grid_max
    box = app.seed_grid_box
    x = 30
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y + 90)
    assert app.seed_grid_stick is False
    assert app.seed_grid_scroll < app.seed_grid_max
    app.pointer_up(x, y + 90)
    earlier = app.render()
    assert earlier.tobytes() != bottom.tobytes()
    assert app.seed_grid_scroll < app.seed_grid_max
    app._pick_word("fun")
    app.render()
    assert app.seed_words[-1] == "fun"
    assert app.seed_grid_stick is True
    assert app.seed_grid_scroll == app.seed_grid_max


def test_entered_words_use_one_column():
    app = App()
    app.screen = "seed"
    app.seed_words = ["abandon", "ability", "able", "about"]
    image = app.render()
    inset = MARGIN
    pad_x = 16
    cell_w = WIDTH - 2 * inset
    draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    size = _grid_font_size(draw, cell_w - 2 * pad_x)
    narrow = (WIDTH - 2 * inset - 8) // 2 - 8
    face = ui_font(size, mono=True)
    assert size > _grid_font_size(draw, narrow)
    assert ImageDraw.Draw(image).textlength("24. business", font=face) <= cell_w - 2 * pad_x
    top = HEADER + 12 + 64 + 12
    cell_h = size + 28
    row_y = top + cell_h // 2
    assert image.getpixel((WIDTH // 2, row_y))[:3] == WHITE
    assert image.getpixel((WIDTH - inset - 8, row_y))[:3] == WHITE
    assert image.getpixel((WIDTH - 4, row_y))[:3] == PAPER
    assert any(
        image.getpixel((WIDTH // 2, y))[:3] == PAPER
        for y in range(row_y, min(HEIGHT - 1, row_y + cell_h))
    )


def test_shown_seed_words_use_one_larger_column():
    app = App()
    added = app.session.add_mnemonic(WORDS)
    app.selected_fp = added["fingerprint"]
    app._open_seed_show()
    image = app.render()
    assert app.screen == "seed-show"
    assert app.seed_grid_max > 0
    inset = MARGIN
    cell_w = WIDTH - 2 * inset
    draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    size = _grid_font_size(draw, cell_w - 32)
    narrow = (WIDTH - 2 * inset - 8) // 2 - 8
    assert size > _grid_font_size(draw, narrow)
    assert size >= 32
    top = HEADER + 16
    cell_h = size + 28
    row_y = top + cell_h // 2
    assert image.getpixel((WIDTH - inset - 8, row_y))[:3] == WHITE
    assert image.getpixel((WIDTH - 4, row_y))[:3] == PAPER


def test_a_24_word_seed_scrolls_the_word_cards():
    words = ["abandon"] * 23 + ["art"]
    app = App()
    added = app.session.add_mnemonic(words)
    app.selected_fp = added["fingerprint"]
    app._open_seed_show()
    app.render()
    assert app.seed_grid_max > 0
    assert app.seed_grid_scroll == 0
    box = app.seed_grid_box
    assert box == (0, HEADER + 16, WIDTH, HEIGHT - 110)
    x = MARGIN + 30
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    assert app.pointer_move(x, y - 90)
    assert 0 < app.seed_grid_scroll < app.seed_grid_max
    app.seed_grid_scroll = app.seed_grid_max
    image = app.render()
    assert any(hit["action"] == "seed-format-next" for hit in app.hits)
    assert image.getpixel((MARGIN + 24, HEIGHT - 120))[:3] == WHITE


def test_a_long_passphrase_field_shows_its_last_characters():
    from bigsigner.ui.canvas import BLUE, INK, TITLE_SIZE, font

    phrase = "abcdefghijklmnopqrstuvwxy"
    app = App()
    app.screen = "passphrase"
    app.passphrase_text = phrase
    app.passphrase_cursor = len(phrase)
    image = app.render()
    face = font(TITLE_SIZE, mono=True)
    draw = ImageDraw.Draw(image)
    room = WIDTH - 2 * MARGIN - 28
    shown, shown_cursor, start = app._passphrase_window(draw, face, room)
    assert start > 0
    assert phrase.endswith(shown)
    assert shown_cursor == len(shown)
    assert draw.textbbox((0, 0), shown, font=face)[2] <= room
    assert not shown.startswith("a")
    right_ink = [
        x
        for y in range(HEADER, 360)
        for x in range(WIDTH - MARGIN + 1, WIDTH)
        if image.getpixel((x, y))[:3] in (INK, BLUE)
    ]
    assert right_ink == []


def test_passphrase_copy_uses_the_same_words():
    app = App()
    added = app.session.add_mnemonic(WORDS)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app.render()
    assert any("with a passphrase" in hit["label"] for hit in app.hits)
    app._act("copy-passphrase")
    assert app.screen == "passphrase"
    for letter in "secret":
        app._passphrase_key(letter)
    app._act("passphrase-save")
    assert app.screen == "key"
    assert len(app.session.fingerprints) == 2
    copied = app.session.fingerprints[app.selected_fp]
    assert copied.keys[0].passphrase == "secret"
    assert copied.keys[0].mnemonic == WORDS


def _muted_pixels(image):
    return [
        (x, y)
        for y in range(HEADER, HEIGHT)
        for x in range(WIDTH)
        if image.getpixel((x, y))[:3] == MUTED
    ]


def test_a_spaceless_passphrase_breaks_inside_the_screen():
    phrase = "m" * 80
    app = App()
    added = app.session.add_mnemonic(WORDS, passphrase=phrase)
    app.selected_fp = added["fingerprint"]
    app.screen = "passphrase-view"
    image = app.render()
    ink = _muted_pixels(image)
    assert ink
    assert max(x for x, _y in ink) <= WIDTH - MARGIN
    assert max(y for _x, y in ink) - min(y for _x, y in ink) > TITLE_SIZE
    lines = wrap(ImageDraw.Draw(image), phrase, ui_font(TITLE_SIZE, mono=True), WIDTH - 2 * MARGIN)
    assert len(lines) > 1
    assert "".join(lines) == phrase


def test_a_passphrase_taller_than_the_screen_scrolls_to_its_end():
    phrase = "m" * 500
    app = App()
    added = app.session.add_mnemonic(WORDS, passphrase=phrase)
    app.selected_fp = added["fingerprint"]
    app.screen = "passphrase-view"
    app.render()
    assert app.scroll_max["passphrase-view"] > 0
    app.scroll["passphrase-view"] = app.scroll_max["passphrase-view"]
    image = app.render()
    ink = _muted_pixels(image)
    assert ink
    assert max(x for x, _y in ink) <= WIDTH - MARGIN
    assert max(y for _x, y in ink) > HEIGHT - 80
    assert min(y for _x, y in ink) > HEADER

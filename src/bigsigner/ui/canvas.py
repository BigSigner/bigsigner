"""Drawing surface for the 480×800 portrait panel."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH = 480
HEIGHT = 800
HEADER = 88
MARGIN = 20
# The title bar is 32px. Paragraphs and buttons are a step larger.
TITLE_SIZE = 32
BODY_SIZE = 36

INK = (22, 26, 31)
MUTED = (90, 98, 110)
PAPER = (246, 247, 249)
WHITE = (255, 255, 255)
NAVY = (18, 36, 58)
BLUE = (24, 92, 184)
LIGHT_BLUE = (58, 146, 216)
RED = (168, 36, 42)
WARNING = (138, 96, 0)
GREEN = (20, 110, 78)
LINE = (214, 218, 224)
# Text cut off because it does not fit ends with this one character.
ELLIPSIS = "\u2026"

ROOT = Path(__file__).resolve().parents[1] / "resources"
_FONTS: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


_LOGO: Image.Image | None = None
_LOGO_FIT: dict[tuple[int, int], Image.Image] = {}


def logo(max_width: int, max_height: int) -> Image.Image:
    """The logo scaled to fit, decoded once.

    The source is much larger than the panel. Opening and scaling it on every
    paint costs about a second on a Pi Zero.
    """
    global _LOGO
    key = (max_width, max_height)
    fitted = _LOGO_FIT.get(key)
    if fitted is not None:
        return fitted
    if _LOGO is None:
        _LOGO = Image.open(ROOT / "logo.png").convert("RGBA")
    fitted = _LOGO.copy()
    fitted.thumbnail((max_width, max_height))
    _LOGO_FIT[key] = fitted
    return fitted


def font(size: int, mono: bool = False) -> ImageFont.ImageFont:
    name = "DejaVuSansMono.ttf" if mono else "DejaVuSans.ttf"
    return _font(name, size)


def icon_font(size: int, awesome: bool = False) -> ImageFont.FreeTypeFont:
    name = "Font_Awesome_6_Free-Solid-900.otf" if awesome else "seedsigner-icons.otf"
    return _font(name, size)


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    """Load each size once. Opening the file again on every line is slow on a Pi Zero."""
    key = (name, size)
    face = _FONTS.get(key)
    if face is None:
        face = ImageFont.truetype(str(ROOT / name), size)
        _FONTS[key] = face
    return face


class Icons:
    """Glyphs in seedsigner-icons.otf. Code points match SeedSignerIconConstants."""

    CAMERA = "\uf030"  # Font Awesome, the same camera glyph SeedSigner uses
    DICE = "\uf522"  # Font Awesome dice
    COINS = "\uf51e"  # Font Awesome coins
    EYE = "\uf06e"  # Font Awesome eye, for a key expression that is not a seed
    SEED = "\uf4d8"  # Font Awesome seedling
    SCAN = "\ue900"
    KEY = "\ue901"
    BACK = "\ue904"
    CHECKBOX = "\ue906"
    CHECKBOX_SELECTED = "\ue907"
    CHEVRON_DOWN = "\ue908"
    CHEVRON_UP = "\ue90b"
    CLOSE = "\ue90c"
    PLUS = "\ue90f"
    FINGERPRINT = "\ue91a"


def _break_token(draw: ImageDraw.ImageDraw, word: str, face, width: int) -> list[str]:
    """Split a token that is wider than the line. Shorter tokens stay whole."""
    if word == "" or draw.textlength(word, font=face) <= width:
        return [word]
    pieces = []
    rest = word
    while rest:
        # The longest prefix that fits, found by halving. Measuring one more
        # character at a time costs a FreeType call per character of an xpub.
        low, high = 1, len(rest)
        while low < high:
            middle = (low + high + 1) // 2
            if draw.textlength(rest[:middle], font=face) <= width:
                low = middle
            else:
                high = middle - 1
        pieces.append(rest[:low])
        rest = rest[low:]
    return pieces


def _fit_prefix(draw: ImageDraw.ImageDraw, text: str, face, width: int) -> int:
    """How many leading characters fit. At least one when `text` is not empty."""
    if text == "" or draw.textlength(text, font=face) <= width:
        return len(text)
    low, high = 1, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if draw.textlength(text[:middle], font=face) <= width:
            low = middle
        else:
            high = middle - 1
    return low


def _comma_pieces(word: str) -> list[str]:
    """Split after commas. The comma stays on the piece it ended."""
    if "," not in word:
        return [word]
    parts = word.split(",")
    pieces = []
    for index, part in enumerate(parts):
        if index < len(parts) - 1:
            pieces.append(part + ",")
        elif part:
            pieces.append(part)
    return pieces or [""]


def _pieces_keeping_comma(draw: ImageDraw.ImageDraw, chunk: str, face, width: int) -> list[str]:
    """Break a chunk that ends with a comma. The comma ends a line.

    A space at a break is dropped. A comma is not. When the comma does not fit
    on the same line as every letter before it, those letters break first and
    the comma stays with the last of them.
    """
    if not chunk.endswith(",") or draw.textlength(chunk, font=face) <= width:
        return _break_token(draw, chunk, face, width)
    pieces = []
    rest = chunk
    while rest:
        if draw.textlength(rest, font=face) <= width:
            pieces.append(rest)
            break
        count = _fit_prefix(draw, rest, face, width)
        if count < len(rest) and rest[count] == ",":
            if count > 1 and draw.textlength(rest[count - 1 : count + 1], font=face) <= width:
                pieces.append(rest[: count - 1])
                rest = rest[count - 1 :]
                continue
            pieces.append(rest[: count + 1])
            rest = rest[count + 1 :]
            continue
        pieces.append(rest[:count])
        rest = rest[count:]
    return [piece for piece in pieces if piece]


def wrap(draw: ImageDraw.ImageDraw, text: str, face, width: int) -> list[str]:
    """Break at a space or after a comma.

    The break takes the place of a space. The comma stays on the line it ended.
    A piece with no space or comma that is wider than `width` breaks at the
    character that would overflow.
    """
    lines = []
    for paragraph in text.split("\n"):
        if paragraph == "":
            lines.append("")
            continue
        current = ""
        for word in paragraph.split(" "):
            for chunk_index, chunk in enumerate(_comma_pieces(word)):
                pieces = (
                    _pieces_keeping_comma(draw, chunk, face, width)
                    if chunk.endswith(",")
                    else _break_token(draw, chunk, face, width)
                )
                for piece_index, piece in enumerate(pieces):
                    if piece_index:
                        if current:
                            lines.append(current)
                        current = piece
                        continue
                    if not current:
                        trial = piece
                    elif chunk_index:
                        trial = current + piece
                    else:
                        trial = f"{current} {piece}"
                    if draw.textlength(trial, font=face) <= width:
                        current = trial
                    else:
                        if current:
                            lines.append(current)
                        current = piece
        lines.append(current)
    return lines


_GLYPHS: dict[tuple, tuple[Image.Image, tuple[float, float]] | None] = {}


def glyph_sprite(char: str, size: int, fill: tuple, awesome: bool = False, text: bool = False):
    """A rendered glyph and the center of its ink, drawn once per look.

    `text` draws with the body font instead of an icon font. The ink box comes
    from the alpha channel in C. Reading it pixel by pixel from Python took half
    a second per icon on a Pi Zero. None means the glyph has no ink.
    """
    key = (char, size, fill, awesome, text)
    if key in _GLYPHS:
        return _GLYPHS[key]
    face = font(size) if text else icon_font(size, awesome=awesome)
    left, top, right, bottom = face.getbbox(char)
    width = right - left + 4
    height = bottom - top + 4
    icon = Image.new("RGBA", (width, height), (0, 0, 0, 0))
    ImageDraw.Draw(icon).text((2 - left, 2 - top), char, font=face, fill=(*fill, 255))
    box = icon.getchannel("A").point(lambda alpha: 255 if alpha > 16 else 0).getbbox()
    if box is None:
        result = None
    else:
        # getbbox is exclusive on the right and bottom. The center is of the inked pixels.
        min_x, min_y, right_edge, bottom_edge = box
        result = (icon, ((min_x + right_edge - 1) / 2, (min_y + bottom_edge - 1) / 2))
    _GLYPHS[key] = result
    return result


class Frame:
    def __init__(self):
        self.image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
        self.draw = ImageDraw.Draw(self.image)
        self.hits = []
        self.marks = []

    def hit(self, box, action: str, label: str = ""):
        self.hits.append({"box": box, "action": action, "label": label})

    def mark(self, text: str, box) -> None:
        """Remember where a string was drawn, so a device test can find it."""
        self.marks.append({"text": text, "box": [int(box[0]), int(box[1]), int(box[2]), int(box[3])]})

    def header(self, title: str, left: str | None = None):
        self.draw.rectangle((0, 0, WIDTH, HEADER), fill=NAVY)
        face = font(TITLE_SIZE)
        if left is None:
            width = self.draw.textlength(title, font=face)
            x = (WIDTH - width) / 2
            self.draw.text((x, 28), title, font=face, fill=WHITE)
            self.mark(title, self.draw.textbbox((x, 28), title, font=face))
            return
        self.draw.text((84, 28), title, font=face, fill=WHITE)
        self.mark(title, self.draw.textbbox((84, 28), title, font=face))
        self.hit((0, 0, 84, HEADER), left, left)
        if left == "menu":
            self.draw.text((26, 24), "≡", font=font(36), fill=WHITE)
        else:
            self.glyph(Icons.BACK, 42, HEADER / 2, 42, WHITE)

    def button_height(self, text: str, icon: bool = False) -> int:
        """The button's box height, without the 12px gap `button` leaves under it."""
        _face, _lines, _line_h, height, _text_delta, _icon_size, _icon_gap = self._button_metrics(text, icon)
        return height

    def _button_metrics(self, text: str, icon: bool):
        face = font(BODY_SIZE)
        icon_size = BODY_SIZE
        icon_gap = 12
        text_width_limit = WIDTH - 2 * MARGIN - 32 - (icon_size + icon_gap if icon else 0)
        lines = wrap(self.draw, text, face, text_width_limit)
        line_h = BODY_SIZE + 6
        # The space under a one-line button's ink. A longer label keeps that
        # same space under its last line, and the same space above its first.
        boxes = [self.draw.textbbox((0, 0), line, font=face) for line in lines]

        def edge_gap(box) -> float:
            ink_h = box[3] - box[1]
            return (BODY_SIZE + 36 - ink_h) / 2

        text_delta = edge_gap(boxes[0]) - boxes[0][1]
        last_ink_bottom = text_delta + (len(lines) - 1) * line_h + boxes[-1][3]
        height = round(last_ink_bottom + edge_gap(boxes[-1]))
        return face, lines, line_h, height, text_delta, icon_size, icon_gap

    def button(self, y: int, text: str, action: str, color=BLUE, label: str = "", icon: str | None = None, awesome: bool = False, enabled: bool = True):
        face, lines, line_h, height, text_delta, icon_size, icon_gap = self._button_metrics(text, icon is not None)
        text_top = y + text_delta
        box = (MARGIN, y, WIDTH - MARGIN, y + height)
        text_fill = WHITE
        if not enabled:
            color = (186, 190, 196)
            text_fill = (132, 136, 142)
        self.draw.rounded_rectangle(box, radius=14, fill=color)
        if icon:
            text_width = max(self.draw.textlength(line, font=face) for line in lines)
            content_left = (WIDTH - text_width - icon_size - icon_gap) / 2
            self.glyph(icon, content_left + icon_size / 2, y + height / 2, icon_size, text_fill, awesome=awesome)
            text_left = content_left + icon_size + icon_gap
            for index, line in enumerate(lines):
                self.draw.text((text_left, text_top + index * line_h), line, font=face, fill=text_fill)
        else:
            for index, line in enumerate(lines):
                width = self.draw.textlength(line, font=face)
                self.draw.text(((WIDTH - width) / 2, text_top + index * line_h), line, font=face, fill=text_fill)
        if enabled:
            self.hit(box, action, label or text)
        return y + height + 12

    def button_box(self, box, text: str, action: str, color=BLUE, text_delta: float | None = None):
        """A button drawn in a given box, with the same label placement as `button`.

        ``text_delta`` pins the baseline. Side-by-side labels share one value so a
        descender in one word does not lift that word above the other.
        """
        face, lines, line_h, _height, own_delta, _icon_size, _icon_gap = self._button_metrics(text, False)
        if text_delta is None:
            text_delta = own_delta
        text_top = box[1] + text_delta
        self.draw.rounded_rectangle(box, radius=14, fill=color)
        for index, line in enumerate(lines):
            width = self.draw.textlength(line, font=face)
            self.draw.text(((box[0] + box[2] - width) / 2, text_top + index * line_h), line, font=face, fill=WHITE)
        self.hit(box, action, text)

    def fingerprint_icon(self, x: int, y: int, size: int = 28, fill=MUTED):
        self.glyph(Icons.FINGERPRINT, x + size / 2, y + size / 2, size, fill)

    def leading_icon(self, icon: str, x: int, y: int, text_size: int, fill, awesome: bool = False, mono: bool = False, icon_size: int | None = None) -> int:
        """Draw an icon centered on the text line that starts at y. Returns the text x."""
        drawn = text_size if icon_size is None else icon_size
        face = font(text_size, mono=mono)
        _left, top, _right, bottom = self.draw.textbbox((0, 0), "Ag", font=face)
        self.glyph(icon, x + drawn / 2, y + (top + bottom) / 2, drawn, fill, awesome=awesome)
        return x + drawn + 12

    def fingerprint_line(self, y: int, fingerprint_hex: str, text_size: int = 22, icon_size: int = 28, left: int = MARGIN):
        size = icon_size
        self.fingerprint_icon(left, y, size)
        label = "Fingerprint: "
        label_face = font(text_size)
        hex_face = font(text_size, mono=True)
        _left, top, _right, bottom = self.draw.textbbox((0, 0), label, font=label_face)
        text_y = y + (size - (bottom - top)) / 2 - top
        x = left + size + 10
        self.draw.text((x, text_y), label, font=label_face, fill=MUTED)
        x += self.draw.textlength(label, font=label_face)
        self.draw.text((x, text_y), fingerprint_hex, font=hex_face, fill=MUTED)
        return y + size + 16

    def glyph(self, char: str, cx: float, cy: float, size: int, fill, awesome: bool = False):
        rendered = glyph_sprite(char, size, tuple(fill), awesome)
        if rendered is None:
            return
        icon, (center_x, center_y) = rendered
        self.image.paste(icon, (round(cx - center_x), round(cy - center_y)), icon)

    def text(self, value: str, x: int, y: int, size=BODY_SIZE, fill=INK, mono=False, width=None):
        face = font(size, mono=mono)
        lines = wrap(self.draw, value, face, width or WIDTH - x - MARGIN)
        clip_top = getattr(self, "clip_top", HEADER)
        clip_bottom = getattr(self, "clip_bottom", HEIGHT)
        for line in lines:
            # Live frames use clip_top=HEADER so a line that starts under the
            # title bar is not sliced in half. Tile strips use clip_top=0 and
            # must still paint a line that began on the previous tile.
            visible = y < clip_bottom and (
                y >= clip_top or (clip_top == 0 and y + size > clip_top)
            )
            if visible:
                self.draw.text((x, y), line, font=face, fill=fill)
                self.mark(line, self.draw.textbbox((x, y), line, font=face))
            y += size + 8
        return y

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
GREEN = (20, 110, 78)
LINE = (214, 218, 224)

ROOT = Path(__file__).resolve().parents[1] / "resources"
_FONTS: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


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
    current = ""
    for char in word:
        trial = current + char
        if current and draw.textlength(trial, font=face) > width:
            pieces.append(current)
            current = char
        else:
            current = trial
    if current:
        pieces.append(current)
    return pieces


def wrap(draw: ImageDraw.ImageDraw, text: str, face, width: int) -> list[str]:
    lines = []
    for paragraph in text.split("\n"):
        if paragraph == "":
            lines.append("")
            continue
        current = ""
        for word in paragraph.split(" "):
            for index, piece in enumerate(_break_token(draw, word, face, width)):
                if index:
                    if current:
                        lines.append(current)
                    current = piece
                    continue
                trial = piece if not current else f"{current} {piece}"
                if draw.textlength(trial, font=face) <= width:
                    current = trial
                else:
                    if current:
                        lines.append(current)
                    current = piece
        lines.append(current)
    return lines


class Frame:
    def __init__(self):
        self.image = Image.new("RGB", (WIDTH, HEIGHT), PAPER)
        self.draw = ImageDraw.Draw(self.image)
        self.hits = []

    def hit(self, box, action: str, label: str = ""):
        self.hits.append({"box": box, "action": action, "label": label})

    def header(self, title: str, left: str | None = None):
        self.draw.rectangle((0, 0, WIDTH, HEADER), fill=NAVY)
        face = font(TITLE_SIZE)
        if left is None:
            width = self.draw.textlength(title, font=face)
            self.draw.text(((WIDTH - width) / 2, 28), title, font=face, fill=WHITE)
            return
        self.draw.text((84, 28), title, font=face, fill=WHITE)
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
        if len(lines) == 1:
            height = BODY_SIZE + 36
            text_delta = None
        else:
            pad = 12
            height = pad * 2 + line_h * len(lines) - 6
            text_delta = pad
        return face, lines, line_h, height, text_delta, icon_size, icon_gap

    def button(self, y: int, text: str, action: str, color=BLUE, label: str = "", icon: str | None = None, awesome: bool = False, enabled: bool = True):
        face, lines, line_h, height, text_delta, icon_size, icon_gap = self._button_metrics(text, icon is not None)
        if text_delta is None:
            _left, top, _right, bottom = self.draw.textbbox((0, 0), lines[0], font=face)
            text_top = y + (height - (bottom - top)) / 2 - top
        else:
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

    def fingerprint_icon(self, x: int, y: int, size: int = 28, fill=MUTED):
        self.glyph(Icons.FINGERPRINT, x + size / 2, y + size / 2, size, fill)

    def leading_icon(self, icon: str, x: int, y: int, text_size: int, fill, awesome: bool = False, mono: bool = False, icon_size: int | None = None) -> int:
        """Draw an icon centered on the text line that starts at y. Returns the text x."""
        drawn = text_size if icon_size is None else icon_size
        face = font(text_size, mono=mono)
        _left, top, _right, bottom = self.draw.textbbox((0, 0), "Ag", font=face)
        self.glyph(icon, x + drawn / 2, y + (top + bottom) / 2, drawn, fill, awesome=awesome)
        return x + drawn + 12

    def fingerprint_line(self, y: int, fingerprint_hex: str, text_size: int = 22, icon_size: int = 28):
        size = icon_size
        self.fingerprint_icon(MARGIN, y, size)
        label = "Fingerprint: "
        label_face = font(text_size)
        hex_face = font(text_size, mono=True)
        _left, top, _right, bottom = self.draw.textbbox((0, 0), label, font=label_face)
        text_y = y + (size - (bottom - top)) / 2 - top
        x = MARGIN + size + 10
        self.draw.text((x, text_y), label, font=label_face, fill=MUTED)
        x += self.draw.textlength(label, font=label_face)
        self.draw.text((x, text_y), fingerprint_hex, font=hex_face, fill=MUTED)
        return y + size + 16

    def glyph(self, char: str, cx: float, cy: float, size: int, fill, awesome: bool = False):
        face = icon_font(size, awesome=awesome)
        left, top, right, bottom = face.getbbox(char)
        width = right - left + 4
        height = bottom - top + 4
        icon = Image.new("RGBA", (width, height), (0, 0, 0, 0))
        ImageDraw.Draw(icon).text((2 - left, 2 - top), char, font=face, fill=(*fill, 255))
        ink = []
        for y in range(height):
            for x in range(width):
                if icon.getpixel((x, y))[3] > 16:
                    ink.append((x, y))
        if not ink:
            return
        min_x = min(point[0] for point in ink)
        max_x = max(point[0] for point in ink)
        min_y = min(point[1] for point in ink)
        max_y = max(point[1] for point in ink)
        self.image.paste(icon, (round(cx - (min_x + max_x) / 2), round(cy - (min_y + max_y) / 2)), icon)

    def text(self, value: str, x: int, y: int, size=BODY_SIZE, fill=INK, mono=False, width=None):
        face = font(size, mono=mono)
        lines = wrap(self.draw, value, face, width or WIDTH - x - MARGIN)
        for line in lines:
            # A scrolled line that starts under the title bar would be sliced in half.
            if y >= HEADER:
                self.draw.text((x, y), line, font=face, fill=fill)
            y += size + 8
        return y

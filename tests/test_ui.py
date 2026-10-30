import json
import time
from pathlib import Path

from PIL import Image, ImageDraw

from bigsigner.ui.app import (
    BOOT_HOLD,
    QR_ZOOM_BAND,
    QR_ZOOM_CELL,
    QR_ZOOM_COUNT,
    QR_ZOOM_RIGHT,
    App,
    _zoom_grid_box,
    _zoom_index_size,
)
from bigsigner.ui.canvas import BODY_SIZE, HEADER, HEIGHT, INK, LINE, MARGIN, MUTED, NAVY, PAPER, TITLE_SIZE, WHITE, WIDTH, font, wrap

PINK = (255, 20, 147)


def write_screenshot_index(folder: Path):
    names = sorted(path.name for path in folder.glob("*.png"))
    if not names:
        return
    (folder / "index.html").write_text(_gallery_html(names), encoding="utf-8")


def _gallery_html(names: list[str]) -> str:
    images = json.dumps(names)
    return f"""<!doctype html>
<meta charset="utf-8">
<title>Screenshots</title>
<style>
  body {{ margin: 0; background: #111; color: #eee; font-family: sans-serif; }}
  main {{
    box-sizing: border-box;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 16px;
    gap: 12px;
  }}
  img {{
    width: 51.84mm;
    height: auto;
    aspect-ratio: 480 / 800;
    background: white;
  }}
  #size {{ display: flex; gap: 8px; align-items: center; }}
  #size button {{ width: auto; background: transparent; color: #ddd; border: 1px solid #555; border-radius: 8px; font: 14px/1 sans-serif; padding: 8px 12px; cursor: pointer; }}
  #size-note {{ margin: 0; max-width: 52mm; color: #9a9a9a; font: 13px/1.4 sans-serif; text-align: center; }}
  .controls {{ display: flex; gap: 12px; justify-content: center; }}
  .controls button {{
    box-sizing: border-box;
    width: 9em;
    font: 16px sans-serif;
    padding: 10px 18px;
  }}
  button:disabled {{ opacity: 0.4; }}
</style>
<main>
  <img id="shot" alt="">
  <div id="size">
    <button type="button" id="smaller" title="Smaller">−</button>
    <button type="button" id="size-label" title="Reset to the Waveshare picture size"></button>
    <button type="button" id="larger" title="Larger">+</button>
  </div>
  <p id="size-note">The 4 inch Waveshare picture is 51.8 mm wide. Match a ruler, then leave it.</p>
  <div class="controls">
    <button id="prev" type="button">Previous</button>
    <button id="next" type="button">Next</button>
  </div>
</main>
<script>
const images = {images};
const shot = document.getElementById("shot");
const prev = document.getElementById("prev");
const next = document.getElementById("next");
const PANEL_WIDTH_MM = 51.84;
const SIZE_KEY = "bigsigner-panel-scale";
let current = 0;
let zoom = 1;
function readHash(count) {{
  const params = new URLSearchParams(location.hash.slice(1));
  let shotNumber = Number(params.get("shot"));
  if (!Number.isInteger(shotNumber) || shotNumber < 1 || shotNumber > count) shotNumber = 1;
  const raw = params.has("zoom") ? Number(params.get("zoom")) : Number(localStorage.getItem(SIZE_KEY));
  const scale = Number.isFinite(raw) && raw >= 0.6 && raw <= 1.8 ? raw : 1;
  return {{ index: shotNumber - 1, scale: Math.round(scale * 100) / 100 }};
}}
function writeHash() {{
  const hash = "#shot=" + (current + 1) + "&zoom=" + zoom;
  if (location.hash === hash) return;
  try {{
    history.replaceState(null, "", hash);
  }} catch (error) {{
    location.hash = hash;
  }}
}}
function panelScale() {{
  return zoom;
}}
function applyPanelSize(scale) {{
  zoom = scale;
  shot.style.width = (PANEL_WIDTH_MM * scale) + "mm";
  const label = document.getElementById("size-label");
  label.textContent = scale === 1 ? "51.8 × 86.4 mm" : Math.round(scale * 100) + "%";
}}
function setPanelScale(scale) {{
  const next = Math.round(Math.min(1.8, Math.max(0.6, scale)) * 100) / 100;
  localStorage.setItem(SIZE_KEY, String(next));
  applyPanelSize(next);
  writeHash();
}}
const start = readHash(images.length);
applyPanelSize(start.scale);
document.getElementById("smaller").addEventListener("click", () => setPanelScale(panelScale() - 0.02));
document.getElementById("larger").addEventListener("click", () => setPanelScale(panelScale() + 0.02));
document.getElementById("size-label").addEventListener("click", () => setPanelScale(1));

function show(index) {{
  current = index;
  shot.src = images[current];
  shot.alt = images[current];
  prev.disabled = current === 0;
  next.disabled = current === images.length - 1;
  writeHash();
}}

prev.addEventListener("click", () => {{
  if (current > 0) show(current - 1);
}});
next.addEventListener("click", () => {{
  if (current < images.length - 1) show(current + 1);
}});
window.addEventListener("hashchange", () => {{
  const state = readHash(images.length);
  applyPanelSize(state.scale);
  show(state.index);
}});
show(start.index);
</script>
"""


def test_screenshot_gallery_uses_the_waveshare_picture_size():
    page = _gallery_html(["001-boot.png"])
    assert "51.84" in page
    assert "bigsigner-panel-scale" in page
    assert "001-boot.png" in page
    assert "max-height" not in page
    assert "history.replaceState" in page
    assert "#shot=" in page
    assert "&zoom=" in page


def row_color(app: App, label: str):
    app.menu = True
    image = app.render()
    box = next(hit["box"] for hit in app.hits if hit["label"] == label)
    x = 290
    y = (box[1] + box[3]) // 2
    return image.getpixel((x, y))[:3]


def test_menu_highlights_the_page_that_owns_the_back_stack():
    app = App()
    app.screen = "keys"
    assert row_color(app, "Bitcoin Keys") != (255, 255, 255)
    assert row_color(app, "Bitcoin Wallets") == (255, 255, 255)

    app.back = ["keys", "key"]
    app.screen = "qr"
    assert row_color(app, "Bitcoin Keys") != (255, 255, 255)
    assert row_color(app, "About") == (255, 255, 255)

    app.back = ["wallets", "wallet"]
    app.screen = "addresses"
    assert row_color(app, "Bitcoin Wallets") != (255, 255, 255)
    assert row_color(app, "Bitcoin Keys") == (255, 255, 255)


def test_the_sd_card_screen_shows_the_logo_above_the_text():
    from bigsigner import __version__

    from bigsigner.ui.canvas import logo

    app = App()
    app.screen = "warning"
    image = app.render()
    # The logo is the orange mark. The version sits under it, and Continue stays.
    assert image.getpixel((WIDTH // 2, HEADER + 60))[0] > 180
    assert image.getpixel((MARGIN + 8, HEADER + 220))[:3] == PAPER
    version = f"Version {__version__}"
    face = font(24)
    version_width = int(ImageDraw.Draw(image).textlength(version, font=face))
    version_left = (WIDTH - version_width) // 2
    version_y = HEADER + 24 + logo(WIDTH - 48, 180).height + 12
    ink = [
        image.getpixel((x, y))[:3]
        for y in range(version_y, version_y + 24)
        for x in range(version_left, version_left + version_width)
        if image.getpixel((x, y))[:3] != PAPER
    ]
    assert ink
    assert max(ink, key=ink.count) == MUTED
    assert any(hit["action"] == "warning-ok" for hit in app.hits)


def test_continue_from_the_sd_card_screen_opens_the_sidebar():
    app = App()
    app.screen = "warning"
    app._act("warning-ok")
    assert app.screen == "keys"
    assert app.menu is True


def test_initial_seed_loads_when_boot_finishes(monkeypatch):
    words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    monkeypatch.setenv("BIGSIGNER_INITIAL_SEED", words.replace(" ", ", "))
    app = App()
    app.render()
    assert app.session.fingerprints == {}
    app.tap(240, 400)
    assert app.screen == "warning"
    record = next(iter(app.session.fingerprints.values()))
    assert record.keys[0].mnemonic == words.split()
    from bigsigner.names import animal_name

    assert record.nickname == animal_name(record.fingerprint)

    timed = App()
    timed.render()
    timed.boot_until = time.monotonic() - 1
    timed.render()
    assert timed.screen == "warning"
    assert len(timed.session.fingerprints) == 1


def test_initial_seed_accepts_18_and_24_words_and_reports_a_bad_phrase(monkeypatch):
    from embit.bip39 import mnemonic_from_bytes

    for size in (24, 32):
        phrase = mnemonic_from_bytes(b"\x11" * size)
        monkeypatch.setenv("BIGSIGNER_INITIAL_SEED", phrase)
        app = App()
        app.render()
        app.tap(240, 400)
        assert next(iter(app.session.fingerprints.values())).keys[0].mnemonic == phrase.split()

    monkeypatch.setenv("BIGSIGNER_INITIAL_SEED", "abandon abandon")
    rejected = App()
    rejected.render()
    rejected.tap(240, 400)
    assert rejected.session.fingerprints == {}
    assert "12, 18, or 24" in rejected.notice


def test_initial_wallet_descriptor_loads_when_boot_finishes(monkeypatch):
    from test_domain import expression

    descriptor = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    monkeypatch.setenv("BIGSIGNER_INITIAL_WALLET_DESCRIPTOR", descriptor)
    app = App()
    app.render()
    assert app.session.wallets == []
    app.tap(240, 400)
    assert app.screen == "warning"
    assert len(app.session.wallets) == 1
    assert not app.session.wallets[0].multisig
    assert app.wallet_index == 0
    assert len(app.session.fingerprints) == 1
    assert "wallet" in app.notice.lower()


def test_initial_wallet_descriptor_accepts_bsms_and_rejects_a_seed(monkeypatch):
    monkeypatch.setenv(
        "BIGSIGNER_INITIAL_WALLET_DESCRIPTOR",
        Path("emulator-sdcard/My SeedSigner Trezor Wallet.bsms").read_text(encoding="utf-8"),
    )
    app = App()
    app.render()
    app.tap(240, 400)
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].multisig
    assert app.session.wallets[0].threshold == 2

    monkeypatch.setenv("BIGSIGNER_INITIAL_WALLET_DESCRIPTOR", ABANDON)
    rejected = App()
    rejected.render()
    rejected.tap(240, 400)
    assert rejected.session.wallets == []
    assert "BIGSIGNER_INITIAL_WALLET_DESCRIPTOR" in rejected.notice
    assert "seed" in rejected.notice.lower()


def test_initial_seed_is_loaded_before_the_wallet_descriptor(monkeypatch):
    from test_domain import expression

    monkeypatch.setenv("BIGSIGNER_INITIAL_SEED", ABANDON.replace(" ", ", "))
    monkeypatch.setenv(
        "BIGSIGNER_INITIAL_WALLET_DESCRIPTOR",
        f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})",
    )
    app = App()
    app.render()
    app.tap(240, 400)
    record = next(iter(app.session.fingerprints.values()))
    assert record.keys[0].has_seed
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].fingerprints == (record.fingerprint,)


def test_boot_advances_when_startup_is_finished():
    app = App()
    assert app.boot_until is None
    started = time.monotonic()
    app.render()
    assert app.screen == "boot"
    assert app.boot_until >= started + BOOT_HOLD - 0.05
    assert any(hit["action"] == "boot" for hit in app.hits)
    app.tap(240, 400)
    assert app.screen == "warning"

    held = App()
    held.render()
    assert held.screen == "boot"
    held.boot_until = time.monotonic() - 1
    held.render()
    assert held.screen == "warning"


def test_confirm_dialog_cancels_outside_the_box():
    app = App()
    app.screen = "key"
    app.confirm = "show-seed"
    image = app.render()
    assert image.getpixel((10, 10)) != (255, 255, 255)
    cancel = next(hit["box"] for hit in app.hits if hit["label"] == "Cancel")
    confirm = next(hit["box"] for hit in app.hits if hit["label"] == "Confirm")
    assert cancel[2] <= confirm[0]
    assert image.getpixel(((cancel[0] + cancel[2]) // 2, (cancel[1] + cancel[3]) // 2))[2] < 180
    app.tap(10, 10)
    assert app.confirm is None

    app.confirm = "show-seed"
    app.render()
    dialog = next(hit["box"] for hit in app.hits if hit["label"] == "dialog")
    app.tap((dialog[0] + dialog[2]) // 2, dialog[1] + 30)
    assert app.confirm == "show-seed"


class ScreenRecord:
    """Numbered stills for one test, in that test's own folder."""

    def __init__(self, folder: Path):
        self.folder = folder
        self.folder.mkdir(parents=True, exist_ok=True)
        for old in self.folder.glob("*.png"):
            old.unlink()
        self.index = 0
        self.name = "screen"
        self.image = None

    def shot(self, app: App, name: str):
        self.name = name
        self.image = app.render()
        self._save(self.image)

    def note(self, text: str):
        """A same-size frame for a step the test performed in code, not by tapping."""
        image = Image.new("RGB", (WIDTH, HEIGHT), (255, 255, 255))
        draw = ImageDraw.Draw(image)
        face = font(32)
        y = 80
        for line in wrap(draw, text, face, WIDTH - 80):
            draw.text((40, y), line, font=face, fill=PINK)
            y += 48
        self.name = "note"
        self.image = image
        self._save(image)

    def mark(self, image, x: int, y: int, name: str):
        """Save the screen, then the same screen with a pink circle at the finger."""
        if self.image is None or image.tobytes() != self.image.tobytes():
            self.name = name
            self.image = image
            self._save(image)
        marked = image.copy()
        ImageDraw.Draw(marked).ellipse((x - 12, y - 12, x + 12, y + 12), fill=PINK)
        self.name = name
        self._save(marked)

    def drag(self, app: App, start: tuple[int, int], end: tuple[int, int]):
        """A vertical drag. The pink circle marks the press, then the release."""
        self.mark(app.render(), start[0], start[1], "scroll-down")
        app.pointer_down(*start)
        app.pointer_move(*end)
        app.pointer_up(*end)
        self.mark(app.render(), end[0], end[1], "scroll-up")

    def click(self, app: App, label: str):
        app.render()
        for hit in app.hits:
            if hit["label"] == label or hit["action"] == label:
                left, top, right, bottom = hit["box"]
                x = (left + right) // 2
                y = (top + bottom) // 2
                current = app.render()
                if self.image is None or current.tobytes() != self.image.tobytes():
                    self.name = label
                    self.image = current
                    self._save(current)
                marked = current.copy()
                draw = ImageDraw.Draw(marked)
                radius = 12
                draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=PINK)
                self._save(marked)
                app.tap(x, y)
                return
        raise AssertionError(f"No control named {label}.")

    def _save(self, image):
        self.index += 1
        image.save(self.folder / f"{self.index:03d}-{self.name}.png")
        write_screenshot_index(self.folder)


def test_main_screens_save_screenshots():
    app = App()
    record = ScreenRecord(Path("artifacts/screenshots/test_main_screens_save_screenshots"))

    record.shot(app, "boot")
    # The boot screen moves on by itself after BOOT_HOLD. A loaded machine can
    # take longer than that between the two renders, so hold it for the tap.
    app.boot_until = time.monotonic() + 60
    record.click(app, "boot")
    record.shot(app, "remove-sd")
    record.click(app, "warning-ok")
    record.shot(app, "keys-empty")
    record.shot(app, "menu")
    record.click(app, "About")
    record.shot(app, "about")
    record.click(app, "menu")
    record.click(app, "Settings")
    record.shot(app, "settings")
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    record.note("Loaded the Abandon seed in code and opened its key screen.")
    record.shot(app, "key")
    record.click(app, "derive-native")
    record.click(app, "derive-wallet")
    record.shot(app, "wallet")
    record.click(app, "Addresses")
    record.shot(app, "addresses")
    record.click(app, "back")
    record.click(app, "Show Descriptor")
    record.shot(app, "qr")
    record.click(app, ">")
    record.shot(app, "qr-plain")
    frames = sorted(record.folder.glob("*.png"))
    plain = next(path for path in frames if "remove-sd" in path.name)
    marked = next(path for path in frames if path.name > plain.name)
    assert plain.stat().st_size > 1000
    plains = list(record.folder.glob("*-qr-plain.png"))
    assert len(plains) == 1
    assert plains[0].stat().st_size > 1000
    before = {pixel[:3] for pixel in Image.open(plain).getdata()}
    after = {pixel[:3] for pixel in Image.open(marked).getdata()}
    assert PINK not in before
    assert PINK in after
    page = (record.folder / "index.html").read_text(encoding="utf-8")
    assert "001-boot.png" in page
    assert ">Previous<" in page
    assert ">Next<" in page


def tap(app: App, label: str):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(f"No control named {label}.")


ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_notices_stay_for_four_seconds():
    app = App()
    before = time.monotonic()
    app.set_notice("Saved.")
    assert app.notice_until is not None
    assert 3.5 < app.notice_until - before < 4.5


def test_xpub_key_screen_shows_the_account_and_the_path():
    from test_domain import expression

    from bigsigner.paths import format_path

    def screen(path):
        app = App()
        added = app.session.add_text(expression(ABANDON, path))
        app.selected_fp = added["fingerprint"]
        app.screen = "key"
        key = app.session.fingerprints[added["fingerprint"]].keys[0]
        return app.render(), key

    account0, key0 = screen("m/84h/0h/0h")
    account7, key7 = screen("m/84h/0h/7h")
    assert key0.account == 0
    assert format_path(list(key0.path)) == "m/84h/0h/0h"
    assert key7.account == 7
    assert format_path(list(key7.path)) == "m/84h/0h/7h"
    assert account0.tobytes() != account7.tobytes()


def test_a_long_xpub_wraps_inside_the_screen():
    from test_domain import expression

    from bigsigner.ui.canvas import MARGIN

    app = App()
    added = app.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app.render()
    xpub = app.session.fingerprints[added["fingerprint"]].keys[0].xpub.to_string()
    draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, HEIGHT)))
    face = font(24, mono=True)
    limit = WIDTH - 2 * MARGIN
    lines = wrap(draw, xpub, face, limit)
    assert len(lines) > 1
    assert "".join(lines) == xpub
    assert all(draw.textlength(line, font=face) <= limit for line in lines)


def test_a_singlesig_xpub_can_create_and_reopen_its_wallet():
    from test_domain import expression

    app = App()
    added = app.session.add_text(expression(ABANDON, "m/84h/0h/7h"))
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app.render()
    assert any(hit["label"] == "Go to Native-Segwit SingleSig Wallet" for hit in app.hits)
    app.session.delete_wallet(0)
    app.render()
    assert any(hit["label"] == "Create a Native-Segwit SingleSig Wallet" for hit in app.hits)
    draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, 8)))
    face = font(BODY_SIZE)
    limit = WIDTH - 2 * MARGIN - 32
    for phrase in (
        "Create a Native-Segwit SingleSig Wallet",
        "Go to Native-Segwit SingleSig Wallet",
        "Create a Taproot SingleSig Wallet",
        "Go to Taproot SingleSig Wallet",
    ):
        lines = wrap(draw, phrase, face, limit)
        assert all("Native-Segwit" in line or "Native" not in line for line in lines)
    app._act("make-xpub-wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    assert app.session.wallets[0].accounts[added["fingerprint"]] == 7
    assert "/7h" in app.session.descriptor_text(0)
    app.screen = "key"
    app.render()
    assert any(hit["label"] == "Go to Native-Segwit SingleSig Wallet" for hit in app.hits)
    app._act("make-xpub-wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1

    multisig = App()
    added = multisig.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    multisig.selected_fp = added["fingerprint"]
    multisig.screen = "key"
    multisig.render()
    assert not any(hit["action"] == "make-xpub-wallet" for hit in multisig.hits)


def test_the_key_screen_shows_a_nineteen_character_xpub_prefix():
    from test_domain import expression

    from bigsigner.ui.canvas import MARGIN

    app = App()
    added = app.session.add_text(expression(ABANDON, "m/84h/0h/0h"))
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    image = app.render()
    xpub = app.session.fingerprints[added["fingerprint"]].keys[0].xpub.to_string()
    preview = xpub[:19] + "\u2026"
    assert preview.startswith("xpub6CatWdiZ")
    assert preview == xpub[:19] + "\u2026"
    assert not any(hit["action"] == "toggle-slip" for hit in app.hits)
    assert any(hit["label"] == "Show Full Details" for hit in app.hits)
    from bigsigner.ui.canvas import TITLE_SIZE

    draw = ImageDraw.Draw(image)
    mono = font(TITLE_SIZE, mono=True)
    assert draw.textlength(preview, font=mono) <= WIDTH - 2 * MARGIN


def test_key_qr_shows_a_scroll_hint_before_the_code():
    from test_domain import expression

    app = App()
    added = app.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    before = time.monotonic()
    app._act("show-qr")
    hint = app.render()
    assert app.qr_hint_until is not None
    assert 1.5 < app.qr_hint_until - before < 2.5
    delay = app.notice_delay()
    assert delay is not None and delay <= 2
    assert app.qr_scroll_box is None
    app.qr_hint_until = 0
    code = app.render()
    assert hint.tobytes() != code.tobytes()
    assert app.qr_scroll_box is not None


def test_key_qr_switches_expression_xpub_and_slip_form():
    from test_domain import expression

    app = App()
    added = app.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("show-qr")
    assert app.screen == "qr"
    formats = app._key_qr_formats()
    assert [name for name, _payload in formats] == ["Key Expression", "xpub only", "Zpub"]
    fingerprint = added["fingerprint"].hex()
    expression_text, xpub_text, zpub_text = (payload for _name, payload in formats)
    assert expression_text.startswith(f"[{fingerprint}/48h/0h/0h/2h]xpub")
    assert xpub_text.startswith("xpub")
    assert zpub_text.startswith("Zpub")
    assert expression_text.endswith(xpub_text)
    app.qr_hint_until = 0
    app.render()
    assert app.key_qr_index == 0
    assert any(hit["action"] == "qr-form-next" for hit in app.hits)
    assert any(hit["action"] == "brightness-up" for hit in app.hits)
    assert app.qr_scroll_max > 0
    app.qr_scroll = app.qr_scroll_max
    bottom = app.render()
    view_bottom = app.qr_scroll_box[3]
    gap = TITLE_SIZE + 8
    assert all(bottom.getpixel((WIDTH // 2, y))[:3] != INK for y in range(view_bottom - gap // 2, view_bottom - 2))
    assert any(
        bottom.getpixel((x, view_bottom - gap - 20))[:3] == INK for x in range(MARGIN, WIDTH - MARGIN)
    )
    app.qr_scroll = 0
    top = app.render()
    box = app.qr_scroll_box
    x = (box[0] + box[2]) // 2
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    app.pointer_move(x, y - 80)
    app.pointer_up(x, y - 80)
    assert app.qr_scroll > 0
    assert app.render().tobytes() != top.tobytes()
    app._act("qr-form-next")
    assert app.qr_scroll == 0
    assert app.key_qr_index == 1
    assert app._qr_payload() == xpub_text
    app._act("qr-form-next")
    assert app._qr_payload() == zpub_text
    app._act("qr-form-next")
    assert app._qr_payload() == expression_text
    before = app.qr_brightness
    app._act("brightness-up")
    assert app.qr_brightness == before + 1

    taproot = App()
    added = taproot.session.add_text(expression(ABANDON, "m/86h/0h/0h"))
    taproot.selected_fp = added["fingerprint"]
    taproot.screen = "key"
    taproot._act("show-qr")
    assert [name for name, _payload in taproot._key_qr_formats()] == ["Key Expression", "xpub only"]


def test_xpub_key_screen_names_the_script_and_whether_it_is_multisig():
    from test_domain import expression

    cases = (
        ("m/84h/0h/0h", "Native-Segwit SingleSig"),
        ("m/86h/0h/0h", "Taproot SingleSig"),
        ("m/48h/0h/0h/2h", "Native-Segwit MultiSig"),
    )
    images = []
    for path, kind in cases:
        app = App()
        added = app.session.add_text(expression(ABANDON, path))
        app.selected_fp = added["fingerprint"]
        app.screen = "key"
        key = app.session.fingerprints[added["fingerprint"]].keys[0]
        assert app._external_kind(key) == kind
        images.append(app.render())
    assert len({image.tobytes() for image in images}) == 3


def test_a_key_expression_uses_an_eye_instead_of_a_key():
    from test_domain import expression

    seed = App()
    seed.session.add_mnemonic(ABANDON.split())
    seed.screen = "keys"
    seed_image = seed.render()
    watch = App()
    watch.session.add_text(expression(ABANDON, "m/84h/0h/0h"))
    watch.screen = "keys"
    watch_image = watch.render()

    def icon_pixels(image):
        return [image.getpixel((x, y))[:3] for x in range(18, 48) for y in range(112, 146)]

    assert any(pixel == (22, 26, 31) for pixel in icon_pixels(watch_image))
    assert icon_pixels(seed_image) != icon_pixels(watch_image)


def test_seed_screen_labels_banner_and_wallet_buttons():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app.set_notice(added["message"])
    assert added["message"] == "The seed was added successfully."
    from bigsigner.names import animal_name

    assert app.session.fingerprints[added["fingerprint"]].nickname == animal_name(added["fingerprint"])

    app.scroll["key"] = 10_000
    image = app.render()
    labels = [hit["label"] for hit in app.hits]
    assert "Derive a Native-Segwit SingleSig Key" in labels
    assert "Derive a Native-Segwit MultiSig Key" in labels
    assert "Derive a Taproot SingleSig Key" in labels
    assert not any("SingleSig Wallet" in label for label in labels)
    assert all("hidden" not in label.lower() for label in labels)

    def toast_rows(picture):
        rows = []
        for y in range(560, HEIGHT):
            if picture.getpixel((WIDTH // 2, y))[:3] != (18, 36, 58):
                continue
            covered = any(
                hit["box"][0] <= WIDTH // 2 < hit["box"][2] and hit["box"][1] <= y < hit["box"][3]
                for hit in app.hits
            )
            if not covered:
                rows.append(y)
        return rows

        showing = toast_rows(image)
        assert len(showing) > 20
        assert max(showing) - min(showing) < 90

    def button_color(action):
        box = next(hit["box"] for hit in app.hits if hit["action"] == action)
        return image.getpixel((box[0] + 24, (box[1] + box[3]) // 2))[:3]

    native = button_color("derive-native")
    taproot = button_color("derive-taproot")
    assert native == taproot
    assert native == (24, 92, 184)
    delete = next(hit["box"] for hit in app.hits if hit["action"] == "delete-key")
    toast_navy = [
        y
        for y in range(delete[3], HEIGHT)
        if image.getpixel((WIDTH // 2, y))[:3] == (18, 36, 58)
    ]
    assert toast_navy
    assert max(toast_navy) >= HEIGHT - 30
    assert min(toast_navy) > delete[3]

    app.notice_until = time.monotonic() - 0.01
    image = app.render()
    assert app.notice == ""
    assert len(toast_rows(image)) < 8

    tap(app, "derive-native")
    assert app.screen == "derive"
    tap(app, "derive-wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    app.back_one()
    assert app.screen == "wallets"
    assert app.back == []


def test_seed_account_is_typed_and_xpub_account_is_a_dropdown():
    from test_domain import expression

    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    fingerprint = added["fingerprint"]
    app.selected_fp = fingerprint
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.render()
    assert all("account " not in hit["label"] for hit in app.hits)
    app._act(f"account-edit-{fingerprint.hex()}")
    assert app.screen == "account"
    app._act("account-key-backspace")
    app._act("account-key-1")
    app._act("account-key-5")
    app._act("account-save")
    assert app.screen == "wallet"
    assert app.session.wallets[0].accounts[fingerprint] == 15
    assert "/15h" in app.session.descriptor_text(0)
    app.session.set_account(0, fingerprint, 0)
    image = app.render()
    assert not any(hit["action"] == f"account-dec-{fingerprint.hex()}" for hit in app.hits)
    field = next(hit["box"] for hit in app.hits if hit["action"] == f"account-edit-{fingerprint.hex()}")
    minus_x = field[0] - 12 - 32
    minus_y = (field[1] + field[3]) // 2
    assert image.getpixel((minus_x, minus_y - 16)) == (186, 190, 196)
    app._act(f"account-inc-{fingerprint.hex()}")
    assert app.session.wallets[0].accounts[fingerprint] == 1
    app.render()
    assert any(hit["action"] == f"account-dec-{fingerprint.hex()}" for hit in app.hits)
    app._act(f"account-dec-{fingerprint.hex()}")
    assert app.session.wallets[0].accounts[fingerprint] == 0
    app.session.set_account(0, fingerprint, 0x7FFFFFFF)
    app.render()
    assert not any(hit["action"] == f"account-inc-{fingerprint.hex()}" for hit in app.hits)
    app._act(f"account-dec-{fingerprint.hex()}")
    assert app.session.wallets[0].accounts[fingerprint] == 0x7FFFFFFF - 1

    watch = App()
    first = expression(ABANDON, "m/84h/0h/0h")
    second = expression(ABANDON, "m/84h/0h/4h")
    watch.session.add_text(f"wpkh({first})")
    watch.session.add_text(f"wpkh({second})")
    watch.wallet_index = 0
    watch.screen = "wallet"
    watch.render()
    assert not any(hit["action"].startswith("account-edit-") for hit in watch.hits)
    watch._act(f"dropdown-acct-{fingerprint.hex()}")
    watch.render()
    assert any(hit["label"] == "0 (default)" and hit["action"] == f"dropdown-pick-acct-{fingerprint.hex()}-0" for hit in watch.hits)
    assert any(hit["label"] == "4" and hit["action"] == f"dropdown-pick-acct-{fingerprint.hex()}-4" for hit in watch.hits)
    watch._act(f"dropdown-pick-acct-{fingerprint.hex()}-0")
    assert watch.session.wallets[0].accounts[fingerprint] == 0
    assert "/0h" in watch.session.descriptor_text(0)


def test_leaving_a_singlesig_wallet_forgets_the_account_change():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    fingerprint = added["fingerprint"]
    app.selected_fp = fingerprint
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    assert app.session.wallets[0].accounts[fingerprint] == 0
    app._act(f"account-inc-{fingerprint.hex()}")
    assert app.session.wallets[0].accounts[fingerprint] == 1
    app._act("addresses")
    app._act("back")
    assert app.screen == "wallet"
    assert app.session.wallets[0].accounts[fingerprint] == 1
    app._act("back")
    assert app.screen == "wallets"
    assert app.session.wallets[0].accounts[fingerprint] == 0
    app._act("open-wallet-0")
    assert app.screen == "wallet"
    assert app.session.wallets[0].accounts[fingerprint] == 0


def test_seed_qr_switches_between_compact_and_text():
    from bigsigner.seedqr import compact_bytes

    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("show-seed")
    app._act("confirm-yes")
    assert app.screen == "seed-show"
    assert app.seed_format == 0
    app.render()
    assert not any(hit["action"] == "zoom-in" for hit in app.hits)
    app._act("seed-format-next")
    assert app.seed_format == 1
    assert app._seed_qr_payload() == compact_bytes(ABANDON)
    app.render()
    assert any(hit["action"] == "zoom-in" for hit in app.hits)
    app._act("seed-format-next")
    assert app._seed_qr_payload() == ABANDON.upper()
    app._act("seed-format-next")
    assert app.seed_format == 0
    app._act("seed-format-prev")
    assert app._seed_qr_payload() == ABANDON.upper()


def test_zoomed_qr_has_a_title_and_a_direction_pad():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("show-seed")
    app._act("confirm-yes")
    app._act("seed-format-next")
    app._act("zoom-in")
    image = app.render()
    assert image.getpixel((WIDTH // 2, 30))[:3] == NAVY
    title = [image.getpixel((x, 44))[:3] for x in range(90, 280)]
    assert WHITE in title
    close = next(hit["box"] for hit in app.hits if hit["action"] == "zoom-close")
    assert close[1] == 0 and close[3] == HEADER
    grid_left, grid_top, grid_bottom = _zoom_grid_box()
    assert grid_left + QR_ZOOM_CELL * QR_ZOOM_COUNT == WIDTH - QR_ZOOM_RIGHT
    assert grid_left > 40
    for col in range(QR_ZOOM_COUNT):
        assert image.getpixel((grid_left + col * QR_ZOOM_CELL + QR_ZOOM_CELL - 1, grid_top + 20))[:3] == LINE
    assert not any(hit["action"] == "zoom-up" for hit in app.hits)
    assert not any(hit["action"] == "zoom-left" for hit in app.hits)

    app._act("zoom-right")
    app._act("zoom-down")
    app.render()
    boxes = {hit["action"]: hit["box"] for hit in app.hits}
    up, left, right, down = (boxes[name] for name in ("zoom-up", "zoom-left", "zoom-right", "zoom-down"))
    assert up[0] == down[0] and up[2] == down[2]
    assert left[1] == right[1] and left[3] == right[3]
    assert left[2] < up[0] < up[2] < right[0]
    assert up[3] < left[1] and left[3] < down[1]
    assert up[0] - left[2] == right[0] - up[2] == left[1] - up[3] == down[1] - left[3]
    assert up[2] - up[0] == left[2] - left[0] == right[2] - right[0]
    assert up[1] == grid_bottom + QR_ZOOM_CELL
    center = ((left[2] + right[0]) // 2, (up[3] + down[1]) // 2)
    assert not any(box[0] <= center[0] < box[2] and box[1] <= center[1] < box[3] for box in boxes.values())

    for _ in range(80):
        app.render()
        if not any(hit["action"] == "zoom-right" for hit in app.hits):
            break
        app._act("zoom-right")
    else:
        raise AssertionError("Right never reached the edge of the code.")
    assert app.qr_zoom[0] > 0
    app._act("zoom-close")
    assert app.screen == "seed-show"
    assert app.qr_zoom is None


def _ink_rows(image, box):
    x0, y0, x1, y1 = box
    return [
        y
        for y in range(y0, y1)
        if any(image.getpixel((x, y))[:3] == INK for x in range(x0, x1))
    ]


def test_zoomed_qr_numbers_the_absolute_rows_and_columns():
    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("show-seed")
    app._act("confirm-yes")
    app._act("seed-format-next")
    app._act("zoom-in")
    image = app.render()
    left, top, _bottom = _zoom_grid_box()
    light = image.getpixel((left - 2, top + QR_ZOOM_CELL // 2))[:3]
    for index in range(QR_ZOOM_COUNT):
        row_top = top + index * QR_ZOOM_CELL
        assert _ink_rows(image, (2, row_top + 4, left - 4, row_top + QR_ZOOM_CELL - 4))
        assert image.getpixel((left - 2, row_top + QR_ZOOM_CELL // 2))[:3] == light
        col_left = left + index * QR_ZOOM_CELL
        assert _ink_rows(image, (col_left + 2, HEADER + 2, col_left + QR_ZOOM_CELL - 2, top - 2))
    gutter = [
        image.getpixel((x, y))[:3]
        for y in range(top, top + QR_ZOOM_CELL)
        for x in range(4, left - 4)
    ]
    app._act("zoom-down")
    moved = app.render()
    assert gutter != [
        moved.getpixel((x, y))[:3]
        for y in range(top, top + QR_ZOOM_CELL)
        for x in range(4, left - 4)
    ]
    assert app.qr_zoom == (0, 1)

    app.qr_zoom = (94, 94)
    wide = app.render()
    two = _ink_rows(wide, (left + 2, HEADER + 2, left + QR_ZOOM_CELL - 2, top - 2))
    three_left = left + 5 * QR_ZOOM_CELL
    three = _ink_rows(wide, (three_left + 2, HEADER + 2, three_left + QR_ZOOM_CELL - 2, top - 2))
    assert three and two
    assert max(three) - min(three) < max(two) - min(two)
    slot_w = QR_ZOOM_CELL - 6
    slot_h = min(QR_ZOOM_BAND - 4, QR_ZOOM_CELL - 8)
    assert _zoom_index_size(ImageDraw.Draw(image), 3, slot_w, slot_h) < _zoom_index_size(
        ImageDraw.Draw(image), 2, slot_w, slot_h
    )


def test_settings_picks_a_network_from_the_dropdown():
    app = App()
    app.screen = "settings"
    app.render()
    assert any(hit["label"] == "mainnet" for hit in app.hits)
    assert not any("Switch to" in hit["label"] for hit in app.hits)
    app._act("dropdown-network")
    app.render()
    app._act("dropdown-pick-network-regtest")
    assert app.session.network == "regtest"
    assert app.open_dropdown is None
    app._act("dropdown-network")
    app._act("dropdown-pick-network-main")
    assert app.session.network == "main"


def test_seeds_are_listed_above_external_keys():
    from test_domain import expression

    app = App()
    external = app.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    seed = app.session.add_mnemonic(
        "legal winner thank year wave sausage worth useful legal winner thank yellow".split()
    )
    app.screen = "keys"
    app.render()
    seed_box = next(hit["box"] for hit in app.hits if hit["action"] == f"open-fp-{seed['fingerprint'].hex()}")
    external_box = next(
        hit["box"] for hit in app.hits if hit["action"] == f"open-fp-{external['fingerprint'].hex()}-0"
    )
    assert seed_box[1] < external_box[1]
    titles = [title for title, _icon, _awesome, items in app._key_sections() if items]
    assert titles == ["Seeds", "MultiSig External Keys"]
    assert app._external_script(app.session.fingerprints[external["fingerprint"]].keys[0]) == "Native-Segwit"


def test_keys_are_listed_in_the_order_they_were_added():
    from test_domain import expression

    other = "legal winner thank year wave sausage worth useful legal winner thank yellow"
    app = App()
    watched = app.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    first_seed = app.session.add_mnemonic(other.split())
    later_seed = app.session.add_mnemonic(ABANDON.split())
    assert app.session.key_counter == 3
    assert app.session.fingerprints[first_seed["fingerprint"]].keys[0].added == 2
    assert app.session.fingerprints[later_seed["fingerprint"]].keys[0].added == 3
    assert watched["fingerprint"] == later_seed["fingerprint"]
    app.screen = "keys"
    app.render()
    first_box = next(hit["box"] for hit in app.hits if hit["action"] == f"open-fp-{first_seed['fingerprint'].hex()}")
    later_box = next(hit["box"] for hit in app.hits if hit["action"] == f"open-fp-{later_seed['fingerprint'].hex()}")
    assert first_box[1] < later_box[1]

    listed = App()
    early = listed.session.add_text(expression(ABANDON, "m/48h/0h/7h/2h"))
    other_key = listed.session.add_text(expression(other, "m/84h/0h/0h"))
    listed.session.add_text(expression(ABANDON, "m/86h/0h/4h"))
    listed.session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    listed.session.add_text(expression(ABANDON, "m/84h/0h/1h"))
    listed.screen = "keys"
    listed.render()
    sections = {title: items for title, _icon, _awesome, items in listed._key_sections() if items}
    assert list(sections) == ["SingleSig External Keys", "MultiSig External Keys"]
    fingerprint = early["fingerprint"]
    singles = [item for item in sections["SingleSig External Keys"] if item[0] == fingerprint]
    assert [item[2].role for item in singles] == ["singlesig_native", "singlesig_taproot"]
    assert [item[2].account for item in singles] == [1, 4]
    multis = [item for item in sections["MultiSig External Keys"] if item[0] == fingerprint]
    assert [item[2].account for item in multis] == [0, 7]
    visible = {
        hit["action"]: hit["box"][1]
        for hit in listed.hits
        if hit["action"].startswith("open-fp-")
    }
    order = []
    for items in sections.values():
        for fingerprint, _record, _key, index in items:
            action = f"open-fp-{fingerprint.hex()}-{index}"
            if action in visible:
                order.append(visible[action])
    assert order == sorted(order)
    assert len(visible) >= 2
    listed._act(f"open-fp-{fingerprint.hex()}-2")
    assert listed.screen == "key"
    assert listed.selected_key_index == 2
    assert listed._stored_key()[1].account == 0
    assert listed._external_kind(listed._stored_key()[1]) == "Native-Segwit MultiSig"


def test_the_plus_button_centers_its_icon():
    from bigsigner.ui.app import _PLUS_DIAMETER
    from bigsigner.ui.canvas import BLUE

    def centers(menu: bool):
        app = App()
        app.screen = "keys"
        app.add_menu = menu
        image = app.render()
        box = next(hit["box"] for hit in app.hits if hit["action"] == "toggle-add")
        assert box[2] - box[0] == box[3] - box[1] == _PLUS_DIAMETER == 94

        def center(predicate):
            points = [
                (x, y)
                for y in range(box[1] - 2, box[3] + 3)
                for x in range(box[0] - 2, box[2] + 3)
                if predicate(image.getpixel((x, y))[:3])
            ]
            return (
                (min(x for x, _y in points) + max(x for x, _y in points)) / 2,
                (min(y for _x, y in points) + max(y for _x, y in points)) / 2,
            )

        return center(lambda pixel: pixel == BLUE), center(lambda pixel: min(pixel) > 200)

    for menu in (False, True):
        circle, icon = centers(menu)
        assert abs(icon[0] - circle[0]) <= 1
        assert abs(icon[1] - circle[1]) <= 1


def test_key_list_scrolls_by_dragging():
    from embit.bip39 import mnemonic_from_bytes

    app = App()
    nicknames = []
    for index in range(8):
        added = app.session.add_mnemonic(mnemonic_from_bytes(bytes([index + 1]) + b"\x3c" * 15).split())
        nicknames.append(app.session.fingerprints[added["fingerprint"]].nickname)
    app.screen = "keys"
    app.render()
    assert app.scroll_max["keys"] > 0
    watched = next(hit["box"] for hit in app.hits if hit["label"] == nicknames[2])
    first = next(hit["box"] for hit in app.hits if hit["label"] == nicknames[0])
    assert app.render().getpixel((WIDTH // 2, 30))[:3] == NAVY
    plus = next(hit["box"] for hit in app.hits if hit["action"] == "toggle-add")

    app.pointer_down(220, (first[1] + first[3]) // 2)
    app.pointer_up(220, (first[1] + first[3]) // 2)
    assert app.screen == "key"
    app.back_one()
    assert app.screen == "keys"
    assert app.scroll.get("keys", 0) == 0

    app.pointer_down(200, 500)
    assert app.pointer_move(200, 280)
    app.pointer_up(200, 280)
    assert app.screen == "keys"
    app.render()
    moved = next(hit["box"] for hit in app.hits if hit["label"] == nicknames[2])
    assert moved[1] < watched[1]
    assert next(hit["box"] for hit in app.hits if hit["action"] == "toggle-add") == plus
    assert app.render().getpixel((WIDTH // 2, 30))[:3] == NAVY


def test_about_opens_dependency_licenses():
    from bigsigner.licenses import NOTICES

    app = App()
    app.screen = "about"
    tap(app, "open-licenses")
    assert app.screen == "licenses"
    app.render()
    labels = {hit["label"] for hit in app.hits}
    app.scroll["licenses"] = app.scroll_max["licenses"]
    app.render()
    labels |= {hit["label"] for hit in app.hits}
    app.scroll["licenses"] = 0
    assert {notice.name for notice in NOTICES} <= labels
    tap(app, "unique-names-generator")
    assert app.screen == "license"
    assert "AndreaSonny" in NOTICES[app.license_index].text
    assert "MIT License" in NOTICES[app.license_index].text
    app.render()
    assert app.scroll_max["license"] > 0
    app.back_one()
    assert app.screen == "licenses"
    tap(app, "embit")
    assert "Stepan Snigirev" in NOTICES[app.license_index].text
    app.back_one()
    app.back_one()
    assert app.screen == "about"

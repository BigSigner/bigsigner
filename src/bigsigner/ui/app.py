"""Touch screens for the portrait signer. The same object drives the emulator."""

import hashlib
import io
import os
import sys
import time
from types import SimpleNamespace
from bisect import bisect_left
from functools import lru_cache
from pathlib import Path

from embit.bip39 import WORDLIST
from PIL import Image, ImageDraw

from .. import __version__
from ..entropy import mnemonic_from_camera, mnemonic_from_coins, mnemonic_from_dice
from ..parse import ParseError
from ..paths import MULTISIG_NATIVE, SINGLESIG_NATIVE, SINGLESIG_TAPROOT, format_path
from ..psbt_review import ReviewError, review_psbt, sign_with
from ..qr import qr_matrix
from ..session import Session, SessionError, _passphrase_warnings, _public_for, account_index_phrase
from ..bsms import bsms_text
from ..scan import QrSequence, import_scanned
from ..sdcard import SdError, child_path, file_exists, list_folder, parent_path, read_text, write_text
from ..licenses import NOTICES
from ..seedqr import compact_bytes
from ..slip132 import display_form, label_of
from ..ur import descriptor_ur
from .canvas import (
    BLUE,
    HEADER,
    HEIGHT,
    INK,
    LINE,
    MARGIN,
    MUTED,
    NAVY,
    PAPER,
    RED,
    WHITE,
    BODY_SIZE,
    TITLE_SIZE,
    WIDTH,
    Frame,
    Icons,
    font,
    glyph_sprite,
    logo,
    wrap,
)

RESOURCES = Path(__file__).resolve().parents[1] / "resources"
# Fingerprint names on the key list and the key screen use the title size and break after the second word.
NAME_ON_CARD = TITLE_SIZE
NAME_ON_KEY = TITLE_SIZE
# Icon beside a title-sized fingerprint hex or seed summary.
_DETAIL_ICON = 36
NAME_ON_WALLET_CARD = TITLE_SIZE
# 32px leaves the widest fingerprint-name line inside the card. 36px does not.
_WALLET_CARD_ICON = NAME_ON_WALLET_CARD
_WALLET_CARD_GAP = 10
# Space above a later key's name. The first key stays under the title.
_WALLET_KEY_GAP = 20
NAME_ON_WALLET = TITLE_SIZE
NAME_ON_MULTISIG = TITLE_SIZE
# The fingerprint line shares the row with the checkbox. 28 is the largest size that stays on one line.
FINGERPRINT_ON_MULTISIG = 28
_CARD_PAD = 16
# One column of seed words. 36 is a step up from the two-column size. The card
# stays inside the page margin, and the numbered word stays inside the card.
SEED_CARD_COLUMNS = 1
SEED_CARD_GAP = 8
SEED_CARD_PAD_X = 16
SEED_CARD_FONT = 36
# A singlesig account xpub shares its first 16 characters with nearby accounts.
# 20 characters is the longest prefix that still fits on one centered line, and it changes with the account.
XPUB_ACCOUNT_PREVIEW = 20
# External Key screen. Nineteen letters and the ellipsis fit on one centered line.
XPUB_KEY_PREVIEW = 19
# Floating plus button. About 10% smaller than the previous 104px circle.
_PLUS_DIAMETER = 94
_PLUS_GLYPH = 49
_PLUS_CLEARANCE = 28 + _PLUS_DIAMETER


def _fingerprint_name_lines(nickname: str) -> list[str]:
    """The title-sized name, broken after the second word."""
    words = nickname.split()
    if len(words) <= 2:
        return [nickname] if nickname else [""]
    return [" ".join(words[:2]), " ".join(words[2:])]


def _draw_centered(frame: Frame, text: str, y: int, size: int, fill=INK) -> None:
    face = font(size)
    width = frame.draw.textlength(text, font=face)
    frame.draw.text(((WIDTH - width) / 2, y), text, font=face, fill=fill)


def _name_icon(has_seed: bool):
    """The icon that used to sit in front of a one-line name."""
    if has_seed:
        return Icons.KEY, False
    return Icons.EYE, True


def _draw_name_block(frame: Frame, y: int, lines: list[str], size: int, icon: str, awesome: bool, icon_size: int, paint: bool, offset: int = 0) -> int:
    """Two name lines after a leading icon, sharing the fingerprint line's left edge."""
    face = font(size)
    _left, top, _right, bottom = frame.draw.textbbox((0, 0), "Ag", font=face)
    step = size + 8
    text_mid = (top + bottom) / 2 + step * (len(lines) - 1) / 2
    if paint and y - offset + text_mid >= HEADER:
        frame.glyph(icon, MARGIN + icon_size / 2, y - offset + text_mid, icon_size, INK, awesome=awesome)
    if paint:
        text_x = MARGIN + icon_size + 10
        for index, line in enumerate(lines):
            line_y = y - offset + index * step
            if line_y >= HEADER:
                frame.draw.text((text_x, line_y), line, font=face, fill=INK)
    return y + step * len(lines)
BOOT_HOLD = 1.0
NOTICE_HOLD = 4.0
QR_HINT_HOLD = 2.0
# A click is a short press that stays inside this box. Either edge is enough
# to make it a scroll, as LVGL's scroll limit does, so there is no radius.
# Once the finger has left the box it stays a scroll, including a fast flick
# that comes back. A finger that stays down this long is a scroll as well.
SCROLL_DELTA_X = 24
SCROLL_DELTA_Y = 24
SCROLL_HOLD = 0.4
# Touch reports that stop for this long end the gesture. A short one inside
# the box is a click.
SCROLL_GAP = 0.08
SEED_FORMATS = ("words", "compact", "text")
SEED_FORMAT_NAMES = ("Words", "Compact SeedQR", "Text QR")
DESCRIPTOR_FORMATS = ("ur", "plain")
DESCRIPTOR_FORMAT_NAMES = ("UR", "Plain QR")
MULTISIG_DESCRIPTOR_NOTE = (
    "A Native-Segwit multisig descriptor can list its key expressions in any order. "
    "The checksum changes with that order."
)
QR_BRIGHTNESS_MAX = 4
QR_BRIGHTNESS_DEFAULT = 2
# 46 px is 4.97 mm on the Waveshare 4-inch panel (0.108 mm pixels), the nearest size to 5 mm.
QR_ZOOM_CELL = 46
QR_ZOOM_COUNT = 9
QR_ZOOM_RIGHT = 4
QR_ZOOM_BAND = 32
QR_BRIGHTNESS_STOPS = (
    (118, 122, 128),
    (176, 180, 186),
    (246, 247, 249),
    (252, 252, 252),
    (255, 255, 255),
)


class App:
    def __init__(self):
        self.session = Session()
        self.screen = "boot"
        self.boot_until = None
        self.back = []
        self.notice = ""
        self.notice_until = None
        self.warnings = []
        self.selected_fp = None
        self.selected_key_index = 0
        self.wallet_index = 0
        self._wallet_account_visit = None
        self.draft = ""
        self.menu = False
        self.add_menu = False
        self.hits = []
        self.qr_zoom = None
        self.qr_text = ""
        self.qr_kind = "plain"
        self.key_qr_index = 0
        self.qr_scroll = 0
        self.qr_scroll_max = 0
        self.qr_scroll_box = None
        self.qr_hint_until = None
        # One picture of the QR and the text under it. Scrolling crops this
        # picture. A frame for every scroll position would be hundreds of
        # megabytes; this one is a couple of megabytes.
        self._qr_strip = None
        self._qr_strip_key = None
        self._qr_strip_due = False
        self.seed_format = 0
        self.qr_brightness = QR_BRIGHTNESS_DEFAULT
        self.descriptor_format = 0
        self.review = None
        self.psbt_text = ""
        self.seed_length = 24
        self.seed_words = []
        self.word_prefix = ""
        self.word_cursor = 0
        self._seed_choice_key = None
        self._seed_choice_words = WORDLIST
        self._seed_picture = None
        self._pass_picture = None
        self._pass_field_box = None
        self._pass_shell = None
        self._pass_fixed_hits = []
        self._derive_picture = None
        self._derive_hits = []
        self._derive_shell = None
        self._derive_account_box = None
        self._derive_path_box = None
        self._derive_xpub_box = None
        self._derive_text_size = TITLE_SIZE
        self._derive_still = []
        self._flow_value_box = None
        self._seed_shell_key = None
        self._seed_key_boxes = {}
        self._seed_bottom_letters: set[str] = set()
        self._seed_fixed_hits = []
        self._seed_enabled: set[str] = set()
        self._seed_field_box = None
        self._letter_sprites = {}
        self.dirty = None
        self.seed_grid_scroll = 0
        self.seed_grid_max = 0
        self.seed_grid_stick = True
        self.seed_grid_box = None
        self.address_query = ""
        self.sd_files = {}
        self.slip_labels = False
        self.show_secret = False
        self.show_passphrase = False
        self.passphrase_text = ""
        self.passphrase_cursor = 0
        self.passphrase_mode = "lower"
        self.confirm = None
        self.entropy_words = 24
        self.open_dropdown = None
        self.scan_kind = "key"
        self.qr_sequence = QrSequence()
        self.camera_unavailable = False
        self.sd_dir = ""
        self.sd_expect = "key"
        self.sd_mode = "load"
        self.export_text = ""
        self.export_label = ""
        self.export_path = ""
        self.export_return = "keys"
        self.export_back = []
        self.filename = ""
        self.filename_cursor = 0
        self.hscroll = 0
        self.hscroll_max = 0
        self._hscroll_box = None
        self._hscroll_key = None
        self.account_fp = None
        self.account_text = ""
        self.account_for = "wallet"
        self.derive_role = None
        self.derive_account = 0
        self.qr_source = "stored"
        self.descriptor_choice = None
        self.descriptor_key_index = 0
        self.multisig_m = 2
        self.multisig_selected = set()
        self.singlesig_role = SINGLESIG_NATIVE
        self.singlesig_selected = None
        self.pending_external = None
        self.external_format = "xpub"
        self.load_error = ""
        self.load_error_home = "keys"
        self.wallet_plan = None
        self.wallet_plan_pos = 0
        self.license_index = 0
        self.entropy_digits = ""
        self.entropy_scroll = 0
        self.entropy_scroll_max = 0
        self.entropy_scroll_box = None
        self.entropy_scroll_stick = True
        self.pending_mnemonic = ""
        self.camera_frames = []
        self.camera_final = b""
        self.scroll = {}
        self.scroll_max = {}
        self.keyboard_top = None
        self._still_boxes = []
        self._press = None
        self._press_at = 0.0
        self._press_last = 0.0

    def set_notice(self, message: str):
        self.notice = message or ""
        self.notice_until = time.monotonic() + NOTICE_HOLD if self.notice else None

    def notice_delay(self):
        """Seconds until the screen should redraw itself, or None if nothing is pending."""
        delays = []
        if self.notice and self.notice_until is not None:
            delays.append(max(0, self.notice_until - time.monotonic()))
        if self.screen == "boot":
            if self.boot_until is None:
                delays.append(BOOT_HOLD)
            else:
                delays.append(max(0, self.boot_until - time.monotonic()))
        if self.qr_hint_until is not None and time.monotonic() < self.qr_hint_until:
            delays.append(max(0, self.qr_hint_until - time.monotonic()))
        if not delays:
            return None
        return min(delays)

    def _expire_notice(self):
        if self.notice and self.notice_until is not None and time.monotonic() >= self.notice_until:
            self.notice = ""
            self.notice_until = None

    def render(self) -> Image.Image:
        self.dirty = None
        self.keyboard_top = None
        self._still_boxes = []
        self._hscroll_box = None
        # A remembered picture is only valid while that screen is showing.
        # Coming back and patching a band would leave the other screen on the panel.
        if self.screen != "derive":
            self._derive_picture = None
        if self.screen != "seed":
            self._seed_picture = None
        if self.screen != "passphrase":
            self._pass_picture = None
        self._expire_notice()
        self._advance_boot()
        frame = Frame()
        painter = {
            "boot": self._boot,
            "warning": self._warning,
            "keys": self._keys,
            "key": self._key,
            "derive": self._derive,
            "wallets": self._wallets,
            "wallet": self._wallet,
            "account": self._account,
            "settings": self._settings,
            "about": self._about,
            "licenses": self._licenses,
            "license": self._license,
            "editor": self._editor,
            "seed": self._seed,
            "passphrase-ask": self._passphrase_ask,
            "passphrase": self._passphrase,
            "passphrase-view": self._passphrase_view,
            "review": self._review,
            "qr": self._qr,
            "seed-show": self._seed_show,
            "addresses": self._addresses,
            "generate": self._generate,
            "dice": self._dice,
            "coins": self._coins,
            "camera": self._camera,
            "scan": self._scan,
            "sd": self._sd,
            "export-format": self._export_format,
            "export-name": self._export_name,
            "multisig": self._multisig,
            "singlesig": self._singlesig,
            "load-error": self._load_error,
            "descriptor-choice": self._descriptor_choice,
            "wallet-import-note": self._wallet_import_note,
            "external-review": self._external_warning,
            "external-details": self._external_details,
            "entropy": self._entropy,
        }[self.screen]
        painter(frame)
        if self.menu:
            self._drawer(frame)
        if self.notice:
            self._toast(frame)
        if self.confirm:
            self._confirm(frame)
        self.hits = frame.hits
        return frame.image

    def tap(self, x: int, y: int, camera: dict | None = None):
        if camera:
            self.camera_frames = list(camera.get("frames") or [])
            self.camera_final = camera.get("final") or b""
        self.set_notice("")
        for hit in reversed(self.hits):
            left, top, right, bottom = hit["box"]
            if left <= x < right and top <= y < bottom:
                self._act(hit["action"])
                return

    def pointer_down(self, x: int, y: int):
        if self._in_hscroll_field(x, y):
            panel = "hfield"
        elif self._in_seed_grid(x, y):
            panel = "seed"
        elif self._in_qr_panel(x, y):
            panel = "qr"
        elif self._in_entropy_log(x, y):
            panel = "entropy"
        else:
            panel = ""
        self._press = (x, y, self.scroll.get(self.screen, 0), False, panel)
        now = time.monotonic()
        self._press_at = now
        self._press_last = now
        if panel == "qr":
            self._grid_origin = self.qr_scroll
        elif panel == "entropy":
            self._grid_origin = self.entropy_scroll
        elif panel == "hfield":
            self._grid_origin = self.hscroll
        else:
            self._grid_origin = self.seed_grid_scroll

    def _in_seed_grid(self, x: int, y: int) -> bool:
        box = self.seed_grid_box
        if self.screen not in ("seed", "seed-show") or box is None or self.seed_grid_max <= 0:
            return False
        left, top, right, bottom = box
        return left <= x < right and top <= y < bottom

    def _in_qr_panel(self, x: int, y: int) -> bool:
        box = self.qr_scroll_box
        if self.screen != "qr" or self.qr_kind not in ("key", "descriptor") or box is None or self.qr_scroll_max <= 0:
            return False
        left, top, right, bottom = box
        return left <= x < right and top <= y < bottom

    def _in_hscroll_field(self, x: int, y: int) -> bool:
        box = self._hscroll_box
        if box is None or self.hscroll_max <= 0:
            return False
        left, top, right, bottom = box
        return left <= x < right and top <= y < bottom

    def _move_hscroll(self, dx: int, dy: int, dragging: bool, origin_x: int, origin_y: int, panel: str) -> bool:
        """Drag a wide text field sideways. A short press still moves the cursor."""
        if not dragging and abs(dx) <= SCROLL_DELTA_X and abs(dy) <= SCROLL_DELTA_Y:
            if time.monotonic() - self._press_at >= SCROLL_HOLD:
                self._press = (origin_x, origin_y, 0, True, panel)
            return False
        if abs(dx) <= abs(dy):
            self._press = (origin_x, origin_y, 0, True, panel)
            return False
        self._press = (origin_x, origin_y, 0, True, panel)
        scroll = max(0, min(self.hscroll_max, int(self._grid_origin - dx)))
        if scroll == self.hscroll:
            return False
        self.hscroll = scroll
        return True

    def finger_down(self) -> bool:
        return self._press is not None

    def pointer_move(self, x: int, y: int) -> bool:
        """Drag the current page, or the seed-word list, vertically."""
        if self._press is None:
            return False
        self._press_last = time.monotonic()
        origin_x, origin_y, origin_scroll, dragging, panel = self._press
        dx = x - origin_x
        dy = y - origin_y
        # A press on the keyboard is a key, down to the bottom edge of the panel.
        if self.keyboard_top is not None and origin_y >= self.keyboard_top:
            return False
        # Plus and minus are clicks even when the finger slides off them.
        if self._in_still_box(origin_x, origin_y):
            return False
        if panel == "hfield":
            return self._move_hscroll(dx, dy, dragging, origin_x, origin_y, panel)
        if not dragging and abs(dx) <= SCROLL_DELTA_X and abs(dy) <= SCROLL_DELTA_Y:
            if time.monotonic() - self._press_at >= SCROLL_HOLD:
                self._press = (origin_x, origin_y, origin_scroll, True, panel)
            return False
        if not dragging:
            dragging = True
            self._press = (origin_x, origin_y, origin_scroll, True, panel)
            if abs(dy) < abs(dx) or not self._scroll_allowed():
                return False
        if not self._scroll_allowed():
            return False
        if panel == "seed":
            offset = max(0, min(self.seed_grid_max, self._grid_origin - dy))
            if offset == self.seed_grid_scroll:
                return False
            self.seed_grid_scroll = offset
            self.seed_grid_stick = offset >= self.seed_grid_max
            return True
        if panel == "qr":
            offset = max(0, min(self.qr_scroll_max, self._grid_origin - dy))
            if offset == self.qr_scroll:
                return False
            self.qr_scroll = offset
            return True
        if panel == "entropy":
            offset = max(0, min(self.entropy_scroll_max, self._grid_origin - dy))
            if offset == self.entropy_scroll:
                return False
            self.entropy_scroll = offset
            self.entropy_scroll_stick = offset >= self.entropy_scroll_max
            return True
        limit = self.scroll_max.get(self.screen, 0)
        if limit <= 0:
            return False
        offset = max(0, min(limit, origin_scroll - dy))
        if offset == self.scroll.get(self.screen, 0):
            return False
        self.scroll[self.screen] = offset
        return True

    def pointer_up(self, x: int, y: int, camera: dict | None = None):
        press = self._press
        self._press = None
        if press is None:
            self.tap(x, y, camera)
            return
        if self._press_is_click(press):
            self.tap(press[0], press[1], camera)

    def pointer_idle(self) -> bool:
        """The reports stopped. A short press inside the box is a click."""
        press = self._press
        if press is None or time.monotonic() - self._press_last < SCROLL_GAP:
            return False
        self._press = None
        if not self._press_is_click(press):
            return False
        self.tap(press[0], press[1])
        return True

    def _press_is_click(self, press) -> bool:
        if self.keyboard_top is not None and press[1] >= self.keyboard_top:
            return True
        if self._in_still_box(press[0], press[1]):
            return True
        if press[3]:
            return False
        return time.monotonic() - self._press_at < SCROLL_HOLD

    def _in_still_box(self, x: int, y: int) -> bool:
        for left, top, right, bottom in self._still_boxes:
            if left <= x < right and top <= y < bottom:
                return True
        return False

    def _scroll_allowed(self) -> bool:
        return not self.menu and not self.add_menu and self.confirm is None and self.open_dropdown is None

    def _scroll_offset(self, screen: str, content_end: int, clearance: int = 96) -> int:
        """How far the content is shifted up. The title stays put."""
        limit = max(0, content_end + clearance - HEIGHT)
        offset = max(0, min(self.scroll.get(screen, 0), limit))
        self.scroll[screen] = offset
        self.scroll_max[screen] = limit
        return offset

    def go(self, screen: str):
        self.back.append(self.screen)
        self.screen = screen
        if screen == "scan":
            self.qr_sequence.reset()
        if screen == "key":
            self.scroll["key"] = 0
        self.menu = False
        self.add_menu = False
        self.open_dropdown = None

    def back_one(self):
        leaving_lit_qr = self.screen == "seed-show" or (
            self.screen == "qr" and self.qr_kind in ("key", "descriptor")
        )
        leaving_wallet = self.screen == "wallet"
        self.screen = self.back.pop() if self.back else "keys"
        if leaving_wallet:
            self._restore_wallet_accounts()
        if self.screen in ("keys", "wallets"):
            self.wallet_plan = None
            self.pending_external = None
        if leaving_lit_qr:
            self.qr_brightness = QR_BRIGHTNESS_DEFAULT
            self.qr_scroll = 0
        self.menu = False
        self.add_menu = False
        self.open_dropdown = None

    def _act(self, action: str):
        if action == "boot":
            self._leave_boot()
        elif action == "warning-ok":
            self.screen = "keys"
            self.menu = True
        elif action == "menu":
            self.menu = not self.menu
            self.add_menu = False
        elif action == "close-menu":
            self.menu = False
        elif action == "toggle-add":
            self.add_menu = not self.add_menu
            self.menu = False
        elif action == "close-add":
            self.add_menu = False
        elif action == "add-manual":
            self.add_menu = False
            self.seed_words = []
            self.word_prefix = ""
            self.word_cursor = 0
            self.seed_grid_stick = True
            self.go("seed")
        elif action == "add-scan":
            self.add_menu = False
            self.scan_kind = "key"
            self.go("scan")
        elif action == "wallet-scan":
            self.add_menu = False
            self.scan_kind = "descriptor"
            self.go("scan")
        elif action == "wallet-sd":
            self._open_sd("descriptor")
        elif action == "wallet-singlesig":
            self.add_menu = False
            self.singlesig_role = SINGLESIG_NATIVE
            self.singlesig_selected = None
            self.open_dropdown = None
            self.scroll["singlesig"] = 0
            self.go("singlesig")
        elif action == "wallet-multisig":
            self.add_menu = False
            self.multisig_m = 2
            self.multisig_selected = set()
            self.open_dropdown = None
            self.go("multisig")
        elif action.startswith("pick-ss-"):
            fingerprint = bytes.fromhex(action[len("pick-ss-") :])
            self.singlesig_selected = None if fingerprint == self.singlesig_selected else fingerprint
        elif action == "ss-create":
            self._create_selected_singlesig()
        elif action.startswith("toggle-ms-"):
            fingerprint = bytes.fromhex(action[len("toggle-ms-") :])
            if fingerprint in self.multisig_selected:
                self.multisig_selected.remove(fingerprint)
            else:
                self.multisig_selected.add(fingerprint)
            self._clamp_multisig_threshold()
        elif action == "ms-create":
            self._create_selected_multisig()
        elif action == "add-sd":
            self._open_sd("key")
        elif action == "sd-up":
            self.sd_dir = parent_path(self.sd_dir)
            self.scroll["sd"] = 0
        elif action.startswith("sd-into:"):
            self.sd_dir = action[len("sd-into:") :]
            self.scroll["sd"] = 0
        elif action.startswith("sd-read:"):
            self._read_sd_file(action[len("sd-read:") :])
        elif action.startswith("sd-write:"):
            self._choose_export_file(action[len("sd-write:") :])
        elif action == "export-key":
            self._open_export("stored")
        elif action == "export-derived":
            self._open_export("derive")
        elif action == "export-wallet":
            self._open_wallet_export()
        elif action.startswith("export-format-"):
            self._choose_export_format(int(action[len("export-format-") :]))
        elif action == "export-new":
            self._open_export_name()
        elif action == "export-save-new":
            self._save_new_export_file()
        elif action.startswith("account-dec-"):
            self._step_account(bytes.fromhex(action[len("account-dec-") :]), -1)
        elif action.startswith("account-inc-"):
            self._step_account(bytes.fromhex(action[len("account-inc-") :]), 1)
        elif action.startswith("account-edit-"):
            self._edit_account(bytes.fromhex(action[len("account-edit-") :]))
        elif action.startswith("account-key-"):
            self._type_account(action[len("account-key-") :])
        elif action == "account-save":
            self._save_account()
        elif action == "add-generate":
            self.add_menu = False
            self.entropy_words = 24
            self.entropy_digits = ""
            self.pending_mnemonic = ""
            self.open_dropdown = None
            self.go("generate")
        elif action == "dropdown-close":
            self.open_dropdown = None
        elif action.startswith("dropdown-pick-"):
            name, key = action[len("dropdown-pick-") :].rpartition("-")[::2]
            if name == "entropy-words":
                self.entropy_words = int(key)
            elif name == "singlesig-script":
                self.singlesig_role = SINGLESIG_TAPROOT if key == "taproot" else SINGLESIG_NATIVE
                if self.singlesig_selected not in self._singlesig_candidates():
                    self.singlesig_selected = None
            elif name == "multisig-m":
                self.multisig_m = int(key)
            elif name == "network" and key != self.session.network:
                self.set_notice(self.session.set_network(key))
            elif name.startswith("acct-"):
                self._pick_account(bytes.fromhex(name[len("acct-") :]), int(key))
            elif name == "external-format":
                self.external_format = key
            elif name == "descriptor-key":
                self.descriptor_key_index = int(key)
            elif name == "seed-length":
                self._set_seed_length(int(key))
            self.open_dropdown = None
        elif action.startswith("dropdown-"):
            name = action[len("dropdown-") :]
            self.open_dropdown = None if self.open_dropdown == name else name
        elif action == "gen-dice":
            self.entropy_digits = ""
            self.entropy_scroll = 0
            self.entropy_scroll_stick = True
            self.go("dice")
        elif action == "gen-coins":
            self.entropy_digits = ""
            self.entropy_scroll = 0
            self.entropy_scroll_stick = True
            self.go("coins")
        elif action == "gen-camera":
            self.camera_frames = []
            self.camera_final = b""
            self.go("camera")
        elif action.startswith("die-") and action[4:].isdigit():
            self.entropy_scroll_stick = True
            self._push_entropy(action[4:], "123456")
        elif action.startswith("coin-"):
            self.entropy_scroll_stick = True
            self._push_entropy(action[5:], "01")
        elif action == "entropy-undo":
            self.entropy_digits = self.entropy_digits[:-1]
            if self.screen in ("dice", "coins"):
                self.entropy_scroll_stick = True
        elif action == "camera-capture":
            self._capture_camera()
        elif action == "entropy-save":
            self._save_pending_mnemonic()
        elif action == "open-licenses":
            self.scroll["licenses"] = 0
            self.go("licenses")
        elif action.startswith("open-license-"):
            self.license_index = int(action[len("open-license-") :])
            self.scroll["license"] = 0
            self.go("license")
        elif action == "load-error-ok":
            home = self.load_error_home if self.load_error_home in ("keys", "wallets") else "keys"
            self.load_error = ""
            self.screen = home
            self.back = []
            self.menu = False
            self.add_menu = False
        elif action == "external-known":
            self._continue_loaded_multisig()
        elif action == "external-next":
            if self.pending_external is None:
                return
            self.open_dropdown = None
            self.scroll["external-details"] = 0
            self.go("external-details")
        elif action == "external-continue":
            if self.wallet_plan is not None:
                self._advance_wallet_import()
            else:
                self._commit_external_key()
        elif action == "wallet-import-continue":
            self._finish_wallet_import()
        elif action == "back":
            self.back_one()
        elif action.startswith("nav-"):
            if self.screen == "wallet":
                self._restore_wallet_accounts()
            self.screen = action[4:]
            self.back = []
            self.menu = False
            self.add_menu = False
        elif action == "add-seed":
            self.seed_words = []
            self.word_prefix = ""
            self.word_cursor = 0
            self.seed_length = 24
            self.seed_grid_stick = True
            self.go("seed")
        elif action == "add-text":
            self.draft = ""
            self.go("editor")
        elif action.startswith("len-"):
            self._set_seed_length(int(action[4:]))
        elif action.startswith("pick-"):
            self._pick_word(action[5:])
        elif action.startswith("key-"):
            self._seed_key(action[4:])
        elif action.startswith("cursor-"):
            self.word_cursor = max(0, min(len(self.word_prefix), int(action[7:])))
        elif action == "seed-undo":
            if self.word_cursor > 0:
                self._seed_key("backspace")
            elif self.seed_words:
                self.seed_words.pop()
                self.word_prefix = ""
                self.word_cursor = 0
        elif action == "save-text":
            self._save_text()
        elif action.startswith("open-fp-"):
            rest = action[len("open-fp-") :]
            hex_fp, separator, index_text = rest.partition("-")
            self.selected_fp = bytes.fromhex(hex_fp)
            self.selected_key_index = int(index_text) if separator else 0
            self.slip_labels = False
            self.show_secret = False
            self.show_passphrase = False
            self.go("key")
        elif action.startswith("open-wallet-"):
            self.wallet_index = int(action[12:])
            self.scroll["wallet"] = 0
            self._remember_wallet_accounts()
            self.go("wallet")
        elif action == "derive-native":
            self._open_derive(SINGLESIG_NATIVE)
        elif action == "derive-multisig":
            self._open_derive(MULTISIG_NATIVE)
        elif action == "derive-taproot":
            self._open_derive(SINGLESIG_TAPROOT)
        elif action == "derive-dec":
            self._step_derive_account(-1)
        elif action == "derive-inc":
            self._step_derive_account(1)
        elif action == "derive-edit":
            self._edit_derive_account()
        elif action == "derive-wallet":
            self._make_derived_wallet()
        elif action == "derive-details":
            self._open_derived_details()
        elif action == "make-xpub-wallet":
            self._make_xpub_wallet()
        elif action == "show-seed":
            self.confirm = "show-seed"
        elif action == "show-passphrase":
            self.confirm = "show-passphrase"
        elif action == "copy-passphrase":
            self._start_passphrase_copy()
        elif action == "seed-continue":
            self.go("passphrase-ask")
        elif action == "passphrase-no":
            self._save_entered_seed(None)
        elif action == "passphrase-yes":
            self.passphrase_text = ""
            self.passphrase_cursor = 0
            self.passphrase_mode = "lower"
            self.go("passphrase")
        elif action == "passphrase-save":
            secret = self.passphrase_text
            self._save_entered_seed(None if secret == "" else secret)
        elif action.startswith("passkey-"):
            self._passphrase_key(action[len("passkey-") :])
        elif action.startswith("passcur-"):
            index = int(action[8:])
            if self.screen == "export-name":
                self.filename_cursor = max(0, min(len(self.filename), index))
            else:
                self.passphrase_cursor = max(0, min(len(self.passphrase_text), index))
        elif action.startswith("passmode-"):
            self.passphrase_mode = action[len("passmode-") :]
        elif action == "confirm-yes":
            self._confirm_yes()
        elif action == "confirm-no":
            self.confirm = None
        elif action == "descriptor-both":
            choice = self.descriptor_choice
            if choice:
                self.open_dropdown = None
                self._start_wallet_import(choice["text"])
        elif action == "descriptor-key":
            self._load_chosen_descriptor_key()
        elif action == "confirm-stay":
            return
        elif action == "delete-key":
            self.confirm = "delete-key"
        elif action == "delete-wallet":
            self.confirm = "delete-wallet"
        elif action == "toggle-slip":
            self.slip_labels = not self.slip_labels
        elif action == "show-qr":
            self._show_qr()
        elif action == "show-descriptor":
            self._open_descriptor_qr()
        elif action == "seed-format-next":
            self._step_seed_format(1)
        elif action == "seed-format-prev":
            self._step_seed_format(-1)
        elif action == "qr-form-next":
            self._step_qr_format(1)
        elif action == "qr-form-prev":
            self._step_qr_format(-1)
        elif action == "zoom-close":
            self.qr_zoom = None
        elif action == "brightness-down":
            self.qr_brightness = max(0, self.qr_brightness - 1)
        elif action == "brightness-up":
            self.qr_brightness = min(QR_BRIGHTNESS_MAX, self.qr_brightness + 1)
        elif action.startswith("zoom-"):
            self._move_zoom(action[5:])
        elif action == "review-sample":
            self.set_notice("Load a PSBT from the editor.")
            self.draft = ""
            self.go("editor")
            self.screen_after_editor = "psbt"
        elif action == "addresses":
            self.go("addresses")
        else:
            self.set_notice("")

    def _generate(self, frame: Frame):
        frame.header("New seed", "back")
        y = frame.text(
            "Seed generation needs a safe source of randomness. BigSigner does not use a hardware random-number chip (TRNG). Choose dice, coin flips, or the camera.",
            MARGIN,
            HEADER + 16,
            size=TITLE_SIZE,
        )
        field = self._dropdown_field(frame, y + 16, "entropy-words", f"{self.entropy_words} words")
        y = frame.button(field[3] + 16, "Dice", "gen-dice", icon=Icons.DICE, awesome=True)
        y = frame.button(y, "Coins", "gen-coins", icon=Icons.COINS, awesome=True)
        frame.button(y, "Camera", "gen-camera", icon=Icons.CAMERA, awesome=True)
        if self.open_dropdown == "entropy-words":
            self._dropdown_menu(
                frame,
                field,
                "entropy-words",
                (("12", "12 words"), ("24", "24 words")),
                str(self.entropy_words),
            )

    def _dropdown_field(self, frame: Frame, y: int, name: str, label: str, enabled: bool = True):
        height = 64
        box = (MARGIN, y, WIDTH - MARGIN, y + height)
        open_now = enabled and self.open_dropdown == name
        if enabled:
            fill, ink, outline = WHITE, INK, BLUE if open_now else LINE
        else:
            fill, ink, outline = (186, 190, 196), (132, 136, 142), (186, 190, 196)
        frame.draw.rounded_rectangle(box, radius=14, fill=fill, outline=outline, width=2)
        limit = (box[2] - 52) - (box[0] + 20)
        size = TITLE_SIZE
        face = font(size)
        while size > 18 and frame.draw.textlength(label, font=face) > limit:
            size -= 1
            face = font(size)
        left, top, right, bottom = frame.draw.textbbox((0, 0), label, font=face)
        text_y = y + (height - (bottom - top)) / 2 - top
        frame.draw.text((box[0] + 20, text_y), label, font=face, fill=ink)
        frame.glyph(Icons.CHEVRON_UP if open_now else Icons.CHEVRON_DOWN, box[2] - 36, y + height / 2, 28, ink if not enabled else MUTED)
        if enabled:
            frame.hit(box, f"dropdown-{name}", label)
        return box

    def _dropdown_menu(self, frame: Frame, field, name: str, options, selected: str):
        row_h = TITLE_SIZE + 20
        left, _top, right, bottom = field
        menu_h = row_h * len(options)
        menu_top = bottom + 8
        if menu_top + menu_h > HEIGHT - 12:
            menu_top = field[1] - 8 - menu_h
        frame.hit((0, 0, WIDTH, HEIGHT), "dropdown-close", "outside")
        frame.draw.rounded_rectangle((left, menu_top, right, menu_top + menu_h), radius=14, fill=WHITE, outline=LINE, width=2)
        for index, (key, label) in enumerate(options):
            row_top = menu_top + index * row_h
            row = (left, row_top, right, row_top + row_h)
            if key == selected:
                frame.draw.rounded_rectangle(
                    (row[0] + 8, row[1] + 6, row[2] - 8, row[3] - 6),
                    radius=10,
                    fill=(228, 230, 234),
                )
            face = font(TITLE_SIZE)
            text_left, text_top, _text_right, text_bottom = frame.draw.textbbox((0, 0), label, font=face)
            text_y = row_top + (row_h - (text_bottom - text_top)) / 2 - text_top
            frame.draw.text((left + 20 - text_left, text_y), label, font=face, fill=INK)
            if index < len(options) - 1:
                frame.draw.line((left + 16, row[3], right - 16, row[3]), fill=LINE, width=2)
            frame.hit(row, f"dropdown-pick-{name}-{key}", label)

    def _dice(self, frame: Frame):
        target = 50 if self.entropy_words == 12 else 99
        frame.header(f"Dice {len(self.entropy_digits)}/{target}", "back")
        y = frame.text("Enter each face as a digit from 1 to 6.", MARGIN, HEADER + 16, size=TITLE_SIZE)
        pad_top = _dice_pad_top()
        self._entropy_log(frame, y + 8, pad_top - 16)
        self._dice_pad(frame, pad_top)
        frame.button(HEIGHT - 110, "Undo", "entropy-undo")

    def _coins(self, frame: Frame):
        target = 128 if self.entropy_words == 12 else 256
        frame.header(f"Coins {len(self.entropy_digits)}/{target}", "back")
        y = frame.text("Enter each flip as 0 or 1.", MARGIN, HEADER + 16, size=TITLE_SIZE)
        pad_top = _coin_pad_top()
        self._entropy_log(frame, y + 8, pad_top - 16)
        self._coin_pad(frame, pad_top)
        frame.button(HEIGHT - 110, "Undo", "entropy-undo")

    def _in_entropy_log(self, x: int, y: int) -> bool:
        box = self.entropy_scroll_box
        if self.screen not in ("dice", "coins") or box is None or self.entropy_scroll_max <= 0:
            return False
        left, top, right, bottom = box
        return left <= x < right and top <= y < bottom

    def _entropy_log(self, frame: Frame, top: int, bottom: int):
        """Show the values entered so far. The white panel scrolls once they no longer fit."""
        self.entropy_scroll_max = 0
        self.entropy_scroll_box = None
        viewport = bottom - top
        if viewport < 20:
            return
        pad = 14
        panel = (MARGIN, top, WIDTH - MARGIN, bottom)
        frame.draw.rounded_rectangle(panel, radius=16, fill=WHITE, outline=LINE)
        digits = self.entropy_digits
        if not digits:
            return
        columns = 10
        size = 36
        face = font(size, mono=True)
        digit_w = frame.draw.textlength("0", font=face)
        ink_left, ink_top, _ink_right, ink_bottom = frame.draw.textbbox((0, 0), "0", font=face)
        text_h = ink_bottom - ink_top
        row_gap = 16
        row_h = text_h + row_gap
        rows = (len(digits) + columns - 1) // columns
        content_h = rows * text_h + max(0, rows - 1) * row_gap
        inner_w = WIDTH - 2 * MARGIN - 2 * pad
        inner_h = viewport - 2 * pad
        gap = (inner_w - columns * digit_w) / (columns - 1)
        inner_left = MARGIN + pad
        inner_top = top + pad

        def paint(draw, origin_x: int, origin_y: int, scroll: int):
            for index, digit in enumerate(digits):
                row, column = divmod(index, columns)
                x = origin_x + column * (digit_w + gap) - ink_left
                y = origin_y + row * row_h - scroll - ink_top
                draw.text((x, y), digit, font=face, fill=INK)

        if content_h <= inner_h:
            paint(frame.draw, inner_left, inner_top, 0)
            return
        max_scroll = content_h - inner_h
        self.entropy_scroll_max = max_scroll
        if self.entropy_scroll_stick:
            self.entropy_scroll = max_scroll
        else:
            self.entropy_scroll = max(0, min(self.entropy_scroll, max_scroll))
        self.entropy_scroll_box = panel
        layer = Image.new("RGB", (inner_w, inner_h), WHITE)
        paint(ImageDraw.Draw(layer), 0, 0, self.entropy_scroll)
        frame.image.paste(layer, (inner_left, inner_top))

    def _dice_pad(self, frame: Frame, top: int):
        cols = 3
        gap = 12
        width = (WIDTH - 2 * MARGIN - gap * (cols - 1)) // cols
        height = 110
        for index, digit in enumerate("123456"):
            column = index % cols
            row = index // cols
            x = MARGIN + column * (width + gap)
            y = top + row * (height + gap)
            box = (x, y, x + width, y + height)
            frame.draw.rounded_rectangle(box, radius=16, fill=BLUE)
            _paint_die_face(frame.draw, box, digit)
            frame.hit(box, f"die-{digit}", digit)

    def _coin_pad(self, frame: Frame, top: int):
        cols = 2
        gap = 12
        width = (WIDTH - 2 * MARGIN - gap * (cols - 1)) // cols
        height = 140
        face = font(40)
        for index, digit in enumerate("01"):
            x = MARGIN + index * (width + gap)
            box = (x, top, x + width, top + height)
            frame.draw.rounded_rectangle(box, radius=16, fill=BLUE)
            text_width = frame.draw.textlength(digit, font=face)
            frame.draw.text((x + (width - text_width) / 2, top + (height - 40) / 2), digit, font=face, fill=WHITE)
            frame.hit(box, f"coin-{digit}", digit)

    def _open_sd(self, expect: str):
        self.add_menu = False
        self.sd_expect = expect
        self.sd_mode = "load"
        self.sd_dir = ""
        self.scroll["sd"] = 0
        self.go("sd")

    def _read_sd_file(self, relative: str):
        try:
            text = read_text(relative)
        except SdError as exc:
            self._show_load_error(str(exc), self.sd_expect)
            return
        self._import_payload(text, self.sd_expect, "file")

    def _open_export(self, source: str):
        self.qr_source = source
        if not self._key_qr_formats():
            self.set_notice("This key is no longer loaded.")
            return
        self.export_return = self.screen
        self.export_back = list(self.back)
        self.go("export-format")

    def _open_wallet_export(self):
        if self.wallet_index >= len(self.session.wallets):
            self.set_notice("This wallet is no longer loaded.")
            return
        try:
            descriptor = self.session.descriptor_text(self.wallet_index)
            text = bsms_text(descriptor, self.session.network)
        except (SessionError, ParseError) as exc:
            self.set_notice(str(exc))
            return
        self.export_label = "BSMS"
        self.export_text = text
        self.export_return = self.screen
        self.export_back = list(self.back)
        self.sd_mode = "export"
        self.sd_dir = ""
        self.scroll["sd"] = 0
        self.go("sd")

    def _choose_export_format(self, index: int):
        formats = self._key_qr_formats()
        if index < 0 or index >= len(formats):
            return
        name, payload = formats[index]
        if name == "Key Expression":
            payload = f"{payload}/<0;1>/*"
        self.export_label = name
        self.export_text = payload
        self.sd_mode = "export"
        self.sd_dir = ""
        self.scroll["sd"] = 0
        self.go("sd")

    def _choose_export_file(self, relative: str):
        self.export_path = relative
        self.confirm = "replace-file"

    def _open_export_name(self):
        self.filename = self._suggested_export_name()
        self.filename_cursor = len(self.filename)
        self.passphrase_mode = "lower"
        self.go("export-name")

    def _suggested_export_name(self) -> str:
        if self.export_label == "BSMS" and self.wallet_index < len(self.session.wallets):
            title = self._wallet_title(self.session.wallets[self.wallet_index])
            return "-".join(title.lower().split()) + ".bsms"
        record = self.session.fingerprints.get(self.selected_fp)
        fingerprint = "key" if record is None else record.fingerprint.hex()
        label = self.export_label.split()[0].lower() if self.export_label else "key"
        if label == "key":
            label = "key-expression"
        return f"{fingerprint}-{label}.txt"

    def _save_new_export_file(self):
        name = self.filename.strip()
        if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
            self.set_notice("Choose a different file name.")
            return
        relative = child_path(self.sd_dir, name)
        try:
            exists = file_exists(relative)
        except SdError as exc:
            self.set_notice(str(exc))
            return
        self.export_path = relative
        if exists:
            self.confirm = "replace-file"
            return
        self._write_export()

    def _write_export(self):
        try:
            write_text(self.export_path, self.export_text)
        except SdError as exc:
            self.set_notice(str(exc))
            return
        name = Path(self.export_path).name
        self.sd_mode = "load"
        self.set_notice(f"Saved {name}.")
        self.screen = self.export_return or "keys"
        self.back = list(self.export_back)

    def _export_format(self, frame: Frame):
        frame.header("Export format", "back")
        formats = self._key_qr_formats()
        if not formats:
            frame.text("This key is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
            return
        y = HEADER + 24
        for index, (name, _payload) in enumerate(formats):
            y = frame.button(y, name, f"export-format-{index}")

    def _export_name(self, frame: Frame):
        frame.header("New file", "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        self._paint_hscroll_field(frame, box, self.filename, self.filename_cursor, "File name")
        frame.button(box[3] + 12, "Save", "export-save-new")
        self._passphrase_keyboard(frame)

    def _sd(self, frame: Frame):
        try:
            entries = list_folder(self.sd_dir)
        except SdError as exc:
            frame.header("Choose a file" if self.sd_mode == "export" else "SD card", "back")
            frame.text(str(exc), MARGIN, HEADER + 24, size=TITLE_SIZE)
            return
        exporting = self.sd_mode == "export"
        rows = []
        if self.sd_dir:
            rows.append(("..", "sd-up"))
        for entry in entries:
            relative = child_path(self.sd_dir, entry["name"])
            if entry["kind"] == "dir":
                rows.append((entry["name"] + "/", f"sd-into:{relative}"))
            else:
                verb = "sd-write" if exporting else "sd-read"
                rows.append((entry["name"], f"{verb}:{relative}"))
        list_top = HEADER + 60
        name_width = WIDTH - 2 * MARGIN - 32
        face = font(TITLE_SIZE)
        placed = []
        top = list_top
        for label, action in rows:
            lines = _filename_lines(frame.draw, label, face, name_width)
            height = _sd_row_height(len(lines))
            placed.append((top, height, lines, label, action))
            top += height + 8
        end = top if placed else list_top
        button_h = frame.button_height("New File") if exporting else 0
        clearance = button_h + 28 if exporting else 96
        offset = self._scroll_offset("sd", end, clearance=clearance)
        for row_top, height, lines, label, action in placed:
            self._sd_row(frame, row_top - offset, list_top, height, lines, label, action)
        if exporting:
            frame.button(HEIGHT - 16 - button_h, "New File", "export-new")
        frame.header("Choose a file" if exporting else "SD card", "back")
        frame.draw.rectangle((0, HEADER, WIDTH, list_top), fill=PAPER)
        shown = _one_line(frame, self.sd_dir or "/", TITLE_SIZE, WIDTH - 2 * MARGIN)
        frame.text(shown, MARGIN, HEADER + 12, size=TITLE_SIZE, fill=MUTED, mono=True)
        if not entries:
            if placed:
                row_top, height, _lines, _label, _action = placed[0]
                message_y = row_top - offset + height + 12
            else:
                message_y = list_top
            message = "This folder is empty." if self.sd_dir else "This SD card is empty."
            frame.text(message, MARGIN, message_y, size=TITLE_SIZE)

    def _sd_row(self, frame: Frame, top: int, list_top: int, height: int, lines: list[str], label: str, action: str):
        if top >= HEIGHT or top + height <= list_top:
            return
        frame.draw.rounded_rectangle((MARGIN, top, WIDTH - MARGIN, top + height), radius=14, fill=WHITE, outline=LINE)
        y = top + 20
        face = font(TITLE_SIZE)
        for line in lines:
            if y + TITLE_SIZE > list_top:
                frame.draw.text((MARGIN + 16, y), line, font=face, fill=INK)
            y += TITLE_SIZE + 8
        frame.hit((MARGIN, max(top, list_top), WIDTH - MARGIN, min(top + height, HEIGHT)), action, label)

    def camera_preview_box(self):
        """Where the live camera picture is drawn, in screen pixels. None hides it."""
        if self.screen == "scan":
            return (0, HEADER, WIDTH, HEIGHT - 108)
        if self.screen == "camera":
            return (MARGIN, HEADER + 108, WIDTH - MARGIN, HEIGHT - 290)
        return None

    def remember_camera_frame(self, data: bytes):
        """Keep a recent picture so Capture can mix it into the new seed."""
        if self.screen != "camera" or not data:
            return
        self.camera_frames.append(data)
        if len(self.camera_frames) > 8:
            self.camera_frames = self.camera_frames[-8:]
        self.camera_final = data

    def _viewfinder(self, frame: Frame):
        box = self.camera_preview_box()
        if box is None:
            return
        frame.draw.rectangle(box, fill=(12, 14, 18))

    def scan_prompt(self) -> str:
        """The line under the viewfinder. A missing camera replaces the instruction."""
        if self.camera_unavailable:
            return "The camera is not available."
        if self.qr_sequence.expected > 1 and self.qr_sequence.received:
            if self.qr_sequence.received < self.qr_sequence.expected:
                return f"Scanned {self.qr_sequence.received} of {self.qr_sequence.expected} parts."
            return "Reading the QR sequence."
        if self.scan_kind == "descriptor":
            return "Point the camera at one wallet descriptor QR code."
        return "Point the camera at one QR code."

    def _scan(self, frame: Frame):
        descriptor = self.scan_kind == "descriptor"
        frame.header("Scan descriptor" if descriptor else "Scan QR", "back")
        self._viewfinder(frame)
        frame.text(
            self.scan_prompt(),
            MARGIN,
            HEIGHT - 96,
            size=TITLE_SIZE,
            fill=RED if self.camera_unavailable else INK,
        )

    def _show_load_error(self, message: str, expect: str):
        """Replace a scan or SD-card failure toast with its own screen."""
        self.load_error = message
        self.load_error_home = "wallets" if expect == "descriptor" else "keys"
        self.notice = ""
        self.notice_until = None
        self.confirm = None
        self.menu = False
        self.add_menu = False
        self.open_dropdown = None
        self.back = []
        self.screen = "load-error"

    def _load_error(self, frame: Frame):
        title = "Error loading wallet" if self.load_error_home == "wallets" else "Error loading key"
        frame.header(title)
        frame.text(self.load_error or "The key could not be loaded.", MARGIN, HEADER + 28, size=BODY_SIZE, fill=RED)
        frame.button(HEIGHT - 110, "OK", "load-error-ok")

    def accept_qr(self, text: str):
        """Import a payload read from a QR code. Ignored unless the scan screen is open."""
        if self.screen != "scan":
            return
        try:
            payload = self.qr_sequence.take(text, self.session.network, "QR code", self.scan_kind)
        except SessionError as exc:
            self.qr_sequence.reset()
            self._show_load_error(str(exc), self.scan_kind)
            return
        if payload is None:
            return
        self.qr_sequence.reset()
        self._import_payload(payload, self.scan_kind, "QR code")

    def _import_payload(self, text: str, expect: str, source: str):
        try:
            added = import_scanned(self.session, text, expect=expect, source=source)
        except SessionError as exc:
            self._show_load_error(str(exc), expect)
            return
        if added.get("choose") == "descriptor":
            self.descriptor_choice = added
            self.descriptor_key_index = 0
            self.open_dropdown = None
            self.wallet_plan = None
            self.go("descriptor-choice")
            return
        if added.get("review") == "external-key":
            self.wallet_plan = None
            self.pending_external = added["key"]
            self.external_format = "xpub"
            self.open_dropdown = None
            self.scroll["external-review"] = 0
            self.go("external-review")
            return
        if added.get("review") == "wallet":
            self._start_wallet_import(added["text"])
            return
        self._show_imported(added)

    def note_qr_unsupported(self):
        if self.screen == "scan":
            self.set_notice("This browser cannot read QR codes.")

    def _show_imported(self, added: dict, prefer_key: bool = False):
        message = added["message"]
        if added.get("warnings"):
            message = f"{message} {' '.join(added['warnings'])}"
        self.set_notice(message)
        fingerprint = added.get("fingerprint")
        if fingerprint is not None and (prefer_key or "wallet" not in added["message"].lower()):
            self.selected_fp = fingerprint
            record = self.session.fingerprints.get(fingerprint)
            if prefer_key and record is not None and record.keys:
                self.selected_key_index = len(record.keys) - 1
            else:
                self.selected_key_index = 0
            self.back = ["keys"]
            self.scroll["key"] = 0
            self.screen = "key"
            return
        self.back = []
        self.screen = "wallets" if self.session.wallets else "keys"
        self.menu = False

    def _camera(self, frame: Frame):
        frame.header("Camera", "back")
        frame.text("Point the camera at a detailed scene.", MARGIN, HEADER + 16, size=TITLE_SIZE)
        self._viewfinder(frame)
        frame.text(
            f"This capture makes a {self.entropy_words}-word seed. The same scene on another device does not repeat.",
            MARGIN,
            HEIGHT - 278,
            size=TITLE_SIZE,
        )
        frame.button(HEIGHT - 110, "Capture", "camera-capture")

    def _entropy(self, frame: Frame):
        words = self.pending_mnemonic.split()
        end = self._entropy_flow(frame, words, paint=False)
        offset = self._scroll_offset("entropy", end, clearance=16)
        self._entropy_flow(frame, words, paint=True, offset=offset)
        frame.header("Back up this seed", "back")

    def _entropy_flow(self, frame: Frame, words: list[str], paint: bool, offset: int = 0) -> int:
        """The backup warning, the word cards, then Continue. Nothing is pinned to the bottom."""
        intro = "Write these words down. They stay in memory only until you power off."
        lines = wrap(frame.draw, intro, font(TITLE_SIZE), WIDTH - 2 * MARGIN) or [""]
        y = HEADER + 12
        if paint:
            frame.text(intro, MARGIN, y - offset, size=TITLE_SIZE)
        y += len(lines) * (TITLE_SIZE + 8) + 8
        y = self._flow_word_cards(frame, words, y, paint, offset)
        return self._flow_button(frame, y + 16, "Continue", "entropy-save", paint, offset)

    def _flow_word_cards(self, frame: Frame, words: list[str], y: int, paint: bool, offset: int) -> int:
        """The same one-column cards as the seed display, in the page flow."""
        if not words:
            return y
        columns = SEED_CARD_COLUMNS
        gap = SEED_CARD_GAP
        inset = MARGIN
        pad_x = SEED_CARD_PAD_X
        pad_y = 14
        cell_w = (WIDTH - 2 * inset - gap * (columns - 1)) // columns
        size = _grid_font_size(frame.draw, cell_w - 2 * pad_x, SEED_CARD_FONT)
        face = font(size, mono=True)
        cell_h = size + 2 * pad_y
        rows = (len(words) + columns - 1) // columns
        if paint:
            self._paint_word_cells(
                frame.draw,
                list(enumerate(words, start=1)),
                y - offset,
                0,
                inset,
                cell_w,
                cell_h,
                gap,
                pad_x,
                face,
                columns,
                clip_top=HEADER,
                clip_bottom=HEIGHT,
            )
        return y + rows * cell_h + (rows - 1) * gap

    def _push_entropy(self, digit: str, allowed: str):
        if digit not in allowed:
            return
        if allowed == "123456":
            target = 50 if self.entropy_words == 12 else 99
        else:
            target = 128 if self.entropy_words == 12 else 256
        if len(self.entropy_digits) >= target:
            return
        self.entropy_digits += digit
        if len(self.entropy_digits) != target:
            return
        try:
            if allowed == "123456":
                mnemonic = mnemonic_from_dice(self.entropy_digits)
            else:
                mnemonic = mnemonic_from_coins(self.entropy_digits)
        except ValueError as exc:
            self.set_notice(str(exc))
            return
        self._offer_mnemonic(mnemonic)

    def _capture_camera(self):
        if not self.camera_final:
            self.set_notice("The camera has not captured a picture yet.")
            return
        serial = os.environ.get("BIGSIGNER_CPU_SERIAL", "bigsigner-emulator").encode()
        mnemonic = mnemonic_from_camera(
            self.camera_frames,
            self.camera_final,
            serial,
            str(time.time()),
            words=self.entropy_words,
        )
        self.camera_frames = []
        self.camera_final = b""
        self._offer_mnemonic(mnemonic)

    def _offer_mnemonic(self, mnemonic: str):
        self.pending_mnemonic = mnemonic
        self.scroll["entropy"] = 0
        self.go("entropy")

    def _save_pending_mnemonic(self):
        if not self.pending_mnemonic:
            self.set_notice("There is no seed to save.")
            return
        self.seed_words = self.pending_mnemonic.split()
        self.seed_length = len(self.seed_words)
        self.word_prefix = ""
        self.word_cursor = 0
        self.go("passphrase-ask")

    def _boot(self, frame: Frame):
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=NAVY)
        mark = logo(WIDTH - 48, 280)
        logo_top = 200
        frame.image.paste(mark, ((WIDTH - mark.width) // 2, logo_top), mark)
        y = logo_top + mark.height + 48
        caption_size = 42
        for caption in (f"Version {__version__}", "Fork of SeedSigner"):
            caption_width = frame.draw.textlength(caption, font=font(caption_size))
            frame.draw.text(((WIDTH - caption_width) / 2, y), caption, font=font(caption_size), fill=WHITE)
            y += caption_size + 20
        frame.hit((0, 0, WIDTH, HEIGHT), "boot", "boot")

    def _advance_boot(self):
        if self.screen != "boot":
            return
        # The hold starts when the loading screen is actually shown. By then
        # startup has finished and the SD card is safe to remove.
        if self.boot_until is None:
            self.boot_until = time.monotonic() + BOOT_HOLD
            return
        if time.monotonic() >= self.boot_until:
            self._leave_boot()

    def _leave_boot(self):
        if self.screen != "boot":
            return
        self.screen = "warning"
        self._load_initial_seed()
        self._load_initial_wallet_descriptor()

    def _load_initial_seed(self):
        raw = os.environ.get("BIGSIGNER_INITIAL_SEED", "").strip()
        if not raw:
            return
        try:
            added = self.session.add_mnemonic(raw)
        except SessionError as exc:
            self._initial_notice(f"BIGSIGNER_INITIAL_SEED: {exc}")
            return
        self.selected_fp = added["fingerprint"]

    def _load_initial_wallet_descriptor(self):
        raw = os.environ.get("BIGSIGNER_INITIAL_WALLET_DESCRIPTOR", "").strip()
        if not raw:
            return
        try:
            added = self.session.load_descriptor_now(raw)
        except SessionError as exc:
            self._initial_notice(f"BIGSIGNER_INITIAL_WALLET_DESCRIPTOR: {exc}")
            return
        message = added["message"]
        if added.get("warnings"):
            message = f"{message} {' '.join(added['warnings'])}"
        self._initial_notice(message)
        wallet = added.get("wallet")
        if wallet is not None and wallet in self.session.wallets:
            self.wallet_index = self.session.wallets.index(wallet)
        fingerprint = added.get("fingerprint")
        if fingerprint is not None and self.selected_fp is None:
            self.selected_fp = fingerprint

    def _initial_notice(self, message: str):
        print(message, file=sys.stderr, flush=True)
        if self.notice:
            self.set_notice(f"{self.notice} {message}")
        else:
            self.set_notice(message)

    def _warning(self, frame: Frame):
        frame.header("Remove SD Card")
        mark = logo(WIDTH - 48, 180)
        logo_top = HEADER + 24
        frame.image.paste(mark, ((WIDTH - mark.width) // 2, logo_top), mark)
        version = f"Version {__version__}"
        version_size = 24
        version_y = logo_top + mark.height + 12
        face = font(version_size)
        version_width = frame.draw.textlength(version, font=face)
        frame.draw.text(((WIDTH - version_width) / 2, version_y), version, font=face, fill=MUTED)
        frame.text(
            "It is now safe to remove the SD card to guarantee nothing will be saved on permanent storage.",
            MARGIN,
            version_y + version_size + 24,
            size=BODY_SIZE,
        )
        frame.button(HEIGHT - 110, "Continue", "warning-ok")

    def _keys(self, frame: Frame):
        y = HEADER + 24
        sections = self._key_sections()
        placed = []
        if not any(items for _title, _icon, _awesome, items in sections):
            frame.text("No keys found. Press the plus button to add a new key.", MARGIN, y, size=BODY_SIZE)
        label_face = font(TITLE_SIZE)
        for title, icon, awesome, items in sections:
            if not items:
                continue
            text_x = MARGIN + TITLE_SIZE + 12
            lines = wrap(frame.draw, title, label_face, WIDTH - MARGIN - text_x) or [""]
            placed.append(("label", y, title, icon, awesome, len(lines)))
            y += len(lines) * (TITLE_SIZE + 8) + 12
            for fingerprint, record, key, index in items:
                placed.append(("card", y, fingerprint, record, key, index))
                y += self._key_card_height(frame, record, key) + 12
        offset = self._scroll_offset("keys", y if placed else HEADER + 24, clearance=_PLUS_CLEARANCE)
        for item in placed:
            if item[0] == "label":
                _kind, top, title, icon, awesome, _line_count = item
                text_x = frame.leading_icon(icon, MARGIN, top - offset, TITLE_SIZE, INK, awesome=awesome)
                frame.text(title, text_x, top - offset, size=TITLE_SIZE)
            else:
                _kind, top, fingerprint, record, key, index = item
                self._key_card(frame, top - offset, fingerprint, record, key, index)
        frame.header("Bitcoin Keys", "menu")
        if self.add_menu:
            self._speed_dial(
                frame,
                (
                    ("Scan QR Code", "add-scan"),
                    ("Manual Entry", "add-manual"),
                    ("Load from SD Card", "add-sd"),
                    ("Generate New Seed", "add-generate"),
                ),
            )
        self._plus(frame, "toggle-add", Icons.CLOSE if self.add_menu else Icons.PLUS)

    def _key_sections(self):
        """Seeds, then single-sig external keys, then multisig external keys."""
        seeds = []
        singles = []
        multis = []
        for fingerprint, record in self.session.fingerprints.items():
            if any(key.has_seed for key in record.keys):
                seeds.append((fingerprint, record, None, 0))
                continue
            for index, key in enumerate(record.keys):
                if key.has_seed:
                    continue
                bucket = multis if getattr(key, "role", None) == MULTISIG_NATIVE else singles
                bucket.append((fingerprint, record, key, index))
        seeds.sort(key=lambda item: self._card_added(item[1], True))
        singles.sort(key=self._external_card_sort)
        multis.sort(key=self._external_card_sort)
        return (
            ("Seeds", Icons.KEY, False, seeds),
            ("SingleSig External Keys", Icons.EYE, True, singles),
            ("MultiSig External Keys", Icons.EYE, True, multis),
        )

    def _external_card_sort(self, item):
        _fingerprint, record, key, _index = item
        script = 1 if getattr(key, "role", None) == SINGLESIG_TAPROOT else 0
        account = 0 if key.account is None else key.account
        return (record.nickname.casefold(), script, account)

    def _key_card_height(self, frame: Frame, record, key=None) -> int:
        return self._key_card_body(frame, 0, record, None, paint=False, only=key) - 0

    def _external_script(self, key) -> str:
        """Native-Segwit or Taproot. The section title already says single-sig or multisig."""
        if getattr(key, "role", None) == SINGLESIG_TAPROOT:
            return "Taproot"
        return "Native-Segwit"

    def _external_kind(self, key) -> str:
        if getattr(key, "role", None) == SINGLESIG_TAPROOT:
            return "Taproot SingleSig"
        if getattr(key, "role", None) == MULTISIG_NATIVE:
            return "Native-Segwit MultiSig"
        return "Native-Segwit SingleSig"

    def _card_added(self, record, seeds: bool) -> int:
        return min(key.added for key in record.keys if key.has_seed is seeds)

    def _external_keys(self, record):
        return sorted((key for key in record.keys if not key.has_seed), key=lambda key: key.added)

    def _key_card(self, frame: Frame, top: int, fingerprint: bytes, record, key=None, key_index: int = 0):
        height = self._key_card_height(frame, record, key)
        if top >= HEIGHT or top + height <= HEADER:
            return
        frame.draw.rounded_rectangle((MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=WHITE, outline=LINE)
        self._key_card_body(frame, top, record, fingerprint, paint=True, only=key)
        action = f"open-fp-{fingerprint.hex()}" if key is None else f"open-fp-{fingerprint.hex()}-{key_index}"
        frame.hit(
            (MARGIN, max(top, HEADER), WIDTH - MARGIN, min(top + height, HEIGHT)),
            action,
            record.nickname,
        )

    def _key_card_body(self, frame: Frame, top: int, record, fingerprint: bytes | None, paint: bool, only=None) -> int:
        inset = MARGIN + 16
        right = WIDTH - MARGIN - 16
        y = top + _CARD_PAD
        for line in _fingerprint_name_lines(record.nickname):
            if paint:
                _draw_centered(frame, line, y, NAME_ON_CARD)
            y += NAME_ON_CARD + 8
        if paint and fingerprint is not None:
            hex_x = frame.leading_icon(
                Icons.FINGERPRINT, inset, y, NAME_ON_CARD, MUTED, icon_size=_DETAIL_ICON,
            )
            frame.text(fingerprint.hex(), hex_x, y, size=NAME_ON_CARD, fill=MUTED, mono=True)
        y += max(NAME_ON_CARD, _DETAIL_ICON) + 12
        text_width = right - (inset + _DETAIL_ICON + 12)
        if any(key.has_seed for key in record.keys):
            summary = self.session.seed_summary(record.keys[0])
            if paint:
                text_x = frame.leading_icon(
                    Icons.SEED, inset, y, NAME_ON_CARD, MUTED, awesome=True, icon_size=_DETAIL_ICON,
                )
                y = frame.text(summary, text_x, y, size=NAME_ON_CARD, fill=MUTED, width=text_width)
            else:
                lines = wrap(frame.draw, summary, font(NAME_ON_CARD), text_width) or [""]
                y += len(lines) * (NAME_ON_CARD + 8)
        else:
            kind_width = right - inset
            keys = [only] if only is not None else self._external_keys(record)
            for key in keys:
                kind = self._external_script(key)
                account = f"Account #{key.account}"
                if paint:
                    y = frame.text(kind, inset, y, size=NAME_ON_CARD, fill=MUTED, width=kind_width)
                    y = frame.text(account, inset, y, size=NAME_ON_CARD, fill=MUTED, width=kind_width)
                else:
                    for value in (kind, account):
                        lines = wrap(frame.draw, value, font(NAME_ON_CARD), kind_width) or [""]
                        y += len(lines) * (NAME_ON_CARD + 8)
        return y + _CARD_PAD

    def _labeled_mono(self, frame: Frame, y: int, label: str, value: str, size: int = 22, fill=INK) -> int:
        label_face = font(size)
        value_face = font(size, mono=True)
        frame.draw.text((MARGIN, y), label, font=label_face, fill=fill)
        x = MARGIN + frame.draw.textlength(label, font=label_face)
        frame.draw.text((x, y), value, font=value_face, fill=fill)
        return y + size + 8

    def _stored_key(self):
        """The fingerprint record and the key opened from its card."""
        record = None if self.selected_fp is None else self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys:
            return record, None
        index = self.selected_key_index
        if index < 0 or index >= len(record.keys):
            index = 0
        return record, record.keys[index]

    def _key(self, frame: Frame):
        record, key = self._stored_key()
        has_seed = key is not None and key.has_seed
        if record is None or key is None:
            title = "Key"
        elif has_seed:
            title = "Seed Key"
        else:
            title = "External Key"
        if record is None or key is None:
            frame.header(title, "back")
            frame.text("This key is no longer loaded.", MARGIN, 140)
            return
        flow_end = self._key_flow(frame, record, key, paint=False)
        delete_h = frame.button_height("Delete Key")
        clearance = 24
        if self.notice:
            _face, _lines, _line_h, _pad, notice_top, _height = self._notice_layout(frame)
            clearance = max(clearance, HEIGHT - notice_top + 12)
        delete_y = HEIGHT - clearance - delete_h
        # A seed key pins Delete when the rest fits. An external key keeps Delete in the button list.
        if key.has_seed and flow_end + 16 <= delete_y:
            self.scroll["key"] = 0
            self.scroll_max["key"] = 0
            self._key_flow(frame, record, key, paint=True)
            frame.button(delete_y, "Delete Key", "delete-key", color=RED)
        else:
            offset = self._scroll_offset("key", flow_end + 16 + delete_h, clearance=clearance)
            self._key_flow(frame, record, key, paint=True, offset=offset)
            frame.button(flow_end + 16 - offset, "Delete Key", "delete-key", color=RED)
        frame.header(title, "back")

    def _fitted_fingerprint(self, frame: Frame) -> tuple[int, int]:
        """Title-sized fingerprint line, or the next size down when the line would overflow."""
        for text_size in (TITLE_SIZE, 30, 28):
            icon = _DETAIL_ICON if text_size == TITLE_SIZE else text_size
            label = frame.draw.textlength("Fingerprint: ", font=font(text_size))
            hex_width = frame.draw.textlength("DDDDDDDD", font=font(text_size, mono=True))
            if MARGIN + icon + 10 + label + hex_width <= WIDTH - MARGIN:
                return text_size, icon
        return 28, 28

    def _key_flow(self, frame: Frame, record, key, paint: bool, offset: int = 0) -> int:
        """Lay out the key screen under the title. Returns the unshifted y after the last control."""
        y = HEADER + 20
        text_size, icon = self._fitted_fingerprint(frame)
        glyph, awesome = _name_icon(key.has_seed)
        y = _draw_name_block(
            frame, y, _fingerprint_name_lines(record.nickname), NAME_ON_KEY, glyph, awesome, icon, paint, offset,
        )
        if paint:
            frame.fingerprint_line(y - offset, record.fingerprint.hex(), text_size=text_size, icon_size=icon)
        y += icon + 16
        if key.has_seed:
            generated = self.session.generated_from(key)
            if paint:
                frame.text(generated, MARGIN, y - offset, size=TITLE_SIZE)
            y += self._text_height(frame, generated, TITLE_SIZE)
            if key.passphrase:
                y = self._flow_button(frame, y, "Show Passphrase", "show-passphrase", paint, offset)
                copy = "Create a Copy of This Seed with a Different Passphrase"
            else:
                note = "No passphrase is used."
                if paint:
                    frame.text(note, MARGIN, y - offset, size=TITLE_SIZE, fill=MUTED)
                y += self._text_height(frame, note, TITLE_SIZE)
                copy = "Create a Copy of This Seed with a Passphrase"
            y = self._flow_button(frame, y, "Show Seed", "show-seed", paint, offset)
            y = self._flow_button(frame, y, copy, "copy-passphrase", paint, offset)
            y = self._flow_button(
                frame, y, "Derive a\nNative-Segwit\nSingleSig Key", "derive-native", paint, offset,
                "Derive a Native-Segwit SingleSig Key",
            )
            y = self._flow_button(
                frame, y, "Derive a\nNative-Segwit\nMultiSig Key", "derive-multisig", paint, offset,
                "Derive a Native-Segwit MultiSig Key",
            )
            return self._flow_button(
                frame, y, "Derive a\nTaproot\nSingleSig Key", "derive-taproot", paint, offset,
                "Derive a Taproot SingleSig Key",
            )
        y = self._flow_text(frame, y, f"Type: {self._external_kind(key)}", paint, offset, size=text_size)
        if key.account is not None:
            y = self._flow_text(frame, y, f"Account: {key.account}", paint, offset, size=text_size)
        preview = key.xpub.to_string()[:XPUB_KEY_PREVIEW] + "\u2026"
        y = self._flow_value_below(frame, y, "Derivation Path:", format_path(list(key.path)), paint, offset, text_size)
        y = self._flow_value_below(frame, y, "Extended Public Key:", preview, paint, offset, text_size)
        if key.role == SINGLESIG_NATIVE:
            y = self._flow_button(
                frame, y, self._seed_wallet_label(SINGLESIG_NATIVE, "Native-Segwit"), "make-xpub-wallet", paint, offset,
            )
        elif key.role == SINGLESIG_TAPROOT:
            y = self._flow_button(
                frame, y, self._seed_wallet_label(SINGLESIG_TAPROOT, "Taproot"), "make-xpub-wallet", paint, offset,
            )
        y += 20
        y = self._flow_button(frame, y, "Show Full Details", "show-qr", paint, offset)
        return self._flow_button(frame, y, "Export to SD Card", "export-key", paint, offset)

    def _flow_text(self, frame: Frame, y: int, value: str, paint: bool, offset: int, size: int, fill=INK, mono: bool = False) -> int:
        if paint:
            frame.text(value, MARGIN, y - offset, size=size, fill=fill, mono=mono)
        return y + self._text_height(frame, value, size, mono=mono)

    def _flow_value_below(self, frame: Frame, y: int, label: str, value: str, paint: bool, offset: int, size: int) -> int:
        """A title-sized label, then the technical value centered on the next line."""
        y = self._flow_text(frame, y, label, paint, offset, size, fill=MUTED)
        top = y - offset
        self._flow_value_box = (0, top, WIDTH, top + size + 8)
        face = font(size, mono=True)
        if paint:
            width = frame.draw.textlength(value, font=face)
            frame.draw.text((max(MARGIN, (WIDTH - width) / 2), top), value, font=face, fill=MUTED)
        return y + size + 8

    def _flow_button(
        self, frame: Frame, y: int, label: str, action: str, paint: bool, offset: int, hit_label: str = "",
    ) -> int:
        height = frame.button_height(label)
        top = y - offset
        if paint and top + height > HEADER and top < HEIGHT:
            frame.button(top, label, action, label=hit_label)
        return y + height + 12

    def _open_derive(self, role: str):
        record = None if self.selected_fp is None else self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys or not record.keys[0].has_seed:
            self.set_notice("Load a seed before deriving a key.")
            return
        self.derive_role = role
        self.derive_account = 0
        self.scroll["derive"] = 0
        self.go("derive")

    def _derived_key(self):
        if self.selected_fp is None or self.derive_role is None:
            return None
        try:
            return _public_for(self.session, self.selected_fp, self.derive_role, self.derive_account)
        except SessionError:
            return None

    def _step_derive_account(self, delta: int):
        account = self.derive_account + delta
        if account < 0 or account >= 0x80000000:
            return
        self.derive_account = account

    def _edit_derive_account(self):
        if self._derived_key() is None:
            self.set_notice("This seed is no longer loaded.")
            return
        self.account_fp = self.selected_fp
        self.account_text = str(self.derive_account)
        self.account_for = "derive"
        self.go("account")

    def _derive(self, frame: Frame):
        if self._patch_derive(frame):
            return
        record = None if self.selected_fp is None else self.session.fingerprints.get(self.selected_fp)
        key = self._derived_key()
        if record is None or key is None or not record.keys or not record.keys[0].has_seed:
            frame.header("Derive Key", "back")
            frame.text("This seed is no longer loaded.", MARGIN, 140)
            return
        end = self._derive_flow(frame, record, key, paint=False)
        offset = self._scroll_offset("derive", end, clearance=16)
        self._derive_flow(frame, record, key, paint=True, offset=offset)
        frame.header("Derive Key", "back")
        self._remember_derive(frame, key)

    def _current_derive_shell(self, key):
        label = ""
        if key.role in (SINGLESIG_NATIVE, SINGLESIG_TAPROOT):
            script = "Taproot" if key.role == SINGLESIG_TAPROOT else "Native-Segwit"
            label = self._seed_wallet_label(key.role, script)
        return (self.selected_fp, self.derive_role, self.scroll.get("derive", 0), label)

    def _remember_derive(self, frame: Frame, key):
        """Keep this picture so the next account changes three lines, not the page."""
        if self.menu or self.notice or self.confirm or self._derive_account_box is None:
            self._derive_picture = None
            return
        self._derive_picture = frame.image
        self._derive_hits = list(frame.hits)
        self._derive_shell = self._current_derive_shell(key)
        self._derive_minus_on = self.derive_account > 0
        self._derive_plus_on = self.derive_account < 0x7FFFFFFF
        self._derive_still = list(self._still_boxes)

    def _patch_derive(self, frame: Frame) -> bool:
        if self._derive_picture is None or self._derive_path_box is None or self._derive_xpub_box is None:
            return False
        if self.menu or self.notice or self.confirm:
            return False
        if (self.derive_account > 0) != self._derive_minus_on or (self.derive_account < 0x7FFFFFFF) != self._derive_plus_on:
            return False
        key = self._derived_key()
        if key is None or self._derive_shell != self._current_derive_shell(key):
            return False
        image = self._derive_picture
        frame.image = image
        frame.draw = ImageDraw.Draw(image)
        frame.hits = list(self._derive_hits)
        self._still_boxes = list(self._derive_still)
        box = self._derive_account_box
        self._account_textbox(frame, box[1], str(self.derive_account), left=box[0], right=box[2])
        self._paint_centered_value(frame, self._derive_path_box, format_path(list(key.path)))
        preview = key.xpub.to_string()[:XPUB_ACCOUNT_PREVIEW] + "\u2026"
        self._paint_centered_value(frame, self._derive_xpub_box, preview)
        frame.header("Derive Key", "back")
        top = min(box[1], self._derive_path_box[1], self._derive_xpub_box[1])
        bottom = max(box[3], self._derive_path_box[3], self._derive_xpub_box[3])
        self.dirty = (max(0, top), min(HEIGHT, bottom))
        return True

    def _paint_centered_value(self, frame: Frame, box, value: str):
        frame.draw.rectangle(box, fill=PAPER)
        face = font(self._derive_text_size, mono=True)
        width = frame.draw.textlength(value, font=face)
        _left, top, _right, bottom = frame.draw.textbbox((0, 0), value, font=face)
        text_y = box[1] + (box[3] - box[1] - (bottom - top)) / 2 - top
        frame.draw.text((max(MARGIN, (WIDTH - width) / 2), text_y), value, font=face, fill=MUTED)

    def _derive_flow(self, frame: Frame, record, key, paint: bool, offset: int = 0) -> int:
        """The external-key details. The account control sits under the type and above the path."""
        y = HEADER + 16
        text_size, icon = self._fitted_fingerprint(frame)
        self._derive_text_size = text_size
        y = _draw_name_block(
            frame, y, _fingerprint_name_lines(record.nickname), NAME_ON_KEY, Icons.KEY, False, icon, paint, offset,
        )
        if paint and y - offset >= HEADER:
            frame.fingerprint_line(y - offset, record.fingerprint.hex(), text_size=text_size, icon_size=icon)
        y += icon + 16
        y = self._flow_text(frame, y, f"Type: {self._external_kind(key)}", paint, offset, size=text_size)
        y = self._account_selector(frame, y, self.derive_account, paint, offset)
        preview = key.xpub.to_string()[:XPUB_ACCOUNT_PREVIEW] + "\u2026"
        y = self._flow_value_below(frame, y, "Derivation Path:", format_path(list(key.path)), paint, offset, text_size)
        self._derive_path_box = self._flow_value_box
        y = self._flow_value_below(frame, y, "Extended Public Key:", preview, paint, offset, text_size)
        self._derive_xpub_box = self._flow_value_box
        if key.role in (SINGLESIG_NATIVE, SINGLESIG_TAPROOT):
            script = "Taproot" if key.role == SINGLESIG_TAPROOT else "Native-Segwit"
            y = self._flow_button(frame, y, self._seed_wallet_label(key.role, script), "derive-wallet", paint, offset)
        y += 20
        y = self._flow_button(frame, y, "Show Full Details", "derive-details", paint, offset)
        return self._flow_button(frame, y, "Export to SD Card", "export-derived", paint, offset)

    def _account_selector(self, frame: Frame, y: int, value: int, paint: bool, offset: int) -> int:
        if paint:
            frame.text("Account", MARGIN, y - offset, size=TITLE_SIZE, fill=MUTED)
        y += self._text_height(frame, "Account", TITLE_SIZE)
        side = 64
        gap = 12
        top = y - offset
        if paint and top + 64 > HEADER and top < HEIGHT:
            self._brightness_button(frame, (MARGIN, top, MARGIN + side, top + 64), "-", value > 0, "derive-dec")
            self._brightness_button(
                frame,
                (WIDTH - MARGIN - side, top, WIDTH - MARGIN, top + 64),
                "+",
                value < 0x7FFFFFFF,
                "derive-inc",
            )
            # A press on this panel is reported a little above the drawn key.
            reach = 24
            if value > 0:
                minus = (0, top - reach, MARGIN + side + gap // 2, top + 64)
                frame.hit(minus, "derive-dec", "-")
                self._still_boxes.append(minus)
            if value < 0x7FFFFFFF:
                plus = (WIDTH - (MARGIN + side + gap // 2), top - reach, WIDTH, top + 64)
                frame.hit(plus, "derive-inc", "+")
                self._still_boxes.append(plus)
            box = self._account_textbox(
                frame, top, str(value), left=MARGIN + side + gap, right=WIDTH - MARGIN - side - gap,
            )
            self._derive_account_box = box
            frame.hit(box, "derive-edit", "Account")
            # The number is wide and sits in the middle, so a drag on it scrolls.
            self._still_boxes.append((MARGIN, top, MARGIN + side, top + 64))
            self._still_boxes.append((WIDTH - MARGIN - side, top, WIDTH - MARGIN, top + 64))
        return y + 64 + 16

    def _open_derived_details(self):
        if self._derived_key() is None:
            self.set_notice("This seed is no longer loaded.")
            return
        self.qr_source = "derive"
        self._open_key_qr()

    def _make_derived_wallet(self):
        if self.derive_role == SINGLESIG_TAPROOT:
            self._make_wallet("tr", self.derive_account)
        elif self.derive_role == SINGLESIG_NATIVE:
            self._make_wallet("wpkh", self.derive_account)

    def _wallets(self, frame: Frame):
        y = HEADER + 24
        cards = []
        if not self.session.wallets:
            frame.text("No wallets yet. Open a key and create one, or press the plus button.", MARGIN, y, size=BODY_SIZE)
        for index, wallet in enumerate(self.session.wallets):
            cards.append((y, index, wallet))
            y += self._wallet_card_height(wallet) + 14
        offset = self._scroll_offset("wallets", y if cards else HEADER + 24, clearance=_PLUS_CLEARANCE)
        for top, index, wallet in cards:
            self._wallet_card(frame, top - offset, index, wallet)
        frame.header("Bitcoin Wallets", "menu")
        if self.add_menu:
            self._speed_dial(
                frame,
                (
                    ("Scan QR Code", "wallet-scan"),
                    ("Load from SD Card", "wallet-sd"),
                    ("Select from Existing SingleSig Key", "wallet-singlesig"),
                    ("Select from Existing MultiSig Keys", "wallet-multisig"),
                ),
            )
        self._plus(frame, "toggle-add", Icons.CLOSE if self.add_menu else Icons.PLUS)

    def _wallet_kind_line(self, wallet) -> str:
        kind = "Taproot" if wallet.role == SINGLESIG_TAPROOT else "Native-Segwit"
        if wallet.multisig:
            return f"{wallet.threshold}-of-{len(wallet.fingerprints)} {kind}"
        return kind

    def _wallet_title(self, wallet) -> str:
        return self._wallet_kind_line(wallet)

    def _wallet_card_height(self, wallet) -> int:
        draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, 4)))
        return self._wallet_card_body(draw, 0, wallet, paint=False)

    def _wallet_card(self, frame: Frame, top: int, index: int, wallet):
        height = self._wallet_card_body(frame.draw, top, wallet, paint=False) - top
        if top >= HEIGHT or top + height <= HEADER:
            return
        label = self._wallet_title(wallet)
        frame.draw.rounded_rectangle((MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=WHITE, outline=LINE)
        self._wallet_card_body(frame.draw, top, wallet, paint=True, frame=frame)
        frame.hit(
            (MARGIN, max(top, HEADER), WIDTH - MARGIN, min(top + height, HEIGHT)),
            f"open-wallet-{index}",
            label,
        )

    def _wallet_card_body(self, _draw, top: int, wallet, paint: bool, frame: Frame | None = None) -> int:
        y = top + 14
        if paint and frame is not None and y >= HEADER:
            frame.text(self._wallet_title(wallet), MARGIN + 16, y, size=TITLE_SIZE)
        y += TITLE_SIZE + 12
        for index, fingerprint in enumerate(wallet.fingerprints):
            if index:
                y += _WALLET_KEY_GAP
            record = self.session.fingerprints.get(fingerprint)
            nickname = "" if record is None else record.nickname
            has_seed = bool(record and any(key.has_seed for key in record.keys))
            y = self._draw_wallet_name(frame, y, nickname, has_seed, paint)
            y = self._draw_wallet_fingerprint(frame, y, fingerprint.hex(), paint)
        return y + 16

    def _draw_wallet_fingerprint(self, frame: Frame | None, y: int, fingerprint_hex: str, paint: bool) -> int:
        """Hex under the name, with the icon aligned to the start of the name text."""
        inset = MARGIN + 16
        name_text_x = inset + _WALLET_CARD_ICON + _WALLET_CARD_GAP
        icon = _WALLET_CARD_ICON
        if paint and frame is not None and y >= HEADER:
            face = font(TITLE_SIZE, mono=True)
            _left, top, _right, bottom = frame.draw.textbbox((0, 0), "Ag", font=face)
            frame.glyph(
                Icons.FINGERPRINT,
                name_text_x + icon / 2,
                y + (top + bottom) / 2,
                icon,
                MUTED,
            )
            frame.draw.text((name_text_x + icon + _WALLET_CARD_GAP, y), fingerprint_hex, font=face, fill=MUTED)
        return y + TITLE_SIZE + 8

    def _draw_wallet_name(self, frame: Frame | None, y: int, nickname: str, has_seed: bool, paint: bool) -> int:
        lines = _fingerprint_name_lines(nickname)
        size = NAME_ON_WALLET_CARD
        step = size + 8
        if paint and frame is not None:
            icon, awesome = _name_icon(has_seed)
            face = font(size)
            _left, top, _right, bottom = frame.draw.textbbox((0, 0), "Ag", font=face)
            text_mid = (top + bottom) / 2 + step * (len(lines) - 1) / 2
            inset = MARGIN + 16
            if y + text_mid >= HEADER:
                frame.glyph(icon, inset + _WALLET_CARD_ICON / 2, y + text_mid, _WALLET_CARD_ICON, MUTED, awesome=awesome)
            text_x = inset + _WALLET_CARD_ICON + _WALLET_CARD_GAP
            for index, line in enumerate(lines):
                line_y = y + index * step
                if line_y >= HEADER:
                    frame.draw.text((text_x, line_y), line, font=face, fill=MUTED)
        return y + step * max(1, len(lines))

    def _multisig(self, frame: Frame):
        candidates = sorted(
            self._multisig_candidates(),
            key=lambda fingerprint: self.session.fingerprints[fingerprint].nickname.casefold(),
        )
        if len(candidates) < 2:
            frame.text(
                "A multisig needs at least two seeds or native-segwit multisig keys.",
                MARGIN,
                HEADER + 16,
                size=TITLE_SIZE,
            )
            frame.header("Native-Segwit Multisig", "back")
            return
        y = HEADER + 16
        selected = [fingerprint for fingerprint in candidates if fingerprint in self.multisig_selected]
        count = len(selected)
        if count == 0:
            if self.open_dropdown == "multisig-m":
                self.open_dropdown = None
            label = "1 of 0 must sign"
            choices = ()
            field_enabled = False
        else:
            self.multisig_m = min(max(self.multisig_m, 1), count)
            label = f"{self.multisig_m} of {count} must sign"
            choices = tuple((str(number), f"{number} of {count} must sign") for number in range(1, count + 1))
            field_enabled = True
        field = self._dropdown_field(frame, y, "multisig-m", label, enabled=field_enabled)
        list_top = field[3] + 16
        heights = [
            self._picker_card_height(self.session.fingerprints[fingerprint], MULTISIG_NATIVE)
            for fingerprint in candidates
        ]
        content_end = list_top + sum(heights) + 12 * len(candidates)
        button = "Go to Wallet" if self._existing_multisig_index() is not None else "Create Wallet"
        button_h = frame.button_height(button)
        offset = self._scroll_offset("multisig", content_end, clearance=24 + button_h)
        visible_bottom = HEIGHT - 16 - button_h
        y = list_top - offset
        for fingerprint, row_h in zip(candidates, heights):
            record = self.session.fingerprints[fingerprint]
            clip = self._list_card_clip(frame, y, row_h, list_top, visible_bottom)
            if clip is not None:
                selected = fingerprint in self.multisig_selected
                box = (MARGIN, y, WIDTH - MARGIN, y + row_h)
                frame.draw.rounded_rectangle(box, radius=14, fill=WHITE, outline=LINE)
                frame.glyph(
                    Icons.CHECKBOX_SELECTED if selected else Icons.CHECKBOX,
                    MARGIN + 28,
                    y + row_h / 2,
                    28,
                    NAVY,
                )
                name_step = NAME_ON_MULTISIG + 8
                name_y = self._draw_picker_kind(frame, record, y + 12, MULTISIG_NATIVE)
                for line_index, line in enumerate(_fingerprint_name_lines(record.nickname)):
                    frame.text(line, MARGIN + 56, name_y + line_index * name_step, size=NAME_ON_MULTISIG)
                hex_y = name_y + name_step + NAME_ON_MULTISIG + 8
                hex_x = frame.leading_icon(
                    Icons.FINGERPRINT, MARGIN + 56, hex_y, FINGERPRINT_ON_MULTISIG, MUTED,
                )
                hex_label = "Fingerprint: "
                frame.draw.text((hex_x, hex_y), hex_label, font=font(FINGERPRINT_ON_MULTISIG), fill=MUTED)
                hex_x += int(frame.draw.textlength(hex_label, font=font(FINGERPRINT_ON_MULTISIG)))
                frame.draw.text(
                    (hex_x, hex_y), fingerprint.hex(),
                    font=font(FINGERPRINT_ON_MULTISIG, mono=True), fill=MUTED,
                )
                self._restore_list_card_clip(frame, clip)
                frame.hit(clip["hit"], f"toggle-ms-{fingerprint.hex()}", record.nickname)
            y += row_h + 12
        frame.button(HEIGHT - 16 - button_h, button, "ms-create", enabled=count > 0 and self.multisig_m <= count)
        frame.header("Native-Segwit Multisig", "back")
        if field_enabled and self.open_dropdown == "multisig-m":
            self._dropdown_menu(frame, field, "multisig-m", choices, str(self.multisig_m))

    def _singlesig(self, frame: Frame):
        any_key = self._singlesig_candidates(SINGLESIG_NATIVE) or self._singlesig_candidates(SINGLESIG_TAPROOT)
        if not any_key:
            frame.text(
                "A singlesig wallet needs a seed or a single-signature key.",
                MARGIN,
                HEADER + 16,
                size=TITLE_SIZE,
            )
            frame.header("SingleSig Key", "back")
            return
        script = "Taproot" if self.singlesig_role == SINGLESIG_TAPROOT else "Native-Segwit"
        candidates = sorted(
            self._singlesig_candidates(),
            key=lambda fingerprint: self.session.fingerprints[fingerprint].nickname.casefold(),
        )
        if self.singlesig_selected not in candidates:
            self.singlesig_selected = None
        y = HEADER + 16
        field = self._dropdown_field(frame, y, "singlesig-script", script)
        list_top = field[3] + 16
        heights = [
            self._picker_card_height(self.session.fingerprints[fingerprint], self.singlesig_role)
            for fingerprint in candidates
        ]
        content_end = list_top + sum(heights) + 12 * len(candidates)
        button = "Go to Wallet" if self._existing_singlesig_index() is not None else "Create Wallet"
        button_h = frame.button_height(button)
        offset = self._scroll_offset("singlesig", content_end, clearance=24 + button_h)
        visible_bottom = HEIGHT - 16 - button_h
        y = list_top - offset
        if not candidates:
            frame.text(f"There is no {script} key to select.", MARGIN, y, size=TITLE_SIZE)
        for fingerprint, row_h in zip(candidates, heights):
            record = self.session.fingerprints[fingerprint]
            clip = self._list_card_clip(frame, y, row_h, list_top, visible_bottom)
            if clip is not None:
                selected = fingerprint == self.singlesig_selected
                box = (MARGIN, y, WIDTH - MARGIN, y + row_h)
                frame.draw.rounded_rectangle(box, radius=14, fill=WHITE, outline=LINE)
                frame.glyph(
                    Icons.CHECKBOX_SELECTED if selected else Icons.CHECKBOX,
                    MARGIN + 28,
                    y + row_h / 2,
                    28,
                    NAVY,
                )
                name_step = NAME_ON_MULTISIG + 8
                name_y = self._draw_picker_kind(frame, record, y + 12, self.singlesig_role)
                for line_index, line in enumerate(_fingerprint_name_lines(record.nickname)):
                    frame.text(line, MARGIN + 56, name_y + line_index * name_step, size=NAME_ON_MULTISIG)
                hex_y = name_y + name_step + NAME_ON_MULTISIG + 8
                hex_x = frame.leading_icon(
                    Icons.FINGERPRINT, MARGIN + 56, hex_y, FINGERPRINT_ON_MULTISIG, MUTED,
                )
                hex_label = "Fingerprint: "
                frame.draw.text((hex_x, hex_y), hex_label, font=font(FINGERPRINT_ON_MULTISIG), fill=MUTED)
                hex_x += int(frame.draw.textlength(hex_label, font=font(FINGERPRINT_ON_MULTISIG)))
                frame.draw.text(
                    (hex_x, hex_y), fingerprint.hex(),
                    font=font(FINGERPRINT_ON_MULTISIG, mono=True), fill=MUTED,
                )
                self._restore_list_card_clip(frame, clip)
                frame.hit(clip["hit"], f"pick-ss-{fingerprint.hex()}", record.nickname)
            y += row_h + 12
        frame.button(
            HEIGHT - 16 - button_h,
            button,
            "ss-create",
            enabled=self.singlesig_selected is not None,
        )
        frame.header("SingleSig Key", "back")
        if self.open_dropdown == "singlesig-script":
            self._dropdown_menu(
                frame,
                field,
                "singlesig-script",
                (("native", "Native-Segwit"), ("taproot", "Taproot")),
                "taproot" if self.singlesig_role == SINGLESIG_TAPROOT else "native",
            )

    def _picker_kind_label(self, record, role: str) -> tuple[str, bool, list[str]]:
        if any(key.has_seed for key in record.keys):
            return Icons.KEY, False, ["Seed"]
        accounts = {
            key.account
            for key in record.keys
            if not key.has_seed and getattr(key, "role", None) == role and key.account is not None
        }
        if len(accounts) > 1:
            return Icons.EYE, True, ["External Keys", f"({len(accounts)} accounts)"]
        return Icons.EYE, True, ["External Key"]

    def _picker_card_height(self, record, role: str) -> int:
        _icon, _awesome, lines = self._picker_kind_label(record, role)
        name_step = NAME_ON_MULTISIG + 8
        kind = len(lines) * (FINGERPRINT_ON_MULTISIG + 8)
        return 12 + kind + name_step + NAME_ON_MULTISIG + 8 + FINGERPRINT_ON_MULTISIG + 14

    def _draw_picker_kind(self, frame: Frame, record, y: int, role: str) -> int:
        icon, awesome, lines = self._picker_kind_label(record, role)
        text_x = frame.leading_icon(
            icon, MARGIN + 56, y, FINGERPRINT_ON_MULTISIG, MUTED, awesome=awesome,
        )
        face = font(FINGERPRINT_ON_MULTISIG)
        for index, line in enumerate(lines):
            frame.draw.text((text_x, y + index * (FINGERPRINT_ON_MULTISIG + 8)), line, font=face, fill=MUTED)
        return y + len(lines) * (FINGERPRINT_ON_MULTISIG + 8)

    def _existing_singlesig_index(self):
        selected = self.singlesig_selected
        if selected not in self._singlesig_candidates():
            return None
        for index, wallet in enumerate(self.session.wallets):
            if wallet.role == self.singlesig_role and not wallet.multisig and selected in wallet.fingerprints:
                return index
        return None

    def _existing_multisig_index(self):
        selected = [fingerprint for fingerprint in self._multisig_candidates() if fingerprint in self.multisig_selected]
        if len(selected) < 2 or len(selected) < self.multisig_m:
            return None
        wanted = tuple(sorted(selected))
        for index, wallet in enumerate(self.session.wallets):
            if (
                wallet.multisig
                and wallet.threshold == self.multisig_m
                and tuple(sorted(wallet.fingerprints)) == wanted
            ):
                return index
        return None

    def _singlesig_candidates(self, role: str | None = None) -> list[bytes]:
        """Seeds, and single-signature external keys of this script. One row per fingerprint."""
        role = self.singlesig_role if role is None else role
        found = []
        for fingerprint, record in self.session.fingerprints.items():
            if any(key.has_seed for key in record.keys):
                found.append(fingerprint)
            elif any(getattr(key, "role", None) == role for key in record.keys):
                found.append(fingerprint)
        return found

    def _singlesig_account(self, fingerprint: bytes) -> int:
        record = self.session.fingerprints[fingerprint]
        if any(key.has_seed for key in record.keys):
            return 0
        accounts = [
            key.account
            for key in record.keys
            if getattr(key, "role", None) == self.singlesig_role and key.account is not None
        ]
        return min(accounts)

    def _create_selected_singlesig(self):
        selected = self.singlesig_selected
        if selected not in self._singlesig_candidates():
            self.set_notice("Select a key.")
            return
        role = self.singlesig_role
        existing = self._existing_singlesig_index()
        if existing is not None:
            self.set_notice("")
            self._show_wallet(existing)
            return
        account = self._singlesig_account(selected)
        kind = "tr" if role == SINGLESIG_TAPROOT else "wpkh"
        key = _public_for(self.session, selected, role, account)
        origin = format_path(list(key.path))[2:]
        text = f"{kind}([{selected.hex()}/{origin}]{key.xpub.to_string()}/<0;1>/*)"
        try:
            added = self.session.add_text(text)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.set_notice(added["message"])
        wallet = added.get("wallet")
        if wallet is not None and wallet in self.session.wallets:
            self._show_wallet(self.session.wallets.index(wallet))
            return
        self.back = ["wallets"]
        self.screen = "wallets"

    def _list_card_clip(self, frame: Frame, y: int, row_h: int, list_top: int, visible_bottom: int):
        """Keep the part of a card that sits in the list. The rest can show only partly."""
        if y + row_h <= list_top or y >= visible_bottom:
            return None
        return {
            "saved_top": frame.image.crop((0, 0, WIDTH, list_top)) if y < list_top else None,
            "saved_bottom": frame.image.crop((0, visible_bottom, WIDTH, HEIGHT)) if y + row_h > visible_bottom else None,
            "list_top": list_top,
            "visible_bottom": visible_bottom,
            "hit": (MARGIN, max(y, list_top), WIDTH - MARGIN, min(y + row_h, visible_bottom)),
        }

    def _restore_list_card_clip(self, frame: Frame, clip) -> None:
        if clip["saved_top"] is not None:
            frame.image.paste(clip["saved_top"], (0, 0))
        if clip["saved_bottom"] is not None:
            frame.image.paste(clip["saved_bottom"], (0, clip["visible_bottom"]))
        frame.draw = ImageDraw.Draw(frame.image)

    def _clamp_multisig_threshold(self):
        count = len(self._multisig_selection())
        if count == 0:
            self.open_dropdown = None
            return
        if self.multisig_m > count:
            self.multisig_m = count
        if self.multisig_m < 1:
            self.multisig_m = 1

    def _multisig_selection(self) -> list[bytes]:
        return [fingerprint for fingerprint in self._multisig_candidates() if fingerprint in self.multisig_selected]

    def _multisig_candidates(self) -> list[bytes]:
        found = []
        for fingerprint, record in self.session.fingerprints.items():
            if any(key.has_seed for key in record.keys):
                found.append(fingerprint)
            elif any(getattr(key, "role", None) == MULTISIG_NATIVE for key in record.keys):
                found.append(fingerprint)
        return found

    def _multisig_account(self, fingerprint: bytes) -> int:
        record = self.session.fingerprints[fingerprint]
        if any(key.has_seed for key in record.keys):
            return 0
        accounts = [
            key.account
            for key in record.keys
            if getattr(key, "role", None) == MULTISIG_NATIVE and key.account is not None
        ]
        return min(accounts)

    def _first_receive_pubkey(self, fingerprint: bytes) -> bytes:
        """Compressed pubkey at /0/0, the order Sparrow uses for the receive descriptor."""
        account = self._multisig_account(fingerprint)
        key = _public_for(self.session, fingerprint, MULTISIG_NATIVE, account)
        return key.xpub.derive("m/0/0").key.sec()

    def _create_selected_multisig(self):
        candidates = self._multisig_candidates()
        selected = [fingerprint for fingerprint in candidates if fingerprint in self.multisig_selected]
        if len(selected) < 2:
            self.set_notice("A multisig needs at least two keys.")
            return
        if len(selected) < self.multisig_m:
            self.set_notice(f"Select at least {self.multisig_m} keys.")
            return
        existing = self._existing_multisig_index()
        if existing is not None:
            self.set_notice("")
            self._show_wallet(existing)
            return
        selected.sort(key=self._first_receive_pubkey)
        parts = []
        for fingerprint in selected:
            account = self._multisig_account(fingerprint)
            key = _public_for(self.session, fingerprint, MULTISIG_NATIVE, account)
            origin = format_path(list(key.path))[2:]
            parts.append(f"[{fingerprint.hex()}/{origin}]{key.xpub.to_string()}/<0;1>/*")
        body = f"wsh(sortedmulti({self.multisig_m},{','.join(parts)}))"
        try:
            added = self.session.add_text(body)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.set_notice(added["message"])
        wallet = added.get("wallet")
        if wallet is not None:
            self.wallet_index = self.session.wallets.index(wallet)
            self.scroll["wallet"] = 0
            self.back = ["wallets"]
            self.screen = "wallet"
            self._remember_wallet_accounts()
            return
        self.back = []
        self.screen = "wallets"

    def _wallet(self, frame: Frame):
        wallet = self.session.wallets[self.wallet_index] if self.wallet_index < len(self.session.wallets) else None
        if wallet is None:
            title = "Wallet"
        elif wallet.multisig:
            title = "MultiSig Wallet"
        else:
            title = "SingleSig Wallet"
        if wallet is None:
            frame.header(title, "back")
            frame.text("This wallet is no longer loaded.", MARGIN, 140)
            return
        flow_end = self._wallet_flow(frame, wallet, paint=False)[0]
        delete_h = frame.button_height("Delete Wallet")
        clearance = 24
        if self.notice:
            _face, _lines, _line_h, _pad, notice_top, _height = self._notice_layout(frame)
            clearance = max(clearance, HEIGHT - notice_top + 12)
        delete_y = HEIGHT - clearance - delete_h
        if flow_end + 16 <= delete_y:
            self.scroll["wallet"] = 0
            self.scroll_max["wallet"] = 0
            _end, open_field, open_fp = self._wallet_flow(frame, wallet, paint=True)
            frame.button(delete_y, "Delete Wallet", "delete-wallet", color=RED)
        else:
            offset = self._scroll_offset("wallet", flow_end + 16 + delete_h, clearance=clearance)
            _end, open_field, open_fp = self._wallet_flow(frame, wallet, paint=True, offset=offset)
            frame.button(flow_end + 16 - offset, "Delete Wallet", "delete-wallet", color=RED)
        frame.header(title, "back")
        if open_field is not None and open_fp is not None:
            options = self.session.account_options(open_fp, wallet.role) or []
            self._dropdown_menu(
                frame,
                open_field,
                f"acct-{open_fp.hex()}",
                tuple((str(account), _account_label(account)) for account in options),
                str(wallet.accounts[open_fp]),
            )

    def _wallet_flow(self, frame: Frame, wallet, paint: bool, offset: int = 0):
        """Lay out the wallet under the title. Returns the unshifted y, and any open account menu."""
        y = HEADER + 16
        kind = f"Type: {self._wallet_kind_line(wallet)}"
        if paint:
            frame.text(kind, MARGIN, y - offset, size=TITLE_SIZE)
        y += self._text_height(frame, kind, TITLE_SIZE) + 8
        open_field = None
        open_fp = None
        for index, fingerprint in enumerate(wallet.fingerprints):
            if index:
                y += 16
            record = self.session.fingerprints[fingerprint]
            has_seed = any(item.has_seed for item in record.keys)
            glyph, awesome = _name_icon(has_seed)
            y = _draw_name_block(
                frame, y, _fingerprint_name_lines(record.nickname), NAME_ON_WALLET, glyph, awesome, _DETAIL_ICON, paint, offset,
            )
            if paint and y - offset >= HEADER:
                frame.fingerprint_line(
                    y - offset, fingerprint.hex(), text_size=TITLE_SIZE, icon_size=_DETAIL_ICON,
                )
            y += _DETAIL_ICON + 8
            options = self.session.account_options(fingerprint, wallet.role)
            if options is not None and len(options) <= 1:
                account = wallet.accounts[fingerprint]
                label = f"Account: {_account_label(account)}"
                if paint:
                    frame.text(label, MARGIN, y - offset, size=TITLE_SIZE)
                y += self._text_height(frame, label, TITLE_SIZE) + 8
                continue
            if paint:
                frame.text("Account", MARGIN, y - offset, size=TITLE_SIZE, fill=MUTED)
            y += self._text_height(frame, "Account", TITLE_SIZE)
            if options is None:
                account = wallet.accounts[fingerprint]
                side = 64
                gap = 12
                top = y - offset
                if paint:
                    minus = (MARGIN, top, MARGIN + side, top + 64)
                    plus = (WIDTH - MARGIN - side, top, WIDTH - MARGIN, top + 64)
                    self._brightness_button(
                        frame, minus, "-", account > 0, f"account-dec-{fingerprint.hex()}"
                    )
                    self._brightness_button(
                        frame,
                        plus,
                        "+",
                        account < 0x7FFFFFFF,
                        f"account-inc-{fingerprint.hex()}",
                    )
                    box = self._account_textbox(
                        frame,
                        top,
                        str(account),
                        left=MARGIN + side + gap,
                        right=WIDTH - MARGIN - side - gap,
                    )
                    frame.hit(box, f"account-edit-{fingerprint.hex()}", "Account")
                y += 64 + 16
            else:
                name = f"acct-{fingerprint.hex()}"
                if paint:
                    field = self._dropdown_field(
                        frame, y - offset, name, _account_label(wallet.accounts[fingerprint])
                    )
                    if self.open_dropdown == name:
                        open_field = field
                        open_fp = fingerprint
                    y += field[3] - (y - offset) + 16
                else:
                    y += 64 + 16
        y = self._flow_button(frame, y, "Addresses", "addresses", paint, offset)
        y = self._flow_button(frame, y, "Show Descriptor", "show-descriptor", paint, offset)
        y = self._flow_button(frame, y, "Export to SD Card", "export-wallet", paint, offset)
        return y, open_field, open_fp

    def _step_account(self, fingerprint: bytes, delta: int):
        if self.wallet_index >= len(self.session.wallets):
            return
        wallet = self.session.wallets[self.wallet_index]
        if fingerprint not in wallet.accounts:
            return
        account = wallet.accounts[fingerprint] + delta
        if account < 0 or account > 0x7FFFFFFF:
            return
        try:
            self.session.set_account(self.wallet_index, fingerprint, account)
        except SessionError as exc:
            self.set_notice(str(exc))

    def _account_textbox(self, frame: Frame, y: int, value: str, outline=LINE, left: int = MARGIN, right: int | None = None):
        height = 64
        box = (left, y, WIDTH - MARGIN if right is None else right, y + height)
        frame.draw.rounded_rectangle(box, radius=14, fill=WHITE, outline=outline, width=2)
        face = font(TITLE_SIZE, mono=True)
        _left, top, _right, bottom = frame.draw.textbbox((0, 0), value or "0", font=face)
        text_y = y + (height - (bottom - top)) / 2 - top
        frame.draw.text((box[0] + 20, text_y), value, font=face, fill=INK)
        return box

    def _edit_account(self, fingerprint: bytes):
        if self.wallet_index >= len(self.session.wallets):
            return
        wallet = self.session.wallets[self.wallet_index]
        if fingerprint not in wallet.fingerprints:
            return
        if self.session.account_options(fingerprint, wallet.role) is not None:
            return
        self.account_fp = fingerprint
        self.account_text = str(wallet.accounts[fingerprint])
        self.account_for = "wallet"
        self.go("account")

    def _type_account(self, key: str):
        if key == "backspace":
            self.account_text = self.account_text[:-1]
            return
        if not key.isdigit() or len(self.account_text) >= 10:
            return
        self.account_text = key if self.account_text == "0" else self.account_text + key

    def _save_account(self):
        if self.account_fp is None:
            return
        if not self.account_text.isdigit():
            self.set_notice("Enter an account index.")
            return
        account = int(self.account_text)
        if self.account_for == "derive":
            if account >= 0x80000000:
                self.set_notice("The account index is too large.")
                return
            self.derive_account = account
            self.back_one()
            return
        try:
            self.session.set_account(self.wallet_index, self.account_fp, account)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.back_one()

    def _pick_account(self, fingerprint: bytes, account: int):
        try:
            self.session.set_account(self.wallet_index, fingerprint, account)
        except SessionError as exc:
            self.set_notice(str(exc))

    def _account(self, frame: Frame):
        frame.header("Account", "back")
        record = None if self.account_fp is None else self.session.fingerprints.get(self.account_fp)
        if record is None:
            frame.text("This key is no longer loaded.", MARGIN, 140)
            return
        y = frame.text("Account", MARGIN, HEADER + 16, size=TITLE_SIZE, fill=MUTED)
        self._account_textbox(frame, y, self.account_text, outline=BLUE)
        save_y = HEIGHT - 100
        if self.notice:
            _face, _lines, _line_h, _pad, notice_top, _height = self._notice_layout(frame)
            save_y = min(save_y, notice_top - 12 - frame.button_height("Use This Account"))
        self._account_pad(frame, save_y)
        frame.button(save_y, "Use This Account", "account-save")

    def _account_pad(self, frame: Frame, save_y: int):
        key_h = 64
        gap = 8
        width = (WIDTH - 2 * MARGIN - 2 * gap) // 3
        y = save_y - 16 - (4 * key_h + 3 * gap)
        for row in ("123", "456", "789"):
            for index, digit in enumerate(row):
                x = MARGIN + index * (width + gap)
                self._account_key(frame, (x, y, x + width, y + key_h), digit, digit)
            y += key_h + gap
        self._account_key(frame, (MARGIN, y, MARGIN + width, y + key_h), "del", "backspace")
        x = MARGIN + width + gap
        self._account_key(frame, (x, y, x + width, y + key_h), "0", "0")

    def _account_key(self, frame: Frame, box, label: str, key: str):
        fill = BLUE if key == "backspace" else WHITE
        text = WHITE if key == "backspace" else INK
        outline = None if key == "backspace" else LINE
        frame.draw.rounded_rectangle(box, radius=12, fill=fill, outline=outline, width=2)
        face = font(TITLE_SIZE)
        text_width = frame.draw.textlength(label, font=face)
        _left, top, _right, bottom = frame.draw.textbbox((0, 0), label, font=face)
        text_x = box[0] + (box[2] - box[0] - text_width) / 2
        text_y = box[1] + (box[3] - box[1] - (bottom - top)) / 2 - top
        frame.draw.text((text_x, text_y), label, font=face, fill=text)
        frame.hit(box, f"account-key-{key}", label)

    def _addresses(self, frame: Frame):
        frame.header("Addresses", "back")
        if self.wallet_index >= len(self.session.wallets):
            return
        addresses = self.session.addresses(self.wallet_index, 0, 0, 8)
        y = HEADER + 16
        for address in addresses:
            y += self._text_height(frame, address, TITLE_SIZE, mono=True)
        offset = self._scroll_offset("addresses", y, clearance=16)
        y = HEADER + 16 - offset
        for address in addresses:
            y = frame.text(address, MARGIN, y, size=TITLE_SIZE, mono=True)
        frame.header("Addresses", "back")

    def _settings(self, frame: Frame):
        frame.header("Settings", "menu")
        y = frame.text("Network:", MARGIN, HEADER + 24, size=TITLE_SIZE)
        names = {"main": "mainnet", "test": "testnet", "regtest": "regtest"}
        field = self._dropdown_field(frame, y + 8, "network", names[self.session.network])
        frame.text(
            "Switching network removes xpubs and wallets. Seeds stay in memory.",
            MARGIN,
            field[3] + 16,
            size=TITLE_SIZE,
        )
        if self.open_dropdown == "network":
            self._dropdown_menu(
                frame,
                field,
                "network",
                (("main", "mainnet"), ("test", "testnet"), ("regtest", "regtest")),
                self.session.network,
            )

    def _about(self, frame: Frame):
        frame.header("About", "menu")
        mark = logo(WIDTH - 80, 220)
        frame.image.paste(mark, ((WIDTH - mark.width) // 2, HEADER + 30), mark)
        y = frame.text(f"BigSigner {__version__}", MARGIN, HEADER + 280, size=TITLE_SIZE)
        y = frame.text("Fork of SeedSigner", MARGIN, y + 8, size=TITLE_SIZE, fill=MUTED)
        y = frame.text("Portrait 480×800 HDMI touchscreen.", MARGIN, y + 8, size=TITLE_SIZE)
        frame.button(y + 24, "Licenses", "open-licenses")

    def _licenses(self, frame: Frame):
        row_h = 16 + TITLE_SIZE + 8 + TITLE_SIZE + 16
        gap = 12
        top = HEADER + 16
        content_end = top + len(NOTICES) * (row_h + gap)
        offset = self._scroll_offset("licenses", content_end, clearance=16)
        y = top - offset
        name_face = font(TITLE_SIZE)
        kind_face = font(TITLE_SIZE)
        for index, notice in enumerate(NOTICES):
            if y + row_h > HEADER and y < HEIGHT:
                box = (MARGIN, y, WIDTH - MARGIN, y + row_h)
                frame.draw.rounded_rectangle(box, radius=12, fill=WHITE, outline=LINE)
                frame.draw.text((MARGIN + 16, y + 16), notice.name, font=name_face, fill=INK)
                frame.draw.text((MARGIN + 16, y + 16 + TITLE_SIZE + 8), notice.license_name, font=kind_face, fill=MUTED)
                frame.hit(box, f"open-license-{index}", notice.name)
            y += row_h + gap
        frame.header("Licenses", "back")

    def _license(self, frame: Frame):
        notice = NOTICES[self.license_index]
        face = font(TITLE_SIZE)
        lines: list[str] = []
        for paragraph in notice.text.split("\n"):
            if paragraph.strip() == "":
                lines.append("")
            else:
                lines.extend(wrap(frame.draw, paragraph, face, WIDTH - 2 * MARGIN))
        line_h = TITLE_SIZE + 10
        name_face = font(TITLE_SIZE)
        name_lines = wrap(frame.draw, notice.name, name_face, WIDTH - 2 * MARGIN)
        kind_h = TITLE_SIZE + 12
        name_h = line_h * len(name_lines)
        body_top = HEADER + 16 + name_h + kind_h
        content_end = body_top + line_h * len(lines)
        offset = self._scroll_offset("license", content_end, clearance=16)
        y = HEADER + 16 - offset
        for line in name_lines:
            if HEADER < y + line_h and y < HEIGHT:
                frame.draw.text((MARGIN, y), line, font=name_face, fill=INK)
            y += line_h
        if HEADER < y + kind_h and y < HEIGHT:
            frame.draw.text((MARGIN, y), notice.license_name, font=font(TITLE_SIZE), fill=MUTED)
        y += kind_h
        for line in lines:
            if HEADER < y + line_h and y < HEIGHT:
                frame.draw.text((MARGIN, y), line, font=face, fill=INK)
            y += line_h
        frame.header("License", "back")

    def _editor(self, frame: Frame):
        frame.header("Enter text", "back")
        frame.draw.rounded_rectangle((MARGIN, HEADER + 20, WIDTH - MARGIN, HEADER + 220), radius=12, fill=WHITE, outline=LINE)
        frame.text(self.draft or "Descriptor, key expression, or seed words", MARGIN + 12, HEADER + 36, size=TITLE_SIZE, mono=True)

    def _seed(self, frame: Frame):
        if len(self.seed_words) < self.seed_length:
            self.keyboard_top = self._seed_keyboard_top()
        if self._patch_seed_keyboard(frame):
            return
        entered = len(self.seed_words)
        complete = entered >= self.seed_length and entered > 0
        title = "Seed words" if complete else f"Word {entered + 1} of {self.seed_length}"
        frame.header(title, "back")
        field = self._dropdown_field(frame, HEADER + 12, "seed-length", f"{self.seed_length} words")
        content_top = field[3] + 12
        if complete:
            self._seed_entered_grid(frame, content_top, HEIGHT - 120)
            frame.button(HEIGHT - 100, "Continue", "seed-continue")
        else:
            matches = self._seed_matches()
            show_words = 0 < len(matches) <= 6
            keyboard_top = self._seed_keyboard_top()
            lower_top = keyboard_top
            if show_words:
                lower_top = self._seed_word_grid(frame, matches)
            else:
                if self.word_prefix and self.word_prefix in matches:
                    lower_top = keyboard_top - 76
                    frame.button(lower_top, self.word_prefix, f"pick-{self.word_prefix}")
                self._seed_keyboard(frame, self._enabled_letters())
            self._seed_transcript(frame, content_top, lower_top - 8, matches)
            self._remember_seed_keyboard(frame, show_words, matches)
        if self.open_dropdown == "seed-length":
            self._dropdown_menu(
                frame,
                field,
                "seed-length",
                (("12", "12 words"), ("18", "18 words"), ("24", "24 words")),
                str(self.seed_length),
            )

    def _seed_entered_grid(self, frame: Frame, top: int, bottom: int) -> int:
        """Draw the accepted words in one column. Returns the y below the grid."""
        return self._draw_indexed_grid(
            frame, self.seed_words, top, bottom, scroll=True,
            columns=SEED_CARD_COLUMNS, gap=SEED_CARD_GAP, inset=MARGIN, pad_x=SEED_CARD_PAD_X,
        )

    def _draw_indexed_grid(
        self,
        frame: Frame,
        words: list[str],
        top: int,
        bottom: int,
        scroll: bool = False,
        columns: int = 3,
        gap: int = 4,
        inset: int = 6,
        pad_x: int = 4,
    ) -> int:
        if not words:
            self.seed_grid_max = 0
            self.seed_grid_box = None
            return top
        pad_y = 14
        cell_w = (WIDTH - 2 * inset - gap * (columns - 1)) // columns
        size = _grid_font_size(frame.draw, cell_w - 2 * pad_x, SEED_CARD_FONT)
        face = font(size, mono=True)
        cell_h = size + 2 * pad_y
        rows = (len(words) + columns - 1) // columns
        content_h = rows * cell_h + (rows - 1) * gap
        viewport = bottom - top
        if not scroll or content_h <= viewport:
            self.seed_grid_max = 0
            self.seed_grid_box = None
            shown = list(enumerate(words, start=1))
            if not scroll and content_h > viewport:
                capacity = max(columns, ((max(viewport, 0) + gap) // (cell_h + gap)) * columns)
                start = max(0, len(words) - capacity)
                shown = list(enumerate(words[start:], start=start + 1))
            y = self._paint_word_cells(
                frame.draw, shown, top, 0, inset, cell_w, cell_h, gap, pad_x, face, columns,
            )
            return y + 8
        max_scroll = content_h - viewport
        self.seed_grid_max = max_scroll
        if self.seed_grid_stick:
            self.seed_grid_scroll = max_scroll
        else:
            self.seed_grid_scroll = max(0, min(self.seed_grid_scroll, max_scroll))
        self.seed_grid_box = (0, top, WIDTH, bottom)
        layer = Image.new("RGB", (WIDTH, viewport), PAPER)
        shown = list(enumerate(words, start=1))
        self._paint_word_cells(
            ImageDraw.Draw(layer),
            shown,
            0,
            self.seed_grid_scroll,
            inset,
            cell_w,
            cell_h,
            gap,
            pad_x,
            face,
            columns,
        )
        frame.image.paste(layer, (0, top))
        return bottom

    def _paint_word_cells(
        self, draw, shown, origin: int, scroll: int, inset: int, cell_w: int, cell_h: int, gap: int, pad_x: int, face, columns: int,
        clip_top: int | None = None, clip_bottom: int | None = None,
    ):
        y = origin
        for offset, (index, word) in enumerate(shown):
            column = offset % columns
            if column == 0 and offset:
                y += cell_h + gap
            row_y = y - scroll
            if clip_top is not None and row_y < clip_top:
                continue
            if clip_bottom is not None and row_y >= clip_bottom:
                continue
            x = inset + column * (cell_w + gap)
            box = (x, row_y, x + cell_w, row_y + cell_h)
            draw.rounded_rectangle(box, radius=10, fill=WHITE, outline=LINE)
            label = f"{index}. {word}"
            _left, text_top, _right, text_bottom = draw.textbbox((0, 0), label, font=face)
            text_y = row_y + (cell_h - (text_bottom - text_top)) / 2 - text_top
            draw.text((x + pad_x, text_y), label, font=face, fill=INK)
        return y + cell_h

    def _set_seed_length(self, length: int):
        """Keep entered words. A shorter seed drops its last word so the checksum can be retyped."""
        if length < self.seed_length:
            kept = self.seed_words[: length - 1]
            if len(kept) < len(self.seed_words):
                self.word_prefix = ""
                self.word_cursor = 0
            self.seed_words = kept
            self.seed_grid_stick = True
        self.seed_length = length

    def _seed_transcript(self, frame: Frame, top: int, bottom: int, matches: list[str]):
        prefix = self.word_prefix
        input_h = 72
        note_face = font(TITLE_SIZE)
        note_h = TITLE_SIZE + 8
        mismatch = "No BIP39 word matches this." if prefix and not matches else ""
        checksum = (
            "The next word has to match the checksum"
            if len(self.seed_words) + 1 == self.seed_length
            else ""
        )
        mismatch_lines = wrap(frame.draw, mismatch, note_face, WIDTH - 2 * MARGIN) if mismatch else []
        checksum_lines = wrap(frame.draw, checksum, note_face, WIDTH - 2 * MARGIN) if checksum else []
        mismatch_h = note_h * len(mismatch_lines)
        checksum_h = note_h * len(checksum_lines)
        grid_bottom = bottom - input_h - mismatch_h - checksum_h - 8
        y = self._seed_entered_grid(frame, top, grid_bottom)
        for line in mismatch_lines:
            frame.draw.text((MARGIN, y), line, font=note_face, fill=MUTED)
            y += note_h
        box = (MARGIN, y, WIDTH - MARGIN, y + input_h)
        self._seed_field_box = box
        self._paint_seed_field(frame, box)
        note_y = box[3] + 8
        for line in checksum_lines:
            frame.draw.text((MARGIN, note_y), line, font=note_face, fill=MUTED)
            note_y += note_h

    def _paint_seed_field(self, frame: Frame, box):
        prefix = self.word_prefix
        frame.draw.rounded_rectangle(box, radius=12, fill=WHITE, outline=LINE)
        shown = prefix if prefix else "Type a seed word"
        text_x = box[0] + 16
        field_face = font(TITLE_SIZE)
        _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), shown, font=field_face)
        text_y = box[1] + (72 - (text_bottom - text_top)) / 2 - text_top
        frame.draw.text((text_x, text_y), shown, font=field_face, fill=INK if prefix else MUTED)
        if prefix:
            caret_x = text_x + frame.draw.textlength(prefix[: self.word_cursor], font=field_face)
            frame.draw.line((caret_x, box[1] + 14, caret_x, box[3] - 14), fill=BLUE, width=2)
            self._seed_cursor_hits(frame, box, prefix)
        else:
            frame.hit(box, "cursor-0", "cursor-0")

    def _letter_sprite(self, letter: str, enabled: bool) -> Image.Image:
        key = (letter, enabled)
        sprite = self._letter_sprites.get(key)
        if sprite is not None:
            return sprite
        width, height = 43, 65
        sprite = Image.new("RGB", (width, height), PAPER)
        draw = ImageDraw.Draw(sprite)
        draw.rounded_rectangle((0, 0, 42, 64), radius=10, fill=WHITE if enabled else (228, 230, 234), outline=LINE)
        face = font(TITLE_SIZE)
        text_width = draw.textlength(letter, font=face)
        _left, text_top, _right, text_bottom = draw.textbbox((0, 0), letter, font=face)
        text_y = (64 - (text_bottom - text_top)) / 2 - text_top
        draw.text(((42 - text_width) / 2, text_y), letter, font=face, fill=INK if enabled else MUTED)
        self._letter_sprites[key] = sprite
        return sprite

    def _seed_shell(self, show_words: bool, matches: list[str]):
        has_pick = bool(self.word_prefix) and self.word_prefix in matches
        return (tuple(self.seed_words), self.seed_length, self.seed_grid_scroll, show_words, has_pick)

    def _remember_seed_keyboard(self, frame: Frame, show_words: bool, matches: list[str]):
        """Keep this picture so the next letter can change keys instead of redrawing it."""
        if show_words or self.open_dropdown or self.notice or self.menu or self.confirm:
            self._seed_picture = None
            return
        self._seed_picture = frame.image
        self._seed_shell_key = self._seed_shell(False, matches)
        self._seed_enabled = self._enabled_letters()
        self._seed_fixed_hits = [
            hit for hit in frame.hits
            if not (hit["action"].startswith("key-") and len(hit["action"]) == 5)
            and not hit["action"].startswith("cursor-")
        ]

    def _patch_seed_keyboard(self, frame: Frame) -> bool:
        """Paste changed keys and the word field onto the previous picture."""
        if self._seed_picture is None or self._seed_field_box is None or not self._seed_key_boxes:
            return False
        if self.menu or self.confirm or self.notice or self.open_dropdown:
            return False
        if len(self.seed_words) >= self.seed_length:
            return False
        matches = self._seed_matches()
        if 0 < len(matches) <= 6:
            return False
        if self._seed_shell_key != self._seed_shell(False, matches):
            return False
        enabled = self._enabled_letters()
        image = self._seed_picture
        top = HEIGHT
        bottom = 0
        for letter, box in self._seed_key_boxes.items():
            if (letter in enabled) == (letter in self._seed_enabled):
                continue
            image.paste(self._letter_sprite(letter, letter in enabled), (box[0], box[1]))
            top = min(top, box[1])
            bottom = max(bottom, box[1] + 65)
        field = self._seed_field_box
        frame.image = image
        frame.draw = ImageDraw.Draw(image)
        frame.hits = list(self._seed_fixed_hits)
        self._paint_seed_field(frame, field)
        for letter, box in self._seed_key_boxes.items():
            if letter in enabled:
                frame.hit(
                    self._key_hit(
                        box,
                        bottom=letter in self._seed_bottom_letters,
                        left=letter in self._seed_left_letters,
                        right=letter in self._seed_right_letters,
                    ),
                    f"key-{letter}",
                    letter,
                )
        self._seed_enabled = enabled
        top = min(top, field[1])
        bottom = max(bottom, field[3])
        self.dirty = (max(0, top), min(HEIGHT, bottom))
        return True

    def _seed_cursor_hits(self, frame: Frame, box, prefix: str):
        face = font(TITLE_SIZE)
        text_x = box[0] + 16
        widths = [frame.draw.textlength(prefix[:i], font=face) for i in range(len(prefix) + 1)]
        edges = [box[0]]
        for index in range(len(prefix)):
            edges.append(text_x + (widths[index] + widths[index + 1]) / 2)
        edges.append(box[2])
        for index in range(len(prefix) + 1):
            frame.hit((edges[index], box[1], edges[index + 1], box[3]), f"cursor-{index}", f"cursor-{index}")

    def _seed_word_grid(self, frame: Frame, matches: list[str]) -> int:
        gap = 12
        height = 68
        columns = 2
        width = (WIDTH - 2 * MARGIN - gap) // columns
        rows = (len(matches) + columns - 1) // columns
        back_top = self._seed_keyboard_top() + 2 * (64 + 6)
        grid_bottom = back_top - 12
        grid_top = grid_bottom - rows * height - (rows - 1) * gap
        for index, word in enumerate(matches):
            column = index % columns
            row = index // columns
            x = MARGIN + column * (width + gap)
            y = grid_top + row * (height + gap)
            box = (x, y, x + width, y + height)
            frame.draw.rounded_rectangle(box, radius=14, fill=BLUE)
            face = font(TITLE_SIZE)
            text_width = frame.draw.textlength(word, font=face)
            _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), word, font=face)
            text_y = y + (height - (text_bottom - text_top)) / 2 - text_top
            frame.draw.text((x + (width - text_width) / 2, text_y), word, font=face, fill=WHITE)
            frame.hit(box, f"pick-{word}", word)
        self._seed_backspace(frame, (WIDTH - MARGIN - 88, back_top, WIDTH - MARGIN, back_top + 64), to_edge=True)
        return grid_top

    def _edge_key_hit(self, box):
        """The bottom row's target includes the margin below it and the gap above it.

        On this panel a press near the bezel is reported higher than the finger,
        and the glass below the last key is still that key.
        """
        return (box[0] - 3, box[1] - 6, box[2] + 3, HEIGHT)

    def _key_hit(self, box, bottom=False, left=False, right=False):
        """Include the bezel beside a key that sits at the edge of its row.

        A press on the left side of a is reported a few pixels left of the key.
        """
        hit = self._edge_key_hit(box) if bottom else box
        if left:
            hit = (0, hit[1], hit[2], hit[3])
        if right:
            hit = (hit[0], hit[1], WIDTH, hit[3])
        return hit

    def _seed_keyboard(self, frame: Frame, enabled: set[str]):
        rows = ("qwertyuiop", "asdfghjkl", "zxcvbnm")
        key_w, key_h, gap = 42, 64, 6
        y = self._seed_keyboard_top()
        self._seed_key_boxes = {}
        self._seed_bottom_letters = set()
        self._seed_left_letters = set()
        self._seed_right_letters = set()
        for letter in "abcdefghijklmnopqrstuvwxyz":
            self._letter_sprite(letter, True)
            self._letter_sprite(letter, False)
        for row_index, letters in enumerate(rows):
            extra = row_index == len(rows) - 1
            row_w = key_w * len(letters) + gap * (len(letters) - 1)
            if extra:
                row_w += gap + 72
            x = int((WIDTH - row_w) / 2)
            for index, letter in enumerate(letters):
                box = (x, y, x + key_w, y + key_h)
                frame.image.paste(self._letter_sprite(letter, letter in enabled), (x, y))
                self._seed_key_boxes[letter] = box
                left = index == 0
                right = index == len(letters) - 1 and not extra
                if left:
                    self._seed_left_letters.add(letter)
                if right:
                    self._seed_right_letters.add(letter)
                if letter in enabled:
                    frame.hit(self._key_hit(box, bottom=extra, left=left, right=right), f"key-{letter}", letter)
                if extra:
                    self._seed_bottom_letters.add(letter)
                x += key_w + gap
            if extra:
                self._seed_backspace(frame, (x, y, x + 72, y + key_h), to_edge=True)
            y += key_h + gap

    def _seed_backspace(self, frame: Frame, box, to_edge: bool = False):
        frame.draw.rounded_rectangle(box, radius=10, fill=BLUE)
        glyph = "del"
        face = font(TITLE_SIZE)
        left, top, right, bottom = frame.draw.textbbox((0, 0), glyph, font=face)
        cx = (box[0] + box[2]) / 2
        cy = (box[1] + box[3]) / 2
        frame.draw.text((cx - (right - left) / 2 - left, cy - (bottom - top) / 2 - top), glyph, font=face, fill=WHITE)
        frame.hit(self._key_hit(box, bottom=to_edge, right=to_edge), "key-backspace", "backspace")

    def _seed_keyboard_top(self) -> int:
        # The last row stays clear of the bezel. Its touch target still reaches the edge.
        return HEIGHT - 64 - (3 * 64 + 2 * 6)

    def _seed_choices(self) -> list[str]:
        """Words allowed for the word being typed.

        The last word's checksum is decided by the words already entered. That list is
        built once. Checking it again for every letter, through a linear dictionary
        search, is what made each key on this screen wait.
        """
        final = len(self.seed_words) + 1 == self.seed_length and len(self.seed_words) > 0
        key = (tuple(self.seed_words), self.seed_length) if final else None
        if key == self._seed_choice_key:
            return self._seed_choice_words
        if key is None:
            choices = WORDLIST
        else:
            stem = [_WORD_INDEX[word] for word in self.seed_words]
            choices = [word for word in WORDLIST if _phrase_checksum_ok(stem + [_WORD_INDEX[word]])]
        self._seed_choice_key = key
        self._seed_choice_words = choices
        return choices

    def _seed_matches(self, prefix: str | None = None) -> list[str]:
        prefix = self.word_prefix if prefix is None else prefix
        choices = self._seed_choices()
        if choices is WORDLIST:
            start, end = _prefix_bounds(prefix)
            return WORDLIST[start:end]
        return [word for word in choices if word.startswith(prefix)]

    def _enabled_letters(self) -> set[str]:
        head = self.word_prefix[: self.word_cursor]
        tail = self.word_prefix[self.word_cursor :]
        start_at = len(head) + 1
        choices = self._seed_choices()
        if choices is WORDLIST:
            words = WORDLIST[slice(*_prefix_bounds(head))]
        else:
            words = choices
        enabled = set()
        for word in words:
            if len(word) < start_at + len(tail) or not word.startswith(head):
                continue
            if word[start_at : start_at + len(tail)] == tail:
                enabled.add(word[len(head)])
        return enabled

    def _seed_key(self, key: str):
        if key == "backspace":
            if self.word_cursor > 0:
                self.word_prefix = self.word_prefix[: self.word_cursor - 1] + self.word_prefix[self.word_cursor :]
                self.word_cursor -= 1
            elif self.seed_words:
                self.seed_words.pop()
            return
        if key not in self._enabled_letters():
            return
        self.word_prefix = self.word_prefix[: self.word_cursor] + key + self.word_prefix[self.word_cursor :]
        self.word_cursor += 1

    def _passphrase_ask(self, frame: Frame):
        frame.header("Passphrase", "back")
        y = frame.text(
            "A passphrase is optional. It behaves like a 25th seed word, but it should contain random letters and digits, not a word picked from the dictionary. A different passphrase creates a different key, even if the first 12/24 seed words are the same.",
            MARGIN,
            HEADER + 24,
            size=TITLE_SIZE,
        )
        y = frame.button(y + 20, "No Passphrase", "passphrase-no")
        frame.button(y, "Enter a Passphrase", "passphrase-yes")

    def _passphrase_view(self, frame: Frame):
        record = self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys or not record.keys[0].passphrase:
            frame.header("Passphrase", "back")
            frame.text("No passphrase is used.", MARGIN, HEADER + 24, size=TITLE_SIZE, fill=MUTED)
            return
        phrase = record.keys[0].passphrase
        lines = wrap(frame.draw, phrase, font(TITLE_SIZE, mono=True), WIDTH - 2 * MARGIN)
        end = HEADER + 32 + (TITLE_SIZE + 8) * len(lines)
        offset = self._scroll_offset("passphrase-view", end, clearance=16)
        frame.text(phrase, MARGIN, HEADER + 32 - offset, size=TITLE_SIZE, fill=MUTED, mono=True)
        frame.header("Passphrase", "back")

    def _passphrase(self, frame: Frame):
        if self._patch_passphrase(frame):
            return
        frame.header("Passphrase", "back")
        warnings = _passphrase_warnings(self.passphrase_text)
        y = HEADER + 16
        box = (MARGIN, y, WIDTH - MARGIN, y + 72)
        self._paint_passphrase_field(frame, box)
        y = box[3] + (8 if warnings else 0)
        for warning in warnings:
            y = frame.text(warning, MARGIN, y, size=TITLE_SIZE, fill=RED)
        frame.button(y + 12, "Save Passphrase", "passphrase-save")
        self._passphrase_keyboard(frame)
        self._remember_passphrase(frame, warnings, box)

    def _passphrase_shell(self, warnings):
        return (self.passphrase_mode, tuple(warnings))

    def _remember_passphrase(self, frame: Frame, warnings, box):
        """Keep this picture so the next letter changes the field, not the keys."""
        if self.menu or self.notice or self.confirm:
            self._pass_picture = None
            return
        self._pass_picture = frame.image
        self._pass_field_box = box
        self._pass_shell = self._passphrase_shell(warnings)
        self._pass_fixed_hits = [hit for hit in frame.hits if not hit["action"].startswith("passcur-")]

    def _patch_passphrase(self, frame: Frame) -> bool:
        """Paste the passphrase text onto the previous picture."""
        if self._pass_picture is None or self._pass_field_box is None:
            return False
        if self.menu or self.notice or self.confirm:
            return False
        warnings = _passphrase_warnings(self.passphrase_text)
        if self._pass_shell != self._passphrase_shell(warnings):
            return False
        image = self._pass_picture
        frame.image = image
        frame.draw = ImageDraw.Draw(image)
        frame.hits = list(self._pass_fixed_hits)
        self._paint_passphrase_field(frame, self._pass_field_box)
        self.keyboard_top = 470
        box = self._pass_field_box
        self.dirty = (max(0, box[1]), min(HEIGHT, box[3]))
        return True

    def _paint_passphrase_field(self, frame: Frame, box):
        self._paint_hscroll_field(
            frame, box, self.passphrase_text, self.passphrase_cursor, "Type a passphrase",
        )

    def _paint_hscroll_field(self, frame: Frame, box, text: str, cursor: int, placeholder: str):
        """One line of text. A finger drags it sideways when it is wider than the field."""
        frame.draw.rounded_rectangle(box, radius=12, fill=WHITE, outline=LINE)
        text_x = box[0] + 16
        room = max(1, box[2] - 12 - text_x)
        face = font(TITLE_SIZE, mono=True)
        box_h = box[3] - box[1]
        if not text:
            self.hscroll = 0
            self.hscroll_max = 0
            self._hscroll_key = ("", 0)
            self._hscroll_box = None
            _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), placeholder, font=face)
            text_y = box[1] + (box_h - (text_bottom - text_top)) / 2 - text_top
            frame.draw.text((text_x, text_y), placeholder, font=face, fill=MUTED)
            return
        cursor = max(0, min(cursor, len(text)))
        ink_w = _text_ink_width(frame.draw, text, face)
        content_w = ink_w + 2
        max_scroll = max(0, content_w - room)
        caret = _text_ink_width(frame.draw, text[:cursor], face)
        key = (text, cursor)
        if key != self._hscroll_key:
            scroll = self.hscroll
            if caret < scroll:
                scroll = caret
            elif caret > scroll + room - 2:
                scroll = caret - (room - 2)
            self.hscroll = max(0, min(max_scroll, int(scroll)))
            self._hscroll_key = key
        else:
            self.hscroll = max(0, min(max_scroll, int(self.hscroll)))
        self.hscroll_max = max_scroll
        self._hscroll_box = box if max_scroll else None
        _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), text, font=face)
        text_y = (box_h - (text_bottom - text_top)) / 2 - text_top
        strip = Image.new("RGB", (max(room, content_w), box_h), WHITE)
        draw = ImageDraw.Draw(strip)
        draw.text((0, text_y), text, font=face, fill=INK)
        draw.line((caret, 14, caret, box_h - 14), fill=BLUE, width=2)
        left = self.hscroll
        frame.image.paste(strip.crop((left, 0, left + room, box_h)), (text_x, box[1]))
        frame.draw.rounded_rectangle(box, radius=12, outline=LINE)
        self._hscroll_cursor_hits(frame, box, text, text_x, face)

    def _hscroll_cursor_hits(self, frame: Frame, box, text: str, text_x: int, face):
        widths = [_text_ink_width(frame.draw, text[:index], face) for index in range(len(text) + 1)]
        positions = [text_x + width - self.hscroll for width in widths]
        for index in range(len(text) + 1):
            if index == 0:
                left = box[0]
            else:
                left = (positions[index - 1] + positions[index]) / 2
            if index == len(text):
                right = box[2]
            else:
                right = (positions[index] + positions[index + 1]) / 2
            hit_left = max(box[0], left)
            hit_right = min(box[2], right)
            if hit_right - hit_left < 1:
                continue
            frame.hit((hit_left, box[1], hit_right, box[3]), f"passcur-{index}", f"passcur-{index}")

    def _passphrase_keyboard(self, frame: Frame):
        modes = (("abc", "lower"), ("ABC", "upper"), (".?123", "digit"), ("#+=", "symbol"))
        y = 470
        self.keyboard_top = y
        gap = 8
        width = (WIDTH - 2 * MARGIN - gap * 3) // 4
        for index, (label, mode) in enumerate(modes):
            x = MARGIN + index * (width + gap)
            box = (x, y, x + width, y + 44)
            frame.draw.rounded_rectangle(box, radius=10, fill=BLUE if self.passphrase_mode == mode else NAVY)
            face = font(TITLE_SIZE)
            text_width = frame.draw.textlength(label, font=face)
            _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), label, font=face)
            text_y = y + (44 - (text_bottom - text_top)) / 2 - text_top
            frame.draw.text((x + (width - text_width) / 2, text_y), label, font=face, fill=WHITE)
            frame.hit(box, f"passmode-{mode}", label)
        rows = {
            "lower": ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
            "upper": ("QWERTYUIOP", "ASDFGHJKL", "ZXCVBNM"),
            "digit": ("1234567890", "-_.,'\"", ""),
            "symbol": ("!@#$%^&*()", "+=?/\\|:;", "<>[]{}"),
        }[self.passphrase_mode]
        key_h = 52
        y = 526
        for letters in rows:
            if not letters:
                continue
            key_w = min(42, (WIDTH - 2 * MARGIN - 6 * (len(letters) - 1)) // len(letters))
            row_w = key_w * len(letters) + 6 * (len(letters) - 1)
            x = (WIDTH - row_w) / 2
            for index, char in enumerate(letters):
                box = (x, y, x + key_w, y + key_h)
                frame.draw.rounded_rectangle(box, radius=8, fill=WHITE, outline=LINE)
                face = font(TITLE_SIZE)
                text_width = frame.draw.textlength(char, font=face)
                _left, text_top, _right, text_bottom = frame.draw.textbbox((0, 0), char, font=face)
                text_y = y + (key_h - (text_bottom - text_top)) / 2 - text_top
                frame.draw.text((x + (key_w - text_width) / 2, text_y), char, font=face, fill=INK)
                frame.hit(
                    self._key_hit(box, left=index == 0, right=index == len(letters) - 1),
                    f"passkey-{char}",
                    char,
                )
                x += key_w + 6
            y += key_h + 6
        space = (MARGIN, y, WIDTH - MARGIN - 100, y + key_h)
        frame.draw.rounded_rectangle(space, radius=8, fill=WHITE, outline=LINE)
        frame.draw.text((space[0] + 16, y + 8), "space", font=font(TITLE_SIZE), fill=INK)
        frame.hit(self._key_hit(space, bottom=True, left=True), "passkey- ", "space")
        delete = (WIDTH - MARGIN - 88, y, WIDTH - MARGIN, y + key_h)
        frame.draw.rounded_rectangle(delete, radius=8, fill=BLUE)
        frame.draw.text((delete[0] + 16, y + 8), "del", font=font(TITLE_SIZE), fill=WHITE)
        frame.hit(self._key_hit(delete, bottom=True, right=True), "passkey-backspace", "backspace")

    def _passphrase_key(self, key: str):
        if self.screen == "export-name":
            self._type_filename(key)
            return
        if key == "backspace":
            if self.passphrase_cursor > 0:
                self.passphrase_text = (
                    self.passphrase_text[: self.passphrase_cursor - 1]
                    + self.passphrase_text[self.passphrase_cursor :]
                )
                self.passphrase_cursor -= 1
            return
        self.passphrase_text = (
            self.passphrase_text[: self.passphrase_cursor] + key + self.passphrase_text[self.passphrase_cursor :]
        )
        self.passphrase_cursor += len(key)

    def _type_filename(self, key: str):
        if key == "backspace":
            if self.filename_cursor > 0:
                self.filename = self.filename[: self.filename_cursor - 1] + self.filename[self.filename_cursor :]
                self.filename_cursor -= 1
            return
        if len(self.filename) >= 64:
            return
        self.filename = self.filename[: self.filename_cursor] + key + self.filename[self.filename_cursor :]
        self.filename_cursor += len(key)

    def _start_passphrase_copy(self):
        record = self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys or not record.keys[0].has_seed:
            self.set_notice("That key does not have a seed.")
            return
        self.seed_words = list(record.keys[0].mnemonic)
        self.seed_length = len(self.seed_words)
        self.passphrase_text = ""
        self.passphrase_cursor = 0
        self.passphrase_mode = "lower"
        self.go("passphrase")

    def _save_entered_seed(self, passphrase: str | None):
        if len(self.seed_words) not in (12, 18, 24):
            self.set_notice("A seed must be 12, 18, or 24 words.")
            return
        try:
            added = self.session.add_mnemonic(self.seed_words, passphrase)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.pending_mnemonic = ""
        self.entropy_digits = ""
        self.seed_words = []
        self.word_prefix = ""
        self.passphrase_text = ""
        self.selected_fp = added["fingerprint"]
        message = added["message"]
        if added.get("warnings"):
            message = f"{message} {' '.join(added['warnings'])}"
        self.set_notice(message)
        self.back = ["keys"]
        self.scroll["key"] = 0
        self.screen = "key"
        self.show_secret = False
        self.show_passphrase = False

    def _review(self, frame: Frame):
        frame.header("Transaction", "back")
        if not self.review:
            frame.text("No transaction is loaded.", MARGIN, 140)
            return
        end = self._review_flow(frame, paint=False, offset=0)
        offset = self._scroll_offset("review", end, clearance=16)
        self._review_flow(frame, paint=True, offset=offset)
        frame.header("Transaction", "back")

    def _review_flow(self, frame: Frame, paint: bool, offset: int) -> int:
        review = self.review
        y = HEADER + 16
        size = TITLE_SIZE
        y = self._flow_text(
            frame, y, f"PSBT v{review['psbt_version']}  tx v{review['tx_version']}", paint, offset, size,
        )
        y = self._flow_text(frame, y, review["txid"], paint, offset, size, mono=True)
        btc = review["external_amount"] / 1e8
        fee = review["fee"] / 1e8
        y = self._flow_text(frame, y, f"Sent {btc:.8f} BTC", paint, offset, size)
        y = self._flow_text(
            frame, y, f"Fee {fee:.8f} BTC at {review['fee_rate']} sat/vB", paint, offset, size,
        )
        for warning in review["warnings"]:
            y = self._flow_text(frame, y, warning, paint, offset, size, fill=RED)
        for item in review["external"]:
            if item["op_return"]:
                text = item["payload"].decode("utf-8") if _is_text(item["payload"]) else item["payload"].hex()
                y = self._flow_text(frame, y, f"OP_RETURN {text}", paint, offset, size, mono=True)
            else:
                y = self._flow_text(
                    frame, y, f"{item['amount'] / 1e8:.8f} {item['address']}", paint, offset, size, mono=True,
                )
        return y

    def _qr(self, frame: Frame):
        if self.qr_kind in ("key", "descriptor"):
            if self.qr_zoom is not None:
                self._draw_zoom(frame)
                return
            if self.qr_kind == "key":
                self._draw_key_qr(frame)
            else:
                self._draw_descriptor_qr(frame)
            return
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=WHITE)
        if self.qr_zoom is None:
            payload = self._qr_payload()
            image = _qr_image(payload, 400)
            frame.image.paste(image, ((WIDTH - image.width) // 2, 48))
            frame.button(HEIGHT - 100, "Zoom In", "zoom-in")
            frame.hit((0, 0, 80, 80), "back", "back")
            frame.glyph(Icons.BACK, 40, 40, 40, INK)
            return
        self._draw_zoom(frame)

    def _seed_show(self, frame: Frame):
        if self.qr_zoom is not None and SEED_FORMATS[self.seed_format] != "words":
            self._draw_zoom(frame)
            return
        frame.header("Seed", "back")
        name = SEED_FORMAT_NAMES[self.seed_format]
        if SEED_FORMATS[self.seed_format] == "words":
            words = self.qr_text.split()
            self._draw_indexed_grid(
                frame, words, HEADER + 16, HEIGHT - 110,
                scroll=True, columns=SEED_CARD_COLUMNS, gap=SEED_CARD_GAP,
                inset=MARGIN, pad_x=SEED_CARD_PAD_X,
            )
        else:
            self.seed_grid_box = None
            self.seed_grid_max = 0
            light = _qr_light(self.qr_brightness)
            frame.draw.rectangle((0, HEADER, WIDTH, HEIGHT), fill=light)
            image = _qr_image(self._seed_qr_payload(), 360, light)
            frame.image.paste(image, ((WIDTH - image.width) // 2, HEADER + 12))
            self._brightness_control(frame, HEIGHT - 252)
            frame.button(HEIGHT - 188, "Zoom In", "zoom-in")
        self._format_switcher(frame, name)

    def _brightness_control(self, frame: Frame, y: int):
        side = 64
        height = 52
        left = (MARGIN, y, MARGIN + side, y + height)
        right = (WIDTH - MARGIN - side, y, WIDTH - MARGIN, y + height)
        self._brightness_button(frame, left, "-", self.qr_brightness > 0, "brightness-down")
        self._brightness_button(frame, right, "+", self.qr_brightness < QR_BRIGHTNESS_MAX, "brightness-up")
        face = font(TITLE_SIZE)
        label = "Brightness"
        text_width = frame.draw.textlength(label, font=face)
        text_left, text_top, _text_right, text_bottom = frame.draw.textbbox((0, 0), label, font=face)
        text_y = y + (height - (text_bottom - text_top)) / 2 - text_top
        frame.draw.text(((WIDTH - text_width) / 2 - text_left, text_y), label, font=face, fill=INK)

    def _brightness_button(self, frame: Frame, box, label: str, enabled: bool, action: str):
        fill = BLUE if enabled else (186, 190, 196)
        text = WHITE if enabled else (132, 136, 142)
        frame.draw.rounded_rectangle(box, radius=12, fill=fill)
        rendered = glyph_sprite(label, 32, text, text=True)
        if rendered is not None:
            glyph, (center_x, center_y) = rendered
            cx = (box[0] + box[2]) / 2
            cy = (box[1] + box[3]) / 2
            frame.image.paste(glyph, (round(cx - center_x), round(cy - center_y)), glyph)
        if enabled:
            frame.hit(box, action, label)

    def _format_switcher(self, frame: Frame, name: str, previous: str = "seed-format-prev", following: str = "seed-format-next"):
        y = HEIGHT - 88
        side = 72
        left = (MARGIN, y, MARGIN + side, y + 64)
        right = (WIDTH - MARGIN - side, y, WIDTH - MARGIN, y + 64)
        for box, label, action in (
            (left, "<", previous),
            (right, ">", following),
        ):
            frame.draw.rounded_rectangle(box, radius=14, fill=BLUE)
            face = font(32)
            text_width = frame.draw.textlength(label, font=face)
            frame.draw.text((box[0] + (side - text_width) / 2, y + 14), label, font=face, fill=WHITE)
            frame.hit(box, action, label)
        limit = (WIDTH - MARGIN - 72) - (MARGIN + 72) - 16
        size = TITLE_SIZE
        face = font(size)
        while size > 22 and frame.draw.textlength(name, font=face) > limit:
            size -= 1
            face = font(size)
        text_width = frame.draw.textlength(name, font=face)
        text_left, text_top, _text_right, text_bottom = frame.draw.textbbox((0, 0), name, font=face)
        text_y = y + (64 - (text_bottom - text_top)) / 2 - text_top
        frame.draw.text(((WIDTH - text_width) / 2 - text_left, text_y), name, font=face, fill=INK)

    def _step_seed_format(self, delta: int):
        self.seed_format = (self.seed_format + delta) % len(SEED_FORMATS)
        self.qr_zoom = None

    def _seed_qr_payload(self):
        words = self.qr_text.strip()
        if SEED_FORMATS[self.seed_format] == "text":
            return words.upper()
        return compact_bytes(words)

    def _open_seed_show(self):
        record = self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys or not record.keys[0].has_seed:
            self.set_notice("That key does not have a seed.")
            return
        self.qr_text = " ".join(record.keys[0].mnemonic)
        self.seed_format = 0
        self.qr_zoom = None
        self.seed_grid_scroll = 0
        self.seed_grid_stick = False
        self.go("seed-show")

    def _draw_zoom(self, frame: Frame):
        modules = _qr_modules(self._qr_payload())
        size = len(modules)
        origin_x, origin_y = self.qr_zoom
        cell = QR_ZOOM_CELL
        count = QR_ZOOM_COUNT
        left, top, grid_bottom = _zoom_grid_box()
        light = (
            _qr_light(self.qr_brightness)
            if self.screen == "seed-show" or self.qr_kind in ("key", "descriptor")
            else WHITE
        )
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
        frame.header("Zoomed QR", "zoom-close")
        for row in range(count):
            for col in range(count):
                module_x = origin_x + col
                module_y = origin_y + row
                dark = 0 <= module_x < size and 0 <= module_y < size and modules[module_y][module_x]
                color = INK if dark else light
                x = left + col * cell
                y = top + row * cell
                frame.draw.rectangle((x, y, x + cell - 1, y + cell - 1), fill=color, outline=LINE)
        self._zoom_indexes(frame, left, top, origin_x, origin_y)
        self._zoom_pad(frame, grid_bottom, origin_x, origin_y, size)

    def _zoom_indexes(self, frame: Frame, left: int, top: int, origin_x: int, origin_y: int):
        """Absolute row and column numbers, counting from 1 at the top-left module."""
        cell = QR_ZOOM_CELL
        slot_w = cell - 6
        slot_h = min(QR_ZOOM_BAND - 4, cell - 8)
        two = _zoom_index_size(frame.draw, 2, slot_w, slot_h)
        three = _zoom_index_size(frame.draw, 3, slot_w, slot_h)
        for col in range(QR_ZOOM_COUNT):
            label = str(origin_x + col + 1)
            self._zoom_index(
                frame,
                label,
                three if len(label) >= 3 else two,
                left + col * cell + cell / 2,
                HEADER + QR_ZOOM_BAND / 2,
                align="center",
            )
        for row in range(QR_ZOOM_COUNT):
            label = str(origin_y + row + 1)
            self._zoom_index(
                frame,
                label,
                three if len(label) >= 3 else two,
                left - 4,
                top + row * cell + cell / 2,
                align="right",
            )

    def _zoom_index(self, frame: Frame, label: str, size: int, anchor_x: float, anchor_y: float, align: str):
        face = font(size, mono=True)
        bbox = frame.draw.textbbox((0, 0), label, font=face)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        x = anchor_x - text_w if align == "right" else anchor_x - text_w / 2
        y = anchor_y - text_h / 2 - bbox[1]
        frame.draw.text((x, y), label, font=face, fill=INK)

    def _zoom_pad(self, frame: Frame, grid_bottom: int, origin_x: int, origin_y: int, size: int):
        """Up, Left, Right, and Down sit on the cross of a 3×3 pad."""
        gap = 10
        side = 16
        pad_top = grid_bottom + QR_ZOOM_CELL
        inner_h = HEIGHT - side - pad_top - 2 * gap
        cell_h = inner_h // 3
        span = WIDTH - 2 * side - 2 * gap
        cell_w = span // 3
        origin = side + (span - cell_w * 3) // 2
        limit = max(0, size - QR_ZOOM_COUNT)
        spots = (
            (1, 0, "Up", "zoom-up", origin_y > 0),
            (0, 1, "Left", "zoom-left", origin_x > 0),
            (2, 1, "Right", "zoom-right", origin_x < limit),
            (1, 2, "Down", "zoom-down", origin_y < limit),
        )
        for col, row, label, action, enabled in spots:
            x = origin + col * (cell_w + gap)
            y = pad_top + row * (cell_h + gap)
            self._zoom_button(frame, (x, y, x + cell_w, y + cell_h), label, enabled, action)

    def _zoom_button(self, frame: Frame, box, label: str, enabled: bool, action: str):
        fill = BLUE if enabled else (186, 190, 196)
        text = WHITE if enabled else (132, 136, 142)
        frame.draw.rounded_rectangle(box, radius=14, fill=fill)
        face = font(TITLE_SIZE)
        bbox = frame.draw.textbbox((0, 0), label, font=face)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        x = box[0] + (box[2] - box[0] - text_w) / 2
        y = box[1] + (box[3] - box[1] - text_h) / 2 - bbox[1]
        frame.draw.text((x, y), label, font=face, fill=text)
        if enabled:
            frame.hit(box, action, label)

    def _drawer(self, frame: Frame):
        overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 90))
        base = frame.image.convert("RGBA")
        frame.image = Image.alpha_composite(base, overlay).convert("RGB")
        frame.draw = __import__("PIL.ImageDraw", fromlist=["Draw"]).Draw(frame.image)
        frame.draw.rectangle((0, 0, 320, HEIGHT), fill=WHITE)
        mark = logo(260, 88)
        frame.image.paste(mark, ((320 - mark.width) // 2, 28), mark)
        y = 28 + mark.height + 20
        face = font(30)
        row_h = 80
        section = self._menu_section()
        frame.draw.line((20, y, 300, y), fill=LINE, width=2)
        for label, action in (
            ("Bitcoin Keys", "nav-keys"),
            ("Bitcoin Wallets", "nav-wallets"),
            ("Settings", "nav-settings"),
            ("About", "nav-about"),
        ):
            next_y = y + row_h
            if action == f"nav-{section}":
                frame.draw.rectangle((0, y + 1, 320, next_y), fill=(228, 230, 234))
            _left, top, _right, bottom = frame.draw.textbbox((0, 0), label, font=face)
            text_y = y + (row_h - (bottom - top)) / 2 - top
            frame.draw.text((28, text_y), label, font=face, fill=INK)
            frame.hit((0, y, 320, next_y), action, label)
            y = next_y
            frame.draw.line((20, y, 300, y), fill=LINE, width=2)
        frame.hit((320, 0, WIDTH, HEIGHT), "close-menu", "close")

    def _menu_section(self) -> str:
        """The side-menu page where this screen's back stack begins."""
        for screen in (*self.back, self.screen):
            if screen in {"keys", "wallets", "settings", "about"}:
                return screen
        return ""

    def _confirm_message(self) -> str:
        if self.confirm in ("show-seed", "show-passphrase"):
            return "Make sure nobody is looking over your shoulder!"
        if self.confirm == "delete-key" and self.selected_fp is not None:
            try:
                return self.session.deletion_message(self.selected_fp, 0)
            except SessionError:
                return "Delete this key?"
        if self.confirm == "delete-wallet":
            return "Delete this wallet? Its keys stay loaded."
        if self.confirm == "replace-file":
            return f'Replace "{Path(self.export_path).name}"?'
        return "Delete this key?"

    def _confirm(self, frame: Frame):
        overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 110))
        base = frame.image.convert("RGBA")
        frame.image = Image.alpha_composite(base, overlay).convert("RGB")
        frame.draw = ImageDraw.Draw(frame.image)
        frame.hit((0, 0, WIDTH, HEIGHT), "confirm-no", "outside")
        message = self._confirm_message()
        face = font(BODY_SIZE)
        lines = wrap(frame.draw, message, face, WIDTH - 88)
        line_h = BODY_SIZE + 8
        button_h = BODY_SIZE + 36
        text_top = 268
        button_top = text_top + line_h * max(1, len(lines)) + 16
        box_bottom = button_top + button_h + 24
        box_top = 230
        if box_bottom > HEIGHT - 16:
            shift = box_bottom - (HEIGHT - 16)
            text_top -= shift
            button_top -= shift
            box_top -= shift
            box_bottom -= shift
        box = (24, box_top, WIDTH - 24, box_bottom)
        frame.draw.rounded_rectangle(box, radius=18, fill=WHITE, outline=LINE)
        frame.hit(box, "confirm-stay", "dialog")
        y = text_top
        for line in lines:
            frame.draw.text((44, y), line, font=face, fill=INK)
            y += line_h
        self._confirm_buttons(frame, box)

    def _confirm_buttons(self, frame: Frame, box):
        gap = 12
        height = BODY_SIZE + 36
        y = box[3] - 24 - height
        left = box[0] + 20
        right = box[2] - 20
        width = (right - left - gap) // 2
        cancel = (left, y, left + width, y + height)
        confirm = (left + width + gap, y, right, y + height)
        self._dialog_button(frame, cancel, "Cancel", "confirm-no", (132, 138, 148))
        color = RED if self.confirm in ("delete-key", "delete-wallet", "replace-file") else BLUE
        self._dialog_button(frame, confirm, "Confirm", "confirm-yes", color)

    def _dialog_button(self, frame: Frame, box, text: str, action: str, color):
        frame.draw.rounded_rectangle(box, radius=14, fill=color)
        face = font(BODY_SIZE)
        left, top, right, bottom = frame.draw.textbbox((0, 0), text, font=face)
        cx = (box[0] + box[2]) / 2
        cy = (box[1] + box[3]) / 2
        frame.draw.text(
            (cx - (right - left) / 2 - left, cy - (bottom - top) / 2 - top),
            text,
            font=face,
            fill=WHITE,
        )
        frame.hit(box, action, text)

    def _confirm_yes(self):
        kind = self.confirm
        self.confirm = None
        if kind == "show-seed":
            self._open_seed_show()
        elif kind == "show-passphrase":
            self.go("passphrase-view")
        elif kind == "delete-key":
            self._delete_selected_key()
        elif kind == "delete-wallet":
            self._delete_selected_wallet()
        elif kind == "replace-file":
            self._write_export()

    def _descriptor_choice_message(self) -> str:
        if self.descriptor_choice and self.descriptor_choice.get("multisig"):
            return (
                "This is a multisig wallet descriptor. "
                "Do you want to load the wallet and all the keys, or only a specific key?"
            )
        return (
            "This is a singlesig wallet descriptor. "
            "Do you want to load both the wallet and the key, or only the key?"
        )

    def _descriptor_choice(self, frame: Frame):
        frame.header("Wallet Descriptor", "back")
        choice = self.descriptor_choice
        if not choice:
            frame.text("This descriptor is no longer waiting to be loaded.", MARGIN, HEADER + 24, size=BODY_SIZE)
            return
        y = frame.text(self._descriptor_choice_message(), MARGIN, HEADER + 24, size=BODY_SIZE)
        if choice["multisig"]:
            y = frame.button(y + 20, "Load Both Wallet and All Keys", "descriptor-both")
            labels = choice["labels"]
            index = min(self.descriptor_key_index, len(labels) - 1)
            field = self._dropdown_field(frame, y + 64, "descriptor-key", labels[index])
            frame.button(field[3] + 24, "Load Only Selected Key", "descriptor-key")
            if self.open_dropdown == "descriptor-key":
                options = [(str(item), label) for item, label in enumerate(labels)]
                self._dropdown_menu(frame, field, "descriptor-key", options, str(index))
            return
        frame.button(HEIGHT - 190, "Both Wallet and Key", "descriptor-both")
        frame.button(HEIGHT - 110, "Only the Key", "descriptor-key")

    def _load_chosen_descriptor_key(self):
        choice = self.descriptor_choice
        if not choice:
            return
        expressions = choice["expressions"]
        index = min(self.descriptor_key_index, len(expressions) - 1) if choice["multisig"] else 0
        try:
            key = self.session.prepare_external_key(expressions[index])
        except SessionError as exc:
            self._show_load_error(str(exc), "key")
            return
        self.wallet_plan = None
        self.pending_external = key
        self.external_format = "xpub"
        self.open_dropdown = None
        self.scroll["external-review"] = 0
        self.go("external-review")

    def _commit_external_key(self):
        key = self.pending_external
        if key is None:
            self.set_notice("There is no external key to load.")
            return
        try:
            added = self.session.commit_external_key(key)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.pending_external = None
        self.open_dropdown = None
        self._show_imported(added, prefer_key=True)

    def _start_wallet_import(self, text: str):
        try:
            plan = self.session.plan_wallet_import(text)
        except SessionError as exc:
            self._show_load_error(str(exc), "descriptor")
            return
        self.wallet_plan = plan
        self.wallet_plan_pos = 0
        self.external_format = "xpub"
        self.open_dropdown = None
        self.back = ["wallets"]
        self.menu = False
        self.add_menu = False
        if plan["parsed"].multisig and (plan["new_keys"] or plan["existing"] is None):
            self.pending_external = plan["new_keys"][0] if plan["new_keys"] else None
            self.scroll["external-review"] = 0
            self.screen = "external-review"
            return
        if plan["new_keys"]:
            self.pending_external = plan["new_keys"][0]
            self.scroll["external-review"] = 0
            self.screen = "external-review"
            return
        if plan["existing"] is not None:
            self.screen = "wallet-import-note"
            return
        self._finish_wallet_import()

    def _advance_wallet_import(self):
        plan = self.wallet_plan
        if plan is None:
            return
        self.wallet_plan_pos += 1
        self.external_format = "xpub"
        self.open_dropdown = None
        if self.wallet_plan_pos < len(plan["new_keys"]):
            self.pending_external = plan["new_keys"][self.wallet_plan_pos]
            self.scroll["external-details"] = 0
            self.back = ["wallets"]
            self.screen = "external-details"
            return
        self.pending_external = None
        if plan["existing"] is not None:
            self.back = ["wallets"]
            self.screen = "wallet-import-note"
            return
        self._finish_wallet_import()

    def _finish_wallet_import(self):
        plan = self.wallet_plan
        self.wallet_plan = None
        self.pending_external = None
        self.open_dropdown = None
        if plan is None:
            self._show_load_error("There is no wallet waiting to be loaded.", "descriptor")
            return
        try:
            wallet = self.session.apply_wallet_plan(plan)
        except SessionError as exc:
            self._show_load_error(str(exc), "descriptor")
            return
        self.wallet_index = self.session.wallets.index(wallet)
        if plan["existing"] is None:
            message = "The multisig wallet was added successfully." if plan["parsed"].multisig else "The wallet was added successfully."
            self.set_notice(message)
        else:
            self.set_notice("")
        self.back = ["wallets"]
        self.scroll["wallet"] = 0
        self.screen = "wallet"
        self.menu = False
        self.add_menu = False
        self._remember_wallet_accounts()

    def _wallet_import_message(self) -> str:
        plan = self.wallet_plan
        name = self.session.wallet_short_name_of(plan["existing"])
        accounts = self._wallet_import_accounts()
        if plan["new_keys"]:
            return f'Wallet "{name}" was already loaded. You can now also use {accounts}.'
        return f'Wallet "{name}" was already loaded. This descriptor points to {accounts}.'

    def _wallet_import_accounts(self) -> str:
        plan = self.wallet_plan
        existing = plan["existing"]
        by_fingerprint = {key.fingerprint: key.account for key in plan["parsed"].keys}
        order = existing.fingerprints if existing is not None else [key.fingerprint for key in plan["parsed"].keys]
        return account_index_phrase(order, by_fingerprint)

    def _wallet_import_note(self, frame: Frame):
        plan = self.wallet_plan
        if plan is None or plan["existing"] is None:
            frame.header("Load Wallet", "back")
            frame.text("This wallet is no longer waiting to be loaded.", MARGIN, HEADER + 24)
            return
        message = self._wallet_import_message()
        frame.header("Load Wallet", "back")
        frame.text(message, MARGIN, HEADER + 28, size=BODY_SIZE)
        frame.button(HEIGHT - 110, "Go to Wallet", "wallet-import-continue")

    def _external_format_options(self, key):
        network = self.session.network
        canonical = "xpub" if network == "main" else "tpub"
        options = [("xpub", canonical)]
        slip = display_form(key.canonical, network, key.role)
        if slip is not None:
            options.append(("slip", f"{label_of(slip)} (SLIP-132)"))
        options.append(("expression", "Full Key Expression"))
        return options

    def _external_format_label(self, key) -> str:
        return dict(self._external_format_options(key))[self.external_format]

    def _external_preview(self, key) -> str:
        if self.external_format == "slip":
            slip = display_form(key.canonical, self.session.network, key.role)
            return slip or key.canonical
        if self.external_format == "expression":
            path = format_path(list(key.path))[2:]
            return f"[{key.fingerprint.hex()}/{path}]{key.canonical}/<0;1>/*"
        return key.canonical

    def _continue_loaded_multisig(self):
        plan = self.wallet_plan
        if plan is None:
            return
        self.pending_external = None
        if plan["existing"] is not None:
            self.back = ["wallets"]
            self.screen = "wallet-import-note"
            return
        self._finish_wallet_import()

    def _importing_multisig_wallet(self) -> bool:
        plan = self.wallet_plan
        return plan is not None and plan["parsed"].multisig

    def _multisig_key_counts(self) -> tuple[int, int]:
        plan = self.wallet_plan
        total = len(plan["parsed"].keys)
        known = total - len(plan["new_keys"])
        return known, total

    def _known_keys_sentence(self) -> str:
        known, total = self._multisig_key_counts()
        if known == total:
            return f"All of the multisig wallet's {total} keys were already loaded."
        verb = "was" if known == 1 else "were"
        return f"{known} of the multisig wallet's {total} keys {verb} already loaded."

    def _wallet_key_warning(self) -> str | None:
        """The warning used while importing a wallet. A lone external key keeps its own text."""
        plan = self.wallet_plan
        if plan is None:
            return None
        if plan["parsed"].multisig:
            new = len(plan["new_keys"])
            if new == 1:
                return (
                    "You are about to load 1 external key for a multisig wallet. "
                    "Your co-signer must verify on their hardware wallet that the following "
                    "extended public key (xpub) is indeed theirs."
                )
            return (
                f"You are about to load {new} external keys for a multisig wallet. "
                "Your co-signers must verify on their hardware wallets that the following "
                "extended public keys (xpubs) are indeed theirs."
            )
        return self._lone_key_warning()

    def _lone_key_warning(self) -> str:
        """Warning for one key expression loaded from Bitcoin Keys."""
        key = self.pending_external
        if key is not None and getattr(key, "role", None) == MULTISIG_NATIVE:
            return (
                "You are about to load an external key for a multisig wallet. "
                "Your co-signer must verify on their hardware wallet that the following "
                "extended public key (xpub) is indeed theirs."
            )
        return (
            "You are about to load an external key for a singlesig wallet. "
            "Before sending any funds to the wallet addresses, the wallet owner must verify "
            "on their hardware wallet that the following extended public key is indeed theirs."
        )

    def _external_details_title(self) -> str:
        title = "Extended Public Key Details"
        plan = self.wallet_plan
        if plan is None:
            return title
        count = len(plan["new_keys"])
        if count < 2:
            return title
        return f"{title} {self.wallet_plan_pos + 1}/{count}"

    def _external_warning(self, frame: Frame):
        multisig = self._importing_multisig_wallet()
        if self.pending_external is None and not multisig:
            frame.header("Load External Key", "back")
            frame.text("This external key is no longer waiting to be loaded.", MARGIN, HEADER + 24)
            return
        frame.header("Load MultiSig Wallet" if multisig else "Load External Key", "back")
        if not multisig:
            self._centered_text(frame, "Warning", HEADER + 28, 34, RED)
            message = self._wallet_key_warning() or self._lone_key_warning()
            frame.text(message, MARGIN, HEADER + 88, size=TITLE_SIZE, fill=RED)
            frame.button(HEIGHT - 110, "Show Extended Public Key Details", "external-next")
            return
        known, total = self._multisig_key_counts()
        y = HEADER + 16
        if known:
            y = frame.text(self._known_keys_sentence(), MARGIN, y, size=TITLE_SIZE)
            y += 16
        if known < total:
            y = self._centered_text(frame, "Warning", y, 34, RED)
            frame.text(self._wallet_key_warning(), MARGIN, y, size=TITLE_SIZE, fill=RED)
            frame.button(HEIGHT - 110, "Show Extended Public Key Details", "external-next")
            return
        frame.button(HEIGHT - 110, "Continue", "external-known")

    def _external_details(self, frame: Frame):
        key = self.pending_external
        if key is None:
            frame.header("Load External Key", "back")
            frame.text("This external key is no longer waiting to be loaded.", MARGIN, HEADER + 24)
            return
        subtitle = self._external_details_title()
        intro = "Verify these details are backed up:"
        prompt = "Verify this Extended Public Key on the other hardware wallet:"
        preview = self._external_preview(key)
        xpub_size = TITLE_SIZE
        detail = TITLE_SIZE
        path = format_path(list(key.path))
        y = HEADER + 16
        y += self._text_height(frame, subtitle, detail)
        y += 8
        y += self._text_height(frame, prompt, detail)
        y += 8
        y += self._text_height(frame, "Format:", detail)
        y += 8
        y += 64 + 16
        y += self._text_height(frame, preview, xpub_size, mono=True) + 16
        y += 16
        y += self._text_height(frame, intro, detail)
        y += 20
        y += self._text_height(frame, f"Type: {self._external_kind(key)}", detail)
        y += detail + 8
        y += self._text_height(frame, "Derivation Path:", detail)
        y += detail + 8
        content_end = y + frame.button_height("Continue") + 24
        offset = self._scroll_offset("external-details", content_end, clearance=12)
        y = HEADER + 16 - offset
        y = self._centered_block(frame, subtitle, y, detail, INK)
        y += 8
        y = frame.text(prompt, MARGIN, y, size=detail)
        y = frame.text("Format:", MARGIN, y + 8, size=detail, fill=MUTED)
        field = self._dropdown_field(frame, y + 8, "external-format", self._external_format_label(key))
        y = self._draw_wrapped(frame, preview, field[3] + 16, xpub_size, mono=True)
        y += 16
        y = frame.text(intro, MARGIN, y, size=detail)
        y += 20
        y = self._label_value(frame, y, "Type: ", self._external_kind(key), detail)
        y = self._review_account_line(frame, y, key.account)
        y = frame.text("Derivation Path:", MARGIN, y, size=detail, fill=MUTED)
        path_face = font(detail, mono=True)
        path_width = frame.draw.textlength(path, font=path_face)
        if y >= HEADER:
            frame.draw.text((max(MARGIN, (WIDTH - path_width) / 2), y), path, font=path_face, fill=INK)
        y += detail + 8
        frame.button(y + 16, "Continue", "external-continue")
        frame.header("Load External Key", "back")
        if self.open_dropdown == "external-format":
            self._dropdown_menu(
                frame,
                field,
                "external-format",
                self._external_format_options(key),
                self.external_format,
            )

    def _centered_text(self, frame: Frame, value: str, y: int, size: int, fill) -> int:
        face = font(size)
        width = frame.draw.textlength(value, font=face)
        frame.draw.text(((WIDTH - width) / 2, y), value, font=face, fill=fill)
        return y + size + 8

    def _centered_block(self, frame: Frame, value: str, y: int, size: int, fill) -> int:
        face = font(size)
        for line in wrap(frame.draw, value, face, WIDTH - 2 * MARGIN) or [""]:
            if y >= HEADER:
                width = frame.draw.textlength(line, font=face)
                frame.draw.text(((WIDTH - width) / 2, y), line, font=face, fill=fill)
            y += size + 8
        return y

    def _label_value(self, frame: Frame, y: int, label: str, value: str, size: int, value_fill=INK) -> int:
        """A grey label and its value, wrapping as one sentence. Later lines are the value."""
        face = font(size)
        source = f"{label}{value}"
        lines = wrap(frame.draw, source, face, WIDTH - 2 * MARGIN) or [""]
        cursor = 0
        label_end = len(label)
        for line in lines:
            while cursor < len(source) and not source.startswith(line, cursor):
                cursor += 1
            if y >= HEADER:
                if cursor < label_end:
                    take = min(len(line), label_end - cursor)
                    label_part = line[:take]
                    value_part = line[take:]
                    frame.draw.text((MARGIN, y), label_part, font=face, fill=MUTED)
                    if value_part:
                        x = MARGIN + frame.draw.textlength(label_part, font=face)
                        frame.draw.text((x, y), value_part, font=face, fill=value_fill)
                else:
                    frame.draw.text((MARGIN, y), line, font=face, fill=value_fill)
            cursor += len(line)
            y += size + 8
        return y

    def _text_height(self, frame: Frame, value: str, size: int, mono: bool = False) -> int:
        face = font(size, mono=mono)
        lines = wrap(frame.draw, value, face, WIDTH - 2 * MARGIN) or [""]
        return len(lines) * (size + 8)

    def _draw_wrapped(self, frame: Frame, value: str, y: int, size: int, mono: bool = False) -> int:
        face = font(size, mono=mono)
        for line in wrap(frame.draw, value, face, WIDTH - 2 * MARGIN) or [""]:
            if y >= HEADER:
                frame.draw.text((MARGIN, y), line, font=face, fill=INK)
            y += size + 8
        return y

    def _review_account_line(self, frame: Frame, y: int, account: int) -> int:
        size = TITLE_SIZE
        face = font(size)
        label = "Account: "
        if y >= HEADER:
            frame.draw.text((MARGIN, y), label, font=face, fill=MUTED)
            x = MARGIN + frame.draw.textlength(label, font=face)
            if account == 0:
                frame.draw.text((x, y), "0 (default)", font=face, fill=INK)
            else:
                value = str(account)
                frame.draw.text((x, y), value, font=face, fill=RED)
                x += frame.draw.textlength(value, font=face)
                frame.draw.text((x, y), " - non-default", font=face, fill=RED)
        return y + size + 8

    def _notice_layout(self, frame: Frame):
        face = font(TITLE_SIZE)
        text_width = WIDTH - 2 * MARGIN - 32
        lines = wrap(frame.draw, self.notice, face, text_width) or [""]
        line_h = TITLE_SIZE + 8
        pad = 16
        height = pad * 2 + line_h * len(lines) - 8
        top = HEIGHT - 24 - height
        return face, lines, line_h, pad, top, height

    def _toast(self, frame: Frame):
        face, lines, line_h, pad, top, height = self._notice_layout(frame)
        frame.draw.rounded_rectangle((MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=NAVY)
        y = top + pad
        for line in lines:
            frame.draw.text((MARGIN + 16, y), line, font=face, fill=WHITE)
            y += line_h

    def _speed_dial(self, frame: Frame, items):
        overlay = Image.new("RGBA", (WIDTH, HEIGHT), (0, 0, 0, 80))
        base = frame.image.convert("RGBA")
        frame.image = Image.alpha_composite(base, overlay).convert("RGB")
        frame.draw = ImageDraw.Draw(frame.image)
        frame.hit((0, 0, WIDTH, HEIGHT), "close-add", "close-add")
        face = font(BODY_SIZE)
        line_h = BODY_SIZE + 8
        gap = 12
        text_width = 380
        prepared = []
        for label, action in items:
            lines = wrap(frame.draw, label, face, text_width)
            height = max(BODY_SIZE + 28, 16 + line_h * len(lines))
            prepared.append((action, lines, height, label))
        rows = []
        y = HEIGHT - _PLUS_CLEARANCE - 16
        for action, lines, height, label in reversed(prepared):
            y -= height
            box = (WIDTH - 24 - (text_width + 36), y, WIDTH - 24, y + height)
            frame.draw.rounded_rectangle(box, radius=16, fill=WHITE)
            _left, top, _right, bottom = frame.draw.textbbox((0, 0), lines[0], font=face)
            block = (bottom - top) + line_h * (len(lines) - 1)
            text_y = y + (height - block) / 2 - top
            for line in lines:
                frame.draw.text((box[0] + 18, text_y), line, font=face, fill=INK)
                text_y += line_h
            rows.append((y, y + height, action, label))
            y -= gap
        # The grey page behind the rows closes the menu. The top row sits in
        # that grey, so a touch slightly above its white pill was an outside
        # tap and the menu vanished. Each row owns the gap around it, and the
        # top row owns a band above the pill.
        rows.reverse()
        plus_top = HEIGHT - 28 - _PLUS_DIAMETER
        for index, (top, bottom, action, label) in enumerate(rows):
            if index == 0:
                above = max(HEADER, top - 72)
            else:
                above = (rows[index - 1][1] + top) // 2
            if index == len(rows) - 1:
                below = min(plus_top, bottom + 16)
            else:
                below = (bottom + rows[index + 1][0]) // 2
            frame.hit((0, above, WIDTH, below), action, label)

    def _plus(self, frame: Frame, action: str, icon: str):
        diameter = _PLUS_DIAMETER
        box = (WIDTH - 24 - diameter, HEIGHT - 28 - diameter, WIDTH - 24, HEIGHT - 28)
        frame.draw.ellipse(box, fill=BLUE)
        cx = (box[0] + box[2]) / 2
        cy = (box[1] + box[3]) / 2
        frame.glyph(icon, cx, cy, _PLUS_GLYPH, WHITE)
        frame.hit(box, action, "plus")

    def _pick_word(self, word: str):
        if word not in self._seed_matches(""):
            self.set_notice("That is not a valid word for this seed.")
            return
        self.seed_words.append(word)
        self.word_prefix = ""
        self.word_cursor = 0
        self.seed_grid_stick = True
        if len(self.seed_words) == self.seed_length:
            self.go("passphrase-ask")

    def _save_text(self):
        if not self.draft.strip():
            self.set_notice("Enter a descriptor, key expression, or seed words.")
            return
        try:
            added = self.session.add_text(self.draft)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.set_notice(added["message"])
        self.screen = "wallets" if self.session.wallets else "keys"
        self.menu = False

    def _seed_wallet_index(self, role: str):
        if self.selected_fp is None:
            return None
        for index, wallet in enumerate(self.session.wallets):
            if wallet.role == role and self.selected_fp in wallet.fingerprints and not wallet.multisig:
                return index
        return None

    def _seed_wallet_label(self, role: str, script: str) -> str:
        verb = "Go to" if self._seed_wallet_index(role) is not None else "Create a"
        return f"{verb} {script} SingleSig Wallet"

    def _make_wallet(self, kind: str, account: int = 0):
        role = SINGLESIG_NATIVE if kind == "wpkh" else SINGLESIG_TAPROOT
        existing = self._seed_wallet_index(role)
        if existing is not None:
            self._show_wallet(existing)
            return
        record = self.session.fingerprints.get(self.selected_fp)
        if record is None or not record.keys[0].has_seed:
            self.set_notice("Load a seed before creating this wallet.")
            return
        if account < 0 or account >= 0x80000000:
            self.set_notice("The account index is too large.")
            return
        derived = _public_for(self.session, self.selected_fp, role, account)
        origin = format_path(list(derived.path))[2:]
        text = f"{kind}([{self.selected_fp.hex()}/{origin}]{derived.xpub.to_string()}/<0;1>/*)"
        try:
            added = self.session.add_text(text)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.set_notice(added["message"])
        self._show_wallet(len(self.session.wallets) - 1)

    def _show_wallet(self, index: int):
        """Open a wallet with Bitcoin Wallets as the only screen behind it."""
        self.wallet_index = index
        self.scroll["wallet"] = 0
        self.back = ["wallets"]
        self.screen = "wallet"
        self.menu = False
        self.add_menu = False
        self.open_dropdown = None
        self._remember_wallet_accounts()

    def _remember_wallet_accounts(self):
        """The account a singlesig wallet had when it was opened. Leaving puts it back."""
        if self.wallet_index >= len(self.session.wallets):
            self._wallet_account_visit = None
            return
        wallet = self.session.wallets[self.wallet_index]
        if wallet.multisig:
            self._wallet_account_visit = None
            return
        self._wallet_account_visit = (id(wallet), dict(wallet.accounts))

    def _restore_wallet_accounts(self):
        visit = self._wallet_account_visit
        self._wallet_account_visit = None
        if visit is None or self.wallet_index >= len(self.session.wallets):
            return
        wallet = self.session.wallets[self.wallet_index]
        marker, saved = visit
        if marker != id(wallet) or wallet.multisig:
            return
        for fingerprint, account in saved.items():
            if fingerprint in wallet.accounts:
                wallet.accounts[fingerprint] = account

    def _make_xpub_wallet(self):
        record, key = self._stored_key()
        if record is None or key is None or key.xpub is None:
            self.set_notice("This key is no longer loaded.")
            return
        if key.role not in (SINGLESIG_NATIVE, SINGLESIG_TAPROOT):
            return
        existing = self._seed_wallet_index(key.role)
        if existing is not None:
            self._show_wallet(existing)
            return
        kind = "tr" if key.role == SINGLESIG_TAPROOT else "wpkh"
        origin = format_path(list(key.path))[2:]
        text = f"{kind}([{record.fingerprint.hex()}/{origin}]{key.xpub.to_string()}/<0;1>/*)"
        try:
            added = self.session.add_text(text)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        self.set_notice(added["message"])
        wallet = added.get("wallet")
        if wallet is not None and wallet in self.session.wallets:
            index = self.session.wallets.index(wallet)
        else:
            index = len(self.session.wallets) - 1
        self._show_wallet(index)

    def _delete_selected_wallet(self):
        try:
            self.session.delete_wallet(self.wallet_index)
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        if self.wallet_index >= len(self.session.wallets):
            self.wallet_index = max(0, len(self.session.wallets) - 1)
        _forget_qr_codes()
        self.back = []
        self.open_dropdown = None
        self.screen = "wallets"
        self.set_notice("The wallet was deleted.")

    def _delete_selected_key(self):
        if self.selected_fp is None:
            return
        try:
            self.set_notice(self.session.delete_key(self.selected_fp, self.selected_key_index))
        except SessionError as exc:
            self.set_notice(str(exc))
            return
        _forget_qr_codes()
        self.selected_fp = None
        self.screen = "keys"

    def _current_export(self) -> str:
        record, key = self._stored_key()
        if self.screen == "wallet" and self.session.wallets:
            return self.session.descriptor_text(self.wallet_index).split("#")[0]
        if key is not None and key.has_seed:
            return " ".join(key.mnemonic)
        if key is not None and key.xpub:
            return key.xpub.to_string()
        return "BigSigner"

    def _show_qr(self):
        if self.screen != "wallet":
            record, key = self._stored_key()
            if key is not None and key.has_seed:
                self._open_seed_show()
                return
            if key is not None and key.xpub is not None:
                self.qr_source = "stored"
                self._open_key_qr()
                return
        self._open_qr(self._current_export())

    def _open_descriptor_qr(self):
        if self.wallet_index >= len(self.session.wallets):
            self.set_notice("This wallet is no longer loaded.")
            return
        self.qr_text = self.session.descriptor_text(self.wallet_index)
        self.qr_kind = "descriptor"
        self.descriptor_format = 0
        self.qr_scroll = 0
        self.qr_zoom = None
        self.qr_hint_until = time.monotonic() + QR_HINT_HOLD
        self.go("qr")

    def _open_key_qr(self):
        self.qr_kind = "key"
        self.key_qr_index = 0
        self.qr_scroll = 0
        self.qr_zoom = None
        self.qr_hint_until = time.monotonic() + QR_HINT_HOLD
        self.go("qr")

    def _key_qr_formats(self) -> list[tuple[str, str]]:
        record = self.session.fingerprints.get(self.selected_fp)
        if self.qr_source == "derive":
            key = self._derived_key()
            if record is None or key is None or key.xpub is None:
                return []
        else:
            record, key = self._stored_key()
            if record is None or key is None or key.xpub is None:
                return []
        canonical = key.xpub.to_string()
        origin = format_path(list(key.path))[2:]
        expression = f"[{record.fingerprint.hex()}/{origin}]{canonical}"
        formats = [("Key Expression", expression), (f"{label_of(canonical)} only", canonical)]
        alternate = display_form(canonical, self.session.network, key.role)
        if alternate:
            formats.append((label_of(alternate), alternate))
        return formats

    def _step_qr_format(self, delta: int):
        if self.qr_kind == "descriptor":
            self.descriptor_format = (self.descriptor_format + delta) % len(DESCRIPTOR_FORMATS)
            self.qr_scroll = 0
            self.qr_zoom = None
            return
        self._step_key_qr(delta)

    def _descriptor_qr_payload(self) -> str:
        text = self.session.descriptor_text(self.wallet_index)
        self.qr_text = text
        if DESCRIPTOR_FORMATS[self.descriptor_format] == "plain":
            return text
        return descriptor_ur(self.session, self.wallet_index).upper()

    def _step_key_qr(self, delta: int):
        count = len(self._key_qr_formats())
        if count == 0:
            return
        self.key_qr_index = (self.key_qr_index + delta) % count
        self.qr_zoom = None
        self.qr_scroll = 0

    def qr_strip_due(self) -> bool:
        return self._qr_strip_due

    def qr_hint_holding(self) -> bool:
        layout = self._qr_scroll_layout()
        return layout is not None and self._qr_hint_active(layout)

    def preview_qr_frame(self) -> Image.Image | None:
        """The chevrons, or a loading line, while the scroll picture is not ready."""
        layout = self._qr_scroll_layout()
        if layout is None or self._qr_strip_matches(layout):
            self._qr_strip_due = False
            return None
        self._qr_strip_due = True
        self.dirty = None
        self.keyboard_top = None
        self._still_boxes = []
        self._expire_notice()
        frame = Frame()
        body = "hint" if self._qr_hint_active(layout) else "loading"
        self._paint_qr_page(frame, layout, body)
        if self.notice:
            self._toast(frame)
        self.hits = frame.hits
        return frame.image

    def build_qr_strip(self):
        """Draw the QR and its text once. Later scrolls crop this picture."""
        layout = self._qr_scroll_layout()
        self._qr_strip_due = False
        if layout is None or self._qr_strip_matches(layout):
            return
        face = font(TITLE_SIZE, mono=True)
        visible = layout.payload if layout.shown is None else layout.shown
        scratch = ImageDraw.Draw(Image.new("RGB", (1, 1)))
        if layout.shown is None:
            lines = wrap(scratch, visible, face, WIDTH - 2 * MARGIN)
        else:
            lines = _wrap_indented(scratch, visible, face, WIDTH - 2 * MARGIN)
        note_face = font(TITLE_SIZE)
        note_lines = wrap(scratch, layout.note, note_face, WIDTH - 2 * MARGIN) if layout.note else []
        note_gap = 16 if note_lines else 0
        content_h = (
            layout.qr_size
            + layout.text_gap
            + layout.line_h * len(lines)
            + note_gap
            + layout.line_h * len(note_lines)
            + layout.tail
        )
        height = max(content_h, layout.view_h)
        strip = Image.new("RGB", (WIDTH, height), layout.light)
        code = _qr_image(layout.payload, layout.qr_size, layout.light)
        strip.paste(code, ((WIDTH - layout.qr_size) // 2, 0))
        draw = ImageDraw.Draw(strip)
        text_y = layout.qr_size + layout.text_gap
        for line in lines:
            draw.text((MARGIN, text_y), line, font=face, fill=INK)
            text_y += layout.line_h
        if note_lines:
            text_y += note_gap
            for line in note_lines:
                draw.text((MARGIN, text_y), line, font=note_face, fill=MUTED)
                text_y += layout.line_h
        self._qr_strip = strip
        self._qr_strip_key = self._qr_strip_identity(layout)
        self.qr_scroll_max = max(0, content_h - layout.view_h)
        self.qr_scroll = max(0, min(self.qr_scroll, self.qr_scroll_max))

    def _draw_key_qr(self, frame: Frame):
        formats = self._key_qr_formats()
        if not formats:
            light = _qr_light(self.qr_brightness)
            frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
            frame.header("QR", "back")
            frame.text("This key is no longer loaded.", MARGIN, 140)
            return
        self._draw_scrolled_qr(frame)

    def _draw_descriptor_qr(self, frame: Frame):
        if self.wallet_index >= len(self.session.wallets):
            frame.header("Descriptor", "back")
            frame.text("This wallet is no longer loaded.", MARGIN, 140)
            return
        self._draw_scrolled_qr(frame)

    def _draw_scrolled_qr(self, frame: Frame):
        layout = self._qr_scroll_layout()
        if layout is None:
            return
        if self._qr_hint_active(layout):
            self._paint_qr_page(frame, layout, "hint")
            return
        if not self._qr_strip_matches(layout):
            self.build_qr_strip()
        self._paint_qr_page(frame, layout, "strip")

    def _qr_scroll_layout(self):
        if self.screen != "qr" or self.qr_zoom is not None or self.qr_kind not in ("key", "descriptor"):
            return None
        if self.qr_kind == "key":
            formats = self._key_qr_formats()
            if not formats:
                return None
            format_name, payload = formats[self.key_qr_index % len(formats)]
            shown = None
            note = None
            title = "QR & content"
            show_zoom = True
        else:
            if self.wallet_index >= len(self.session.wallets):
                return None
            payload = self._descriptor_qr_payload()
            shown = _pretty_descriptor(self.qr_text)
            wallet = self.session.wallets[self.wallet_index]
            note = MULTISIG_DESCRIPTOR_NOTE if wallet.multisig else None
            format_name = DESCRIPTOR_FORMAT_NAMES[self.descriptor_format]
            title = "Descriptor"
            show_zoom = False
        if show_zoom:
            zoom_y = HEIGHT - 88 - 12 - 64 if format_name else HEIGHT - 100
            bright_y = zoom_y - 12 - 52
        else:
            zoom_y = 0
            bright_y = HEIGHT - 88 - 12 - 52
        view_top = HEADER + 8
        view_bottom = bright_y - 4
        view_h = view_bottom - view_top
        line_h = TITLE_SIZE + 8
        text_gap = 4
        # The first text line is fully visible, and part of the next line is cut off.
        second_peek = 16
        qr_size = min(WIDTH - 2 * MARGIN, view_h - text_gap - line_h - second_peek)
        # A blank line after the key text, so scrolling to the end leaves empty space.
        tail = line_h if format_name else 0
        return SimpleNamespace(
            title=title,
            payload=payload,
            shown=shown,
            note=note,
            format_name=format_name,
            show_zoom=show_zoom,
            light=_qr_light(self.qr_brightness),
            view_top=view_top,
            view_bottom=view_bottom,
            view_h=view_h,
            qr_size=qr_size,
            zoom_y=zoom_y,
            bright_y=bright_y,
            line_h=line_h,
            text_gap=text_gap,
            tail=tail,
        )

    def _qr_strip_identity(self, layout):
        return (layout.payload, layout.shown, layout.note, layout.light, layout.qr_size, layout.tail)

    def _qr_strip_matches(self, layout) -> bool:
        return self._qr_strip is not None and self._qr_strip_key == self._qr_strip_identity(layout)

    def _qr_hint_active(self, layout) -> bool:
        if self.qr_hint_until is None or time.monotonic() >= self.qr_hint_until:
            return False
        # The chevrons stay up while the picture is built. A page that does not
        # scroll drops them once that picture exists.
        if not self._qr_strip_matches(layout):
            return True
        return self.qr_scroll_max > 0

    def _paint_qr_page(self, frame: Frame, layout, body: str):
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=layout.light)
        frame.header(layout.title, "back")
        hint = body == "hint"
        if hint:
            self._draw_scroll_hint(frame, layout.view_top, layout.view_bottom)
        elif body == "loading":
            frame.text("Preparing the QR code.", MARGIN, layout.view_top + 48, size=TITLE_SIZE)
        elif self._qr_strip is not None:
            top = self.qr_scroll
            window = self._qr_strip.crop((0, top, WIDTH, top + layout.view_h))
            frame.image.paste(window, (0, layout.view_top))
        self.qr_scroll_box = (
            None
            if hint or body == "loading" or self.qr_scroll_max <= 0
            else (0, layout.view_top, WIDTH, layout.view_bottom)
        )
        self._brightness_control(frame, layout.bright_y)
        if layout.show_zoom:
            frame.button(layout.zoom_y, "Zoom In", "zoom-in")
        if layout.format_name:
            self._format_switcher(frame, layout.format_name, "qr-form-prev", "qr-form-next")

    def _draw_scroll_hint(self, frame: Frame, top: int, bottom: int):
        face = font(36)
        lines = wrap(frame.draw, "Scroll to see more content", face, WIDTH - 2 * MARGIN)
        line_h = 46
        icon = 72
        gap = 20
        block = icon + gap + line_h * len(lines) + gap + icon
        y = top + max(0, (bottom - top - block) // 2)
        frame.glyph(Icons.CHEVRON_UP, WIDTH / 2, y + icon / 2, icon, INK)
        y += icon + gap
        for line in lines:
            width = frame.draw.textlength(line, font=face)
            frame.draw.text(((WIDTH - width) / 2, y), line, font=face, fill=INK)
            y += line_h
        frame.glyph(Icons.CHEVRON_DOWN, WIDTH / 2, y + gap + icon / 2, icon, INK)

    def _qr_payload(self):
        if self.screen == "seed-show":
            return self._seed_qr_payload()
        if self.qr_kind == "key":
            formats = self._key_qr_formats()
            if formats:
                return formats[self.key_qr_index % len(formats)][1]
        if self.qr_kind == "descriptor" and self.wallet_index < len(self.session.wallets):
            return self._descriptor_qr_payload()
        return self.qr_text

    def _open_qr(self, text: str):
        self.qr_text = text
        self.qr_kind = "plain"
        self.qr_zoom = None
        self.go("qr")

    def _move_zoom(self, direction: str):
        if direction == "in":
            self.qr_zoom = (0, 0)
            return
        x, y = self.qr_zoom or (0, 0)
        limit = max(0, len(_qr_modules(self._qr_payload())) - QR_ZOOM_COUNT)
        if direction == "left":
            x = max(0, x - 1)
        elif direction == "right":
            x = min(limit, x + 1)
        elif direction == "up":
            y = max(0, y - 1)
        elif direction == "down":
            y = min(limit, y + 1)
        self.qr_zoom = (x, y)

# Pip positions on a die face, as (column, row) in a 3 by 3 grid.
_DIE_PIPS = {
    "1": ((1, 1),),
    "2": ((0, 0), (2, 2)),
    "3": ((0, 0), (1, 1), (2, 2)),
    "4": ((0, 0), (2, 0), (0, 2), (2, 2)),
    "5": ((0, 0), (2, 0), (1, 1), (0, 2), (2, 2)),
    "6": ((0, 0), (2, 0), (0, 1), (2, 1), (0, 2), (2, 2)),
}


def _coin_pad_top() -> int:
    """Top of the coin buttons, kept just above Undo so the flip list has the space above."""
    undo_top = HEIGHT - 110
    return undo_top - 24 - 140


def _dice_pad_top() -> int:
    """Top of the dice buttons, kept just above Undo so the roll list has the space above."""
    button_height = 110
    gap = 12
    undo_top = HEIGHT - 110
    pad_height = 2 * button_height + gap
    return undo_top - 24 - pad_height


def _paint_die_face(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], digit: str):
    left, top, right, bottom = box
    pad_x = 26
    pad_y = 20
    radius = 10
    xs = (left + pad_x, (left + right) / 2, right - pad_x)
    ys = (top + pad_y, (top + bottom) / 2, bottom - pad_y)
    for column, row in _DIE_PIPS[digit]:
        cx = xs[column]
        cy = ys[row]
        draw.ellipse((cx - radius, cy - radius, cx + radius, cy + radius), fill=WHITE)


def _account_label(account: int) -> str:
    if account == 0:
        return "0 (default)"
    return str(account)


def _pretty_descriptor(text: str) -> str:
    """Show each key expression on its own indented line. The QR stays compact."""
    starts = _key_expression_starts(text)
    if not starts:
        return text
    out = []
    cursor = 0
    for index, start in enumerate(starts):
        out.append(text[cursor:start])
        out.append("\n  ")
        if index + 1 < len(starts):
            out.append(text[start:starts[index + 1]])
            cursor = starts[index + 1]
            continue
        end = start
        brackets = 0
        while end < len(text):
            if text[end] == "[":
                brackets += 1
            elif text[end] == "]":
                brackets -= 1
            elif text[end] == ")" and brackets == 0:
                break
            end += 1
        out.append(text[start:end])
        if end < len(text) and text[end] == ")":
            out.append("\n")
        out.append(text[end:])
        cursor = len(text)
    return "".join(out)


def _key_expression_starts(text: str) -> list[int]:
    starts = []
    cursor = 0
    while True:
        bracket = text.find("[", cursor)
        if bracket < 0:
            return starts
        fingerprint = text[bracket + 1:bracket + 9]
        if len(fingerprint) == 8 and all(char in "0123456789abcdefABCDEF" for char in fingerprint) and text[bracket + 9:bracket + 10] == "/":
            starts.append(bracket)
        cursor = bracket + 1


def _wrap_indented(draw, text: str, face, width: int) -> list[str]:
    """Keep a paragraph's leading spaces on its first line only."""
    lines = []
    for paragraph in text.split("\n"):
        if paragraph == "":
            lines.append("")
            continue
        indent_len = len(paragraph) - len(paragraph.lstrip(" "))
        indent = paragraph[:indent_len]
        body = paragraph[indent_len:]
        if not indent:
            lines.extend(wrap(draw, body, face, width))
            continue
        room = max(1, int(width - draw.textlength(indent, font=face)))
        first = ""
        index = 0
        while index < len(body) and draw.textlength(first + body[index], font=face) <= room:
            first += body[index]
            index += 1
        lines.append(indent + first)
        if index < len(body):
            lines.extend(wrap(draw, body[index:], face, width))
    return lines


def _filename_lines(draw, text: str, face, width: int, limit: int = 3) -> list[str]:
    """Wrap at the character that would overflow, for at most `limit` lines."""
    if draw.textlength(text, font=face) <= width:
        return [text]
    lines = []
    rest = text
    while rest and len(lines) < limit:
        if len(lines) < limit - 1 and _fit_count(draw, rest, face, width) < len(rest):
            count = _fit_count(draw, rest, face, width)
            lines.append(rest[:count])
            rest = rest[count:]
            continue
        if draw.textlength(rest, font=face) <= width:
            lines.append(rest)
            break
        count = _fit_count(draw, rest, face, width, "...")
        lines.append(rest[:count] + "...")
        break
    return lines or [""]


def _fit_count(draw, text: str, face, width: int, suffix: str = "") -> int:
    """How many leading characters fit, reserving room for `suffix`."""
    low, high = 0, len(text)
    while low < high:
        middle = (low + high + 1) // 2
        if draw.textlength(text[:middle] + suffix, font=face) <= width:
            low = middle
        else:
            high = middle - 1
    if low == 0 and text and not suffix:
        return 1
    return low


def _sd_row_height(line_count: int) -> int:
    block = line_count * TITLE_SIZE + max(0, line_count - 1) * 8
    return 20 + block + 24


def _one_line(frame: Frame, text: str, size: int, width: int, mono: bool = False) -> str:
    face = font(size, mono=mono)
    if frame.draw.textlength(text, font=face) <= width:
        return text
    while text and frame.draw.textlength(text + "...", font=face) > width:
        text = text[:-1]
    return text + "..."


def _zoom_grid_box() -> tuple[int, int, int]:
    """Left, top, and bottom of the zoomed module block, parked on the right."""
    grid_px = QR_ZOOM_COUNT * QR_ZOOM_CELL
    left = WIDTH - QR_ZOOM_RIGHT - grid_px
    top = HEADER + QR_ZOOM_BAND
    return left, top, top + grid_px


def _zoom_index_size(draw, digits: int, max_width: int, max_height: int) -> int:
    """Largest small monospace size at which this many eights fit in the slot."""
    sample = "8" * digits
    size = 26
    while size > 8:
        face = font(size, mono=True)
        box = draw.textbbox((0, 0), sample, font=face)
        if box[2] - box[0] <= max_width and box[3] - box[1] <= max_height:
            return size
        size -= 1
    return size


def _text_ink_width(draw, text: str, face) -> int:
    if not text:
        return 0
    left, _top, right, _bottom = draw.textbbox((0, 0), text, font=face)
    return right - left


_WORD_INDEX = {word: index for index, word in enumerate(WORDLIST)}


def _prefix_bounds(prefix: str) -> tuple[int, int]:
    """Indexes of the sorted word list that start with this prefix."""
    if not prefix:
        return 0, len(WORDLIST)
    start = bisect_left(WORDLIST, prefix)
    end = bisect_left(WORDLIST, prefix[:-1] + chr(ord(prefix[-1]) + 1))
    return start, end


def _phrase_checksum_ok(indexes: list[int]) -> bool:
    """True when these BIP39 word indexes have a valid checksum. No dictionary scan."""
    count = len(indexes)
    checksum_bits = count * 11 // 33
    acc = 0
    width = 0
    raw = bytearray()
    for index in indexes:
        acc = (acc << 11) | index
        width += 11
        while width >= 8:
            width -= 8
            raw.append((acc >> width) & 0xFF)
            acc &= (1 << width) - 1
    if width:
        raw.append((acc << (8 - width)) & 0xFF)
    remainder = checksum_bits % 8
    if remainder:
        checksum_length = checksum_bits // 8 + 1
        bits_to_ignore = 8 - remainder
    else:
        checksum_length = checksum_bits // 8
        bits_to_ignore = 0
    data, checksum = bytes(raw[:-checksum_length]), bytes(raw[-checksum_length:])
    computed = bytearray(hashlib.sha256(data).digest()[:checksum_length])
    computed[-1] &= 256 - (1 << (bits_to_ignore + 1) - 1)
    return checksum == bytes(computed)


def _grid_font_size(draw, width: int, max_size: int = SEED_CARD_FONT) -> int:
    """Largest monospace size at which a long numbered word still fits."""
    # "21. business" is the requested sample. "24. business" is wider, and a
    # 24-word seed uses that index, so the cell is sized for both.
    samples = ("21. business", "24. business")
    size = max_size
    while size > 10:
        face = font(size, mono=True)
        if all(draw.textlength(sample, font=face) <= width for sample in samples):
            return size
        size -= 1
    return size


@lru_cache(maxsize=8)
def _qr_modules(data):
    # Error correction L packs the most data into one code. The screen is large
    # enough to show that single dense code instead of several sparse ones.
    # Each payload is built once. Every redraw of the QR, scrolled, or zoomed
    # screen asks for the same code again.
    return qr_matrix(data)


def _qr_light(level: int) -> tuple[int, int, int]:
    return QR_BRIGHTNESS_STOPS[level]


@lru_cache(maxsize=4)
def _qr_image(data, box: int, light: tuple[int, int, int] = WHITE) -> Image.Image:
    """The code as a picture. Callers paste it and do not draw on it."""
    modules = _qr_modules(data)
    count = len(modules)
    shades = bytes(0 if dark else 255 for row in modules for dark in row)
    small = Image.frombytes("L", (count, count), shades)
    image = small.resize((box, box), Image.Resampling.NEAREST).convert("RGB")
    if light == WHITE:
        return image
    # Dark modules stay black. Everything else takes the chosen background.
    dark = image.convert("L").point(lambda value: 255 if value < 128 else 0)
    tinted = Image.new("RGB", image.size, light)
    tinted.paste((0, 0, 0), mask=dark)
    return tinted


def _forget_qr_codes():
    """Drop cached codes once what they showed is gone from the session."""
    _qr_modules.cache_clear()
    _qr_image.cache_clear()


def _is_text(payload: bytes) -> bool:
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def load_psbt(app: App, raw: str):
    if not app.session.wallets:
        raise ReviewError("Load a wallet before reviewing a transaction.")
    app.review = review_psbt(app.session, app.wallet_index, raw)
    app.psbt_text = raw
    app.screen = "review"


def sign_loaded(app: App, fingerprint: bytes):
    if app.review is None:
        raise ReviewError("Load a transaction first.")
    sign_with(app.session, app.wallet_index, app.review["psbt"], fingerprint)
    app.set_notice("A signature was added successfully.")

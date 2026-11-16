"""GPG key review, date selection, and signature/checksum result screens."""

import calendar
import re

from .. import sdcard
from ..gpg import GpgBackend, GpgError, KEY_LIMIT, Outcome
from ..qr import MAX_BYTE_PAYLOAD
from .canvas import BLUE, BODY_SIZE, HEADER, HEIGHT, INK, LINE, MARGIN, MUTED, PAPER, RED, TITLE_SIZE, WHITE, WIDTH, Frame, Icons, font, wrap


DATE_NOTE = "Some GPG signatures and keys expire. Set the current date so they can be checked correctly. The signer has no reliable clock."


class GpgUI:
    def __init__(self, app, backend=None):
        self.app = app
        self.backend = backend or GpgBackend()
        self.date = dict(year=2026, month=6, day=15)
        self.operation = "detached"
        self.edit_field = "year"
        self.draft = ""
        self.replace_digit = False
        self.date_error = ""
        self.key_data = b""
        self.outcome = Outcome(True)
        self.rows = []
        self.cards = []
        self.card_actions = []
        self.buttons = []
        self.content_end = HEADER
        self.selected = None
        self.armor = ""
        self.export_secret = False
        self.job = None
        self.future = None
        self.executor = None
        self.job_kind = ""
        self.work_shown = False
        self.painters = {"gpg": self.home, "gpg-formats": self.formats, "gpg-date": self.date_screen,
                         "gpg-number": self.number, "gpg-key-source": self.key_source,
                         "gpg-working": self.working, "gpg-keys": self.keys,
                         "gpg-key-details": self.details, "gpg-export": self.export_choice,
                         "gpg-key-qr": self.key_qr, "gpg-review": self.review, "gpg-result": self.result}

    def open(self):
        app = self.app
        if app.screen == "wallet":
            app._restore_wallet_accounts()
        self.key_data = b""
        app.back = []
        app.screen = "gpg"
        app.menu = app.add_menu = False
        app.open_dropdown = None

    def timestamp(self):
        date = self.date
        return calendar.timegm((date["year"], date["month"], date["day"], 0, 0, 0))

    def limits(self, field):
        return {"year": (1970, 9999), "month": (1, 12),
                "day": (1, calendar.monthrange(self.date["year"], self.date["month"])[1])}[field]

    def set_date(self, field, value):
        lo, hi = self.limits(field)
        if not lo <= value <= hi:
            self.date_error = f"{field.title()} must be between {lo} and {hi}."
            return False
        self.date[field] = value
        self.date["day"] = min(self.date["day"], self.limits("day")[1])
        self.date_error = ""
        return True

    def act(self, action):
        app = self.app
        if action == "gpg-list":
            self.start("list", self.backend.list_keys)
        elif action == "gpg-load":
            app.go("gpg-key-source")
        elif action == "gpg-formats":
            app.go("gpg-formats")
        elif action.startswith("gpg-date:"):
            self.operation = action.split(":", 1)[1]
            app.go("gpg-date")
        elif action.startswith("gpg-date-step:"):
            field, delta = action.split(":")[1:]
            self.set_date(field, self.date[field] + int(delta))
        elif action.startswith("gpg-date-edit:"):
            self.edit_field = action.split(":", 1)[1]
            self.draft = str(self.date[self.edit_field])
            self.replace_digit = True
            self.date_error = ""
            app.go("gpg-number")
        elif action.startswith("gpg-digit:"):
            digit = action.split(":", 1)[1]
            self.date_error = ""
            if digit == "clear":
                self.draft = ""
            elif digit == "delete":
                self.draft = self.draft[:-1]
            elif len(self.draft) < (4 if self.edit_field == "year" else 2) or self.replace_digit:
                self.draft = digit if self.replace_digit else self.draft + digit
            self.replace_digit = False
        elif action == "gpg-number-save":
            if self.draft and self.set_date(self.edit_field, int(self.draft)):
                app.back_one()
        elif action == "gpg-date-continue":
            app._open_sd("gpg-verify")
        elif action == "gpg-load-file":
            app._open_sd("gpg-key")
        elif action == "gpg-scan-key":
            app.scan_kind = "gpg-key"
            app.go("scan")
        elif action == "gpg-confirm-key":
            content = self.key_data
            self.key_data = b""
            self.start("import", lambda: self.backend.import_key(content), replace=True)
        elif action == "gpg-cancel-key":
            app.back_one()
        elif action.startswith("gpg-open:"):
            index = int(action.split(":", 1)[1])
            if not 0 <= index < len(self.outcome.keys):
                return
            self.selected = self.outcome.keys[index]
            self.build_details()
            app.scroll["gpg-key-details"] = 0
            app.go("gpg-key-details")
        elif action in ("gpg-export-public", "gpg-export-private"):
            key = self.selected
            if key is None:
                return
            secret = action == "gpg-export-private"
            if secret and not key.secret:
                return
            self.export_secret = secret
            fingerprint = key.fingerprint
            self.start("export", lambda: self.backend.export_key(fingerprint, secret=secret))
        elif action == "gpg-export-file":
            self._export_file()
        elif action == "gpg-export-qr":
            if len(self.armor.encode("utf-8")) > MAX_BYTE_PAYLOAD:
                return
            from .app import QR_BRIGHTNESS_DEFAULT

            app.qr_text = self.armor
            app.qr_brightness = QR_BRIGHTNESS_DEFAULT
            app.go("gpg-key-qr")

    def before_back(self):
        if self.app.screen == "gpg-review":
            self.key_data = b""

    def close_picker(self):
        app = self.app
        if app.screen in ("scan", "sd"):
            app.back_one()
        if app.screen == "storage":
            app.back_one()

    def accept_key(self, content):
        if isinstance(content, str):
            content = content.encode("utf-8")
        self.close_picker()
        if len(content) > KEY_LIMIT:
            self.show_error("The key content is larger than 1 MiB.")
            return
        self.key_data = content
        self.start("preview", lambda: self.backend.inspect_key(content))

    def accept_file(self, relative):
        app = self.app
        try:
            if app.sd_expect == "gpg-key":
                self.accept_key(sdcard.read_bytes(relative, storage=app.sd_storage, max_bytes=KEY_LIMIT))
                return
            if not relative.lower().endswith(".asc"):
                raise GpgError("Choose an .asc signature file.")
            storage, timestamp = app.sd_storage, self.timestamp()
            checksums = self.operation == "checksums"
            self.close_picker()
            self.start("verify", lambda: self.backend.verify(relative, storage, timestamp, checksums))
        except (sdcard.SdError, GpgError) as exc:
            self.show_error(str(exc))

    def start(self, kind, job, *, replace=False):
        self.job_kind, self.job = kind, job
        self.future = None
        self.work_shown = False
        if replace:
            self.app.screen = "gpg-working"
        else:
            self.app.go("gpg-working")

    def delay(self):
        return 0 if self.future is None else 0.2

    def advance(self):
        if self.app.screen != "gpg-working" or not self.work_shown:
            return
        try:
            if not self.backend.supported:
                raise GpgError("GPG commands are not available in the web emulator. Use the BigSigner device.")
            if self.future is None:
                from concurrent.futures import ThreadPoolExecutor

                if self.executor is None:
                    self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bigsigner-gpg")
                self.future = self.executor.submit(self.job)
                return
            if not self.future.done():
                return
            outcome = self.future.result()
        except Exception as exc:
            outcome = Outcome(False, str(exc))
        self.finish(outcome)

    def finish(self, outcome):
        self.job = self.future = None
        if self.executor is not None:
            self.executor.shutdown(wait=False)
            self.executor = None
        self.outcome = outcome
        if outcome.ok and self.job_kind == "export":
            self.armor = outcome.stages[-1].stdout if outcome.stages else ""
            self.app.screen = "gpg-export"
        elif outcome.ok and self.job_kind in ("list", "preview"):
            self.build_keys(summary=self.job_kind == "list")
            self.app.screen = "gpg-review" if self.job_kind == "preview" else "gpg-keys"
        else:
            self.key_data = b""
            self.build_result()
            self.app.screen = "gpg-result"
        self.app.scroll[self.app.screen] = 0
        self.app._arm_search_touch_quiet()

    def show_error(self, message):
        self.outcome = Outcome(False, message)
        self.build_result()
        self.app.go("gpg-result")
        self.app.scroll["gpg-result"] = 0

    def home(self, frame):
        frame.header("GPG", "menu")
        y = HEADER + 24
        version = self.backend.version_line()
        if version:
            face = font(28, mono=True)
            line_width = frame.draw.textlength(version, font=face)
            y = frame.text(version, (WIDTH - line_width) / 2, HEADER + 16, size=28, fill=MUTED, mono=True) + 8
        y = frame.button(y, "List GPG Keys", "gpg-list")
        y = frame.button(y, "Load GPG Key", "gpg-load")
        y = frame.button(y, "Verify Signature", "gpg-formats")
        frame.text("GPG keys stay in RAM and are cleared on reboot.", MARGIN, y + 12, size=28, fill=MUTED)

    def formats(self, frame):
        frame.header("Verify Signature", "back")
        y = frame.button(HEADER + 24, "Detached Signature", "gpg-date:detached")
        y = frame.text("Example: release.zip + release.zip.asc", MARGIN, y, size=28, fill=MUTED)
        y = frame.button(y + 24, "Signed Checksum File", "gpg-date:checksums")
        frame.text("Example: release.tar.gz + SHASUMS.asc, with or without SHASUMS.", MARGIN, y, size=28, fill=MUTED)

    def date_screen(self, frame):
        app = self.app
        frame.header("Date", "back")
        y = frame.text(DATE_NOTE, MARGIN, HEADER + 16, size=28)
        y += 16
        for name in ("year", "month", "day"):
            lo, hi = self.limits(name)
            app._brightness_button(frame, (MARGIN, y, MARGIN + 64, y + 64), "-", self.date[name] > lo, f"gpg-date-step:{name}:-1")
            app._brightness_button(frame, (WIDTH - MARGIN - 64, y, WIDTH - MARGIN, y + 64), "+", self.date[name] < hi, f"gpg-date-step:{name}:1")
            label = name.title() + ": "
            value = str(self.date[name]) if name == "year" else f"{self.date[name]:02d}"
            face = font(TITLE_SIZE)
            x = (WIDTH - frame.draw.textlength(label + value, font=face)) / 2
            frame.text(label, x, y + 10, size=TITLE_SIZE, fill=MUTED)
            frame.text(value, x + frame.draw.textlength(label, font=face), y + 10, size=TITLE_SIZE)
            frame.hit((MARGIN + 76, y, WIDTH - MARGIN - 76, y + 64), f"gpg-date-edit:{name}", name.title())
            y += 80
        frame.text("UTC · 00:00:00", MARGIN, y, size=24, fill=MUTED)
        frame.button(HEIGHT - 110, "Continue", "gpg-date-continue")

    def number(self, frame):
        frame.header("Set " + self.edit_field.title(), "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 96)
        frame.draw.rounded_rectangle(box, radius=12, fill=WHITE, outline=LINE, width=2)
        frame.text(self.draft, MARGIN + 16, HEADER + 22, size=48, mono=True)
        lo, hi = self.limits(self.edit_field)
        message = self.date_error or f"{self.edit_field.title()} (UTC): {lo} to {hi}."
        frame.text(message, MARGIN, HEADER + 120, size=28, fill=RED if self.date_error else MUTED)
        gap, width = 12, (WIDTH - 2 * MARGIN - 24) // 3
        for i, digit in enumerate(("1", "2", "3", "4", "5", "6", "7", "8", "9", "clear", "0", "delete")):
            x, y = MARGIN + i % 3 * (width + gap), 304 + i // 3 * 84
            frame.button_box((x, y, x + width, y + 72), {"clear": "Clear", "delete": "Del"}.get(digit, digit), "gpg-digit:" + digit)
        frame.button(HEIGHT - 110, "Save", "gpg-number-save", enabled=bool(self.draft))

    def key_source(self, frame):
        frame.header("Load GPG Key", "back")
        y = frame.button(HEADER + 24, "Load from File", "gpg-load-file", icon=Icons.FILE, awesome=True)
        frame.button(y, "Scan QR Code", "gpg-scan-key", icon=Icons.CAMERA, awesome=True)

    def working(self, frame):
        frame.header("GPG")
        labels = {"list": "Listing GPG Keys…", "preview": "Reading GPG Key…", "import": "Importing GPG Key…",
                  "verify": "Verifying Signature…", "export": "Exporting Private Key…" if self.export_secret else "Exporting Public Key…"}
        frame.text(labels.get(self.job_kind, "Working…"), MARGIN, HEADER + 40, size=BODY_SIZE)
        self.work_shown = True

    def reset_layout(self):
        self.rows, self.cards, self.card_actions, self.buttons = [], [], [], []
        self.content_end = HEADER + 20
        self.scratch = Frame()

    def add_button(self, text, action):
        height = self.scratch.button_height(text)
        self.buttons.append((self.content_end, text, action, height))
        self.content_end += height + 12

    def add_text(self, text, *, fill=INK, size=TITLE_SIZE, mono=False, center=False, inset=0):
        face = font(size, mono=mono)
        for paragraph in str(text).split("\n"):
            for line in wrap(self.scratch.draw, paragraph, face, WIDTH - 2 * (MARGIN + inset)):
                x = (WIDTH - self.scratch.draw.textlength(line, font=face)) / 2 if center else MARGIN + inset
                self.rows.append((x, self.content_end, line, size, fill, mono))
                self.content_end += size + 8

    def add_labeled_value(self, label, value, *, value_fill=INK, size=28):
        face = font(size)
        self.rows.append((MARGIN, self.content_end, label, size, MUTED, False))
        value_x = MARGIN + self.scratch.draw.textlength(label + " ", font=face)
        self.rows.append((value_x, self.content_end, value, size, value_fill, False))
        self.content_end += size + 8

    def add_output(self, text, *, fill=INK, checksums=False):
        for line in text.splitlines():
            color = RED if checksums and re.search(r"\bFAILED\b", line) else fill
            self.add_text(line, fill=color, size=28, mono=True)

    def build_keys(self, *, summary=False):
        self._key_cards(self.outcome.keys, summary=summary, open_cards=summary)
        self._append_stderr()

    def build_details(self):
        key = self.selected
        self._key_cards([] if key is None else [key], summary=False, open_cards=False)
        if key is None:
            return
        self.content_end += 8
        self.add_button("Export Public Key", "gpg-export-public")
        if key.secret:
            self.add_button("Export Private Key", "gpg-export-private")

    def _key_cards(self, keys, *, summary, open_cards):
        self.reset_layout()
        if not keys and summary:
            self.add_text("No GPG keys are loaded.")
        fields = ("User ID:", "Fingerprint:", "Key ID:")
        if not summary:
            fields += ("Algorithm:", "Created:", "Expires:", "Validity:")
        for index, key in enumerate(keys):
            values = {"User ID:": "\n".join(key.user_ids) or "None", "Fingerprint:": key.fingerprint,
                      "Key ID:": key.key_id, "Algorithm:": key.algorithm, "Created:": key.created,
                      "Expires:": key.expires, "Validity:": key.validity}
            top = self.content_end
            self.content_end += 16
            for label in fields:
                self.add_text(label, fill=MUTED, inset=16)
                if label == "Fingerprint:":
                    groups = [values[label][i:i + 4] for i in range(0, len(values[label]), 4)]
                    for i in range(0, len(groups), 4):
                        self.add_text(" ".join(groups[i:i + 4]), mono=True, center=True, inset=16)
                else:
                    self.add_text(values[label], mono=label in ("Key ID:", "Created:", "Expires:"), inset=16)
                self.content_end += 8
            if not summary and key.subkeys:
                self.add_text("Subkeys:", fill=MUTED, inset=16)
                for subkey in key.subkeys:
                    self.add_text(subkey["key_id"], mono=True, inset=16)
            if not summary and key.secret:
                self.content_end += 8
                self.add_text("This file contains a private key.", fill=RED, inset=16)
            self.content_end += 8
            self.cards.append((MARGIN, top, WIDTH - MARGIN, self.content_end))
            self.card_actions.append(f"gpg-open:{index}" if open_cards else "")
            self.content_end += 16

    def _append_stderr(self):
        for stage in self.outcome.stages:
            if stage.stderr:
                self.add_text("stderr:", fill=MUTED, size=28)
                self.add_output(stage.stderr, fill=RED)

    def _export_file(self):
        app = self.app
        key = self.selected
        if key is None or not self.armor:
            return
        app.export_label = "GPG Private Key" if self.export_secret else "GPG Public Key"
        app.export_text = self.armor
        app.export_binary = False
        app.export_return = "gpg-key-details"
        app.export_back = list(app.back[:-1]) if app.back and app.back[-1] == "gpg-key-details" else list(app.back)
        app.sd_mode = "export"
        app.sd_dir = ""
        app.scroll["sd"] = 0
        app.go("storage")

    def build_result(self):
        self.reset_layout()
        if self.outcome.message:
            self.add_text(self.outcome.message, fill=RED if not self.outcome.ok else INK)
            self.content_end += 16
        for stage in self.outcome.stages:
            self.add_text(stage.name, fill=MUTED)
            status = f"success ({stage.returncode})" if stage.returncode == 0 else f"failure ({stage.returncode})"
            self.add_labeled_value("Exit Status:", status, value_fill=INK if stage.returncode == 0 else RED)
            if stage.stdout:
                self.add_text("stdout:", fill=MUTED, size=28)
                self.add_output(stage.stdout, checksums=stage.checksums)
            if stage.stderr:
                self.add_text("stderr:", fill=MUTED, size=28)
                self.add_output(stage.stderr, fill=RED)
            self.content_end += 20

    def content(self, frame, title, review=False):
        offset = self.app._scroll_offset(self.app.screen, self.content_end, clearance=132 if review else 20)
        bottom = HEIGHT - 128 if review else HEIGHT
        for (left, top, right, end), action in zip(self.cards, self.card_actions):
            if end - offset > HEADER and top - offset < bottom:
                frame.draw.rounded_rectangle((left, top - offset, right, end - offset), radius=12, fill=WHITE, outline=LINE, width=2)
                if action:
                    frame.hit((left, max(top - offset, HEADER), right, min(end - offset, bottom)), action, "GPG Key")
        for y, text, action, height in self.buttons:
            top = y - offset
            if top >= HEADER and top < bottom:
                frame.button(top, text, action)
        for x, y, text, size, fill, mono in self.rows:
            y -= offset
            if y + size + 8 > HEADER and y < bottom:
                frame.text(text, x, y, size=size, fill=fill, mono=mono)
        if review:
            frame.draw.rectangle((0, bottom, WIDTH, HEIGHT), fill=PAPER)
            self.app._dialog_button(frame, (MARGIN, HEIGHT - 96, 234, HEIGHT - 24), "Cancel", "gpg-cancel-key", (132, 138, 148))
            self.app._dialog_button(frame, (246, HEIGHT - 96, WIDTH - MARGIN, HEIGHT - 24), "Confirm", "gpg-confirm-key", BLUE)
        frame.header(title, "back")

    def keys(self, frame):
        self.content(frame, "List GPG Keys")

    def details(self, frame):
        self.content(frame, "GPG Key")

    def export_choice(self, frame):
        title = "Export Private Key" if self.export_secret else "Export Public Key"
        frame.header(title, "back")
        y = frame.button(HEADER + 24, "Export to File", "gpg-export-file")
        too_big = len(self.armor.encode("utf-8")) > MAX_BYTE_PAYLOAD
        y = frame.button(y, "Show QR Code", "gpg-export-qr", enabled=not too_big)
        if too_big:
            frame.text("The key is too large for a single QR code.", MARGIN, y, size=28, fill=MUTED)

    def key_qr(self, frame):
        from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

        light = _qr_light(QR_BRIGHTNESS_DEFAULT)
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
        top = HEADER + 24
        image = _qr_image(self.armor, WIDTH - 2 * MARGIN, light)
        frame.image.paste(image, (MARGIN, top))
        self.app._brightness_control(frame, top + image.height + 24)
        frame.header("Private Key" if self.export_secret else "Public Key", "back")

    def review(self, frame):
        self.content(frame, "Load GPG Key", review=True)

    def result(self, frame):
        self.content(frame, "Success" if self.outcome.ok else "Error")

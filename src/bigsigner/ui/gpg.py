"""GPG key review, date selection, and signature/checksum result screens."""

import calendar
import os
import re
import time

from .. import sdcard
from ..entropy import camera_digest
from ..gpg import GpgBackend, GpgError, KEY_LIMIT, Outcome
from ..qr import MAX_BYTE_PAYLOAD
from .canvas import BLUE, BODY_SIZE, HEADER, HEIGHT, INK, LINE, MARGIN, MUTED, PAPER, RED, TITLE_SIZE, WARNING, WHITE, WIDTH, Frame, Icons, font, wrap


DATE_NOTE = "Some GPG signatures and keys expire. Set the current date so they can be checked correctly. The air-gapped device has no reliable clock."
SUBKEY_TIME_NOTE = "This time is written on the new subkey. The air-gapped device has no reliable clock."
EXPIRE_NOTE = "This is the UTC time when the subkey expires."
SUBKEY_NOTE = "Adding a subkey requires the certificate's private key."
PRIVATE_NOTE = "Contains a private key"
_USAGE = (("c", "Certification"), ("s", "Signing"), ("e", "Encryption"), ("a", "Authentication"))
_SUBKEY_ALGOS = (("ed25519", "Ed25519"), ("cv25519", "Curve25519"), ("rsa3072", "RSA-3072"), ("rsa4096", "RSA-4096"))
_SUBKEY_USAGES = (("sign", "Signing"), ("encr", "Encryption"), ("auth", "Authentication"))


class GpgUI:
    def __init__(self, app, backend=None):
        self.app = app
        self.backend = backend or GpgBackend()
        self.date = dict(year=2026, month=6, day=15)
        self.subkey_clock = dict(year=2026, month=6, day=15, hour=0, minute=0)
        self.clock = "date"
        self.subkey_algo = "ed25519"
        self.subkey_usage = "sign"
        self.subkey_expire = None
        self.expire_clock = dict(year=2027, month=6, day=15, hour=0)
        self.details_back = []
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
        self.export_subkey = False
        self.export_fingerprint = ""
        self.export_title = ""
        self.job = None
        self.future = None
        self.executor = None
        self.job_kind = ""
        self.work_shown = False
        self.painters = {"gpg": self.home, "gpg-formats": self.formats, "gpg-date": self.date_screen,
                         "gpg-subkey-time": self.date_screen, "gpg-subkey-expire": self.date_screen,
                         "gpg-number": self.number,
                         "gpg-key-source": self.key_source, "gpg-working": self.working, "gpg-keys": self.keys,
                         "gpg-key-details": self.details, "gpg-export": self.export_choice,
                         "gpg-key-qr": self.key_qr, "gpg-review": self.review, "gpg-result": self.result,
                         "gpg-subkey-options": self.subkey_options}

    def open(self):
        app = self.app
        if app.screen == "wallet":
            app._restore_wallet_accounts()
        self.key_data = b""
        app.back = []
        app.screen = "gpg"
        app.menu = app.add_menu = False
        app.open_dropdown = None

    def active_clock(self):
        if self.clock == "subkey":
            return self.subkey_clock
        if self.clock == "expire":
            return self.expire_clock
        return self.date

    def timestamp(self):
        date = self.date
        return calendar.timegm((date["year"], date["month"], date["day"], 0, 0, 0))

    def subkey_timestamp(self):
        clock = self.subkey_clock
        return calendar.timegm((clock["year"], clock["month"], clock["day"], clock["hour"], clock["minute"], 0))

    def limits(self, field):
        clock = self.active_clock()
        if field == "hour":
            return (0, 23)
        if field == "minute":
            return (0, 59)
        if field == "year":
            return (1970, 9999)
        if field == "month":
            return (1, 12)
        return (1, calendar.monthrange(clock["year"], clock["month"])[1])

    def set_date(self, field, value):
        lo, hi = self.limits(field)
        if not lo <= value <= hi:
            self.date_error = f"{field.title()} must be between {lo} and {hi}."
            return False
        clock = self.active_clock()
        clock[field] = value
        clock["day"] = min(clock["day"], self.limits("day")[1])
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
            self.clock = "date"
            app.go("gpg-date")
        elif action.startswith("gpg-date-step:"):
            field, delta = action.split(":")[1:]
            clock = self.active_clock()
            self.set_date(field, clock[field] + int(delta))
        elif action.startswith("gpg-date-edit:"):
            self.edit_field = action.split(":", 1)[1]
            self.draft = str(self.active_clock()[self.edit_field])
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
            if self.clock == "subkey":
                self._start_add_subkey()
            else:
                app._open_sd("gpg-verify")
        elif action == "gpg-add-subkey":
            key = self.selected
            if key is None or not key.secret_available:
                return
            self.details_back = list(app.back)
            app.camera_frames = []
            app.camera_final = b""
            app.camera_purpose = "gpg"
            app.go("camera")
        elif action == "gpg-subkey-time":
            self.clock = "subkey"
            app.open_dropdown = None
            app.go("gpg-subkey-time")
        elif action == "gpg-subkey-expire":
            self.clock = "expire"
            app.open_dropdown = None
            if self.subkey_expire:
                self.expire_clock = dict(self.subkey_expire)
            else:
                self.expire_clock = self._draft_expiration()
            app.go("gpg-subkey-expire")
        elif action == "gpg-expire-clear":
            self.subkey_expire = None
            app.back_one()
        elif action == "gpg-expire-save":
            self.subkey_expire = dict(self.expire_clock)
            app.back_one()
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
        elif action in ("gpg-export-public", "gpg-export-private") or action.startswith("gpg-export-subkey:"):
            key = self.selected
            if key is None:
                return
            subkey = None
            if action.startswith("gpg-export-subkey:"):
                index = int(action.split(":", 1)[1])
                if not 0 <= index < len(key.subkeys) or not key.subkeys[index].get("secret"):
                    return
                subkey = key.subkeys[index]
                fingerprint = subkey["fingerprint"]
            else:
                if action == "gpg-export-private" and not key.secret_available:
                    return
                fingerprint = key.fingerprint
            self.export_subkey = subkey is not None
            self.export_secret = self.export_subkey or action == "gpg-export-private"
            self.export_fingerprint = fingerprint
            if subkey is None:
                self.export_title = "Export Private Key" if self.export_secret else "Export Public Key"
            else:
                self.export_title = "Export Private Subkey"
            self.start("export", lambda: self.backend.export_key(fingerprint, secret=self.export_secret, subkey=self.export_subkey))
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
        elif outcome.ok and self.job_kind == "add-subkey":
            fingerprint = self.selected.fingerprint if self.selected else ""
            match = next((key for key in outcome.keys if key.fingerprint == fingerprint), None)
            if match is not None:
                self.selected = match
            self.build_details()
            self.app.back = list(self.details_back)
            self.app.screen = "gpg-key-details"
            self.app.set_notice("The subkey was added.")
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
        kind = self.clock if self.clock in ("subkey", "expire") else "date"
        notes = {"subkey": SUBKEY_TIME_NOTE, "expire": EXPIRE_NOTE, "date": DATE_NOTE}
        fields = {"subkey": ("year", "month", "day", "hour", "minute"),
                  "expire": ("year", "month", "day", "hour"),
                  "date": ("year", "month", "day")}
        footers = {"subkey": "Seconds are 00 UTC.", "expire": "Minutes are 00 UTC.", "date": "UTC · 00:00:00"}
        frame.header({"subkey": "Time", "expire": "Expires", "date": "Date"}[kind], "back")
        y = frame.text(notes[kind], MARGIN, HEADER + 16, size=28)
        y += 16
        clock = self.active_clock()
        for name in fields[kind]:
            lo, hi = self.limits(name)
            app._brightness_button(frame, (MARGIN, y, MARGIN + 64, y + 64), "-", clock[name] > lo, f"gpg-date-step:{name}:-1")
            app._brightness_button(frame, (WIDTH - MARGIN - 64, y, WIDTH - MARGIN, y + 64), "+", clock[name] < hi, f"gpg-date-step:{name}:1")
            label = name.title() + ": "
            value = str(clock[name]) if name == "year" else f"{clock[name]:02d}"
            face = font(TITLE_SIZE)
            x = (WIDTH - frame.draw.textlength(label + value, font=face)) / 2
            frame.text(label, x, y + 10, size=TITLE_SIZE, fill=MUTED)
            frame.text(value, x + frame.draw.textlength(label, font=face), y + 10, size=TITLE_SIZE)
            frame.hit((MARGIN + 76, y, WIDTH - MARGIN - 76, y + 64), f"gpg-date-edit:{name}", name.title())
            y += 80
        frame.text(footers[kind], MARGIN, y, size=24, fill=MUTED)
        if kind == "expire":
            set_top = HEIGHT - 110
            clear_top = set_top - 16 - frame.button_height("No Expiration")
            frame.button(clear_top, "No Expiration", "gpg-expire-clear")
            frame.button(set_top, "Set Expiration", "gpg-expire-save")
        else:
            frame.button(HEIGHT - 110, "Add a Subkey" if kind == "subkey" else "Continue", "gpg-date-continue")

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
                  "verify": "Verifying Signature…", "export": self._export_progress(), "add-subkey": "Adding a Subkey…"}
        frame.text(labels.get(self.job_kind, "Working…"), MARGIN, HEADER + 40, size=BODY_SIZE)
        self.work_shown = True

    def reset_layout(self):
        self.rows, self.cards, self.card_actions, self.buttons = [], [], [], []
        self.content_end = HEADER + 20
        self.scratch = Frame()

    def add_button(self, text, action, *, inset=0, enabled=True):
        height = self.scratch.button_height(text, inset=inset)
        self.buttons.append((self.content_end, text, action, height, inset, enabled))
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

    def _subkey_export_label(self, sub):
        letters = set(sub.get("capabilities", "").lower())
        roles = [name for letter, name in (("s", "Signing"), ("e", "Encryption"), ("a", "Authentication")) if letter in letters]
        if not roles:
            return "Export Private Subkey"
        if len(roles) == 1:
            role = roles[0]
        elif len(roles) == 2:
            role = f"{roles[0]} and {roles[1]}"
        else:
            role = ", ".join(roles[:-1]) + ", and " + roles[-1]
        return f"Export Private {role} Subkey"

    def _export_title(self):
        return self.export_title or ("Export Private Key" if self.export_secret else "Export Public Key")

    def _export_progress(self):
        title = self._export_title()
        return ("Exporting " + title[len("Export "):] if title.startswith("Export ") else title) + "…"

    def usage_text(self, capabilities):
        names = [name for letter, name in _USAGE if letter in capabilities]
        if not names:
            return "Unknown"
        if len(names) == 1:
            return names[0]
        if len(names) == 2:
            return f"{names[0]} and {names[1]}"
        return ", ".join(names[:-1]) + ", and " + names[-1]

    def _add_fingerprint(self, fingerprint):
        groups = [fingerprint[i:i + 4] for i in range(0, len(fingerprint), 4)]
        for start in range(0, len(groups), 4):
            self.add_text(" ".join(groups[start:start + 4]), mono=True, center=True, inset=16)

    def _add_same_line(self, label, value, *, inset=16, size=TITLE_SIZE):
        face = font(size)
        x = MARGIN + inset
        self.rows.append((x, self.content_end, label, size, MUTED, False))
        self.rows.append((x + self.scratch.draw.textlength(label + " ", font=face), self.content_end, value, size, INK, False))
        self.content_end += size + 8

    def _add_value(self, label, value, *, mono=False):
        if label == "Usage:" and self.scratch.draw.textlength(f"{label} {value}", font=font(TITLE_SIZE)) <= WIDTH - 2 * (MARGIN + 16):
            self._add_same_line(label, value)
            return
        self.add_text(label, fill=MUTED, inset=16)
        if label == "Fingerprint:":
            self._add_fingerprint(value)
        else:
            self.add_text(value, mono=mono, inset=16)
        self.content_end += 8

    def _card(self, values, fields, *, open_action="", private=False, heading="", buttons=(), note=""):
        top = self.content_end
        self.content_end += 16
        if heading:
            self.add_text(heading, fill=MUTED, inset=16)
            self.content_end += 8
        for label in fields:
            self._add_value(label, values[label], mono=label in ("Key ID:", "Created:", "Expires:"))
            if label == "Fingerprint:" and private:
                self.add_text(PRIVATE_NOTE, fill=WARNING, center=True, inset=16)
                self.content_end += 8
        if buttons:
            self.content_end += 4
            for item in buttons:
                text, action = item[0], item[1]
                enabled = item[2] if len(item) > 2 else True
                self.add_button(text, action, inset=16, enabled=enabled)
            if note:
                self.add_text(note, fill=MUTED, size=28, inset=16)
        self.content_end += 8
        self.cards.append((MARGIN, top, WIDTH - MARGIN, self.content_end))
        self.card_actions.append(open_action)
        self.content_end += 16

    def build_details(self):
        key = self.selected
        self._key_cards([] if key is None else [key], summary=False, open_cards=False, exports=True)

    def _key_cards(self, keys, *, summary, open_cards, exports=False):
        self.reset_layout()
        if not keys and summary:
            self.add_text("No GPG keys are loaded.")
        fields = ("User ID:", "Fingerprint:", "Key ID:")
        if not summary:
            fields += ("Algorithm:", "Usage:", "Created:", "Expires:", "Validity:")
        for index, key in enumerate(keys):
            values = {"User ID:": "\n".join(key.user_ids) or "None", "Fingerprint:": key.fingerprint,
                      "Key ID:": key.key_id, "Algorithm:": key.algorithm, "Usage:": self.usage_text(key.capabilities),
                      "Created:": key.created, "Expires:": key.expires, "Validity:": key.validity}
            buttons = []
            note = ""
            if exports:
                buttons.append(("Export Public Key", "gpg-export-public"))
                if key.secret_available:
                    buttons.append(("Export Private Key", "gpg-export-private"))
                buttons.append(("Add a Subkey", "gpg-add-subkey", bool(key.secret_available)))
                if not key.secret_available:
                    note = SUBKEY_NOTE
            self._card(values, fields, open_action=f"gpg-open:{index}" if open_cards else "",
                       private=not summary and key.contains_private, buttons=buttons, note=note)
            if not summary:
                labels = [self._subkey_export_label(sub) if sub.get("secret") else "" for sub in key.subkeys]
                for sub_index, sub in enumerate(key.subkeys):
                    buttons = []
                    if exports and sub.get("secret"):
                        label = labels[sub_index]
                        if labels.count(label) > 1 and sub.get("key_id"):
                            label = f"{label} {sub['key_id']}"
                        buttons.append((label, f"gpg-export-subkey:{sub_index}"))
                    self._card({"Usage:": self.usage_text(sub.get("capabilities", "")), "Algorithm:": sub.get("algorithm", ""),
                                "Fingerprint:": sub.get("fingerprint", ""), "Key ID:": sub.get("key_id", ""),
                                "Created:": sub.get("created", ""), "Expires:": sub.get("expires", ""),
                                "Validity:": sub.get("validity", "")},
                               ("Usage:", "Algorithm:", "Fingerprint:", "Key ID:", "Created:", "Expires:", "Validity:"),
                               private=bool(sub.get("contains_private")), heading="Subkey", buttons=buttons)

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
        if self.export_subkey:
            app.export_label = "GPG Private Subkey"
        elif self.export_secret:
            app.export_label = "GPG Private Key"
        else:
            app.export_label = "GPG Public Key"
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
        for y, text, action, _height, inset, enabled in self.buttons:
            top = y - offset
            if top >= HEADER and top < bottom:
                frame.button(top, text, action, inset=inset, enabled=enabled)
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
        title = self._export_title()
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
        frame.header(self._export_title().removeprefix("Export "), "back")

    def subkey_options(self, frame):
        app = self.app
        frame.header("Add a Subkey", "back")
        y = HEADER + 16
        y = self._choice(frame, y, "Algorithm", "gpg-algo", _SUBKEY_ALGOS, self.subkey_algo)
        usages = self._usage_options()
        y = self._choice(frame, y + 16, "Usage", "gpg-usage", usages, self.subkey_usage, enabled=len(usages) > 1)
        y = self._expire_field(frame, y + 16)
        frame.button(max(y + 24, HEIGHT - 110), "Continue", "gpg-subkey-time")
        if app.open_dropdown == "gpg-algo":
            app._dropdown_menu(frame, self._choice_box, "gpg-algo", _SUBKEY_ALGOS, self.subkey_algo)
        elif app.open_dropdown == "gpg-usage" and len(usages) > 1:
            app._dropdown_menu(frame, self._choice_box, "gpg-usage", usages, self.subkey_usage)

    def _choice(self, frame, y, label, name, options, selected, *, enabled=True):
        y = frame.text(label, MARGIN, y, size=TITLE_SIZE, fill=MUTED)
        shown = dict(options)[selected]
        box = self.app._dropdown_field(frame, y + 8, name, shown, enabled=enabled)
        if self.app.open_dropdown == name:
            self._choice_box = box
        return box[3]

    def _expire_field(self, frame, y):
        y = frame.text("Expires", MARGIN, y, size=TITLE_SIZE, fill=MUTED)
        shown = self.expire_label()
        top = y + 8
        height = 64
        box = (MARGIN, top, WIDTH - MARGIN, top + height)
        frame.draw.rounded_rectangle(box, radius=14, fill=WHITE, outline=LINE, width=2)
        face = font(TITLE_SIZE)
        left, ascent, _right, descent = frame.draw.textbbox((0, 0), shown, font=face)
        text_x = MARGIN + 20 - left
        text_y = top + (height - (descent - ascent)) / 2 - ascent
        frame.draw.text((text_x, text_y), shown, font=face, fill=INK)
        frame.mark(shown, frame.draw.textbbox((text_x, text_y), shown, font=face))
        frame.hit(box, "gpg-subkey-expire", shown)
        return box[3]

    def expire_label(self):
        clock = self.subkey_expire
        if not clock:
            return "No Expiration"
        return f"{clock['year']:04d}-{clock['month']:02d}-{clock['day']:02d} {clock['hour']:02d}:00 UTC"

    def expire_argument(self):
        clock = self.subkey_expire
        if not clock:
            return "never"
        return f"{clock['year']:04d}{clock['month']:02d}{clock['day']:02d}T{clock['hour']:02d}0000"

    def _draft_expiration(self):
        created = self.subkey_clock
        year = created["year"] + 1
        month = created["month"]
        day = min(created["day"], calendar.monthrange(year, month)[1])
        return dict(year=year, month=month, day=day, hour=created["hour"])

    def _usage_options(self):
        if self.subkey_algo == "cv25519":
            return (("encr", "Encryption"),)
        if self.subkey_algo == "ed25519":
            return tuple(item for item in _SUBKEY_USAGES if item[0] != "encr")
        return _SUBKEY_USAGES

    def choose(self, name, key):
        if name == "gpg-algo" and key in dict(_SUBKEY_ALGOS):
            self.subkey_algo = key
            if key == "cv25519":
                self.subkey_usage = "encr"
            elif key == "ed25519" and self.subkey_usage == "encr":
                self.subkey_usage = "sign"
        elif name == "gpg-usage" and key in dict(self._usage_options()):
            self.subkey_usage = key

    def accept_camera(self, frames, final):
        serial = os.environ.get("BIGSIGNER_CPU_SERIAL", "bigsigner-emulator").encode()
        digest = camera_digest(frames, final, serial, str(time.time()))
        self.app.camera_frames = []
        self.app.camera_final = b""
        try:
            self.backend.mix_entropy(digest)
        except GpgError as exc:
            self.show_error(str(exc))
            return
        self.subkey_algo = "ed25519"
        self.subkey_usage = "sign"
        self.subkey_expire = None
        self.app.open_dropdown = None
        self.app.go("gpg-subkey-options")

    def _start_add_subkey(self):
        key = self.selected
        if key is None or not key.secret_available or not key.fingerprint:
            return
        algo, usage, expire = self.subkey_algo, self.subkey_usage, self.expire_argument()
        timestamp = self.subkey_timestamp()
        self.start("add-subkey", lambda: self.backend.add_subkey(key.fingerprint, algo, usage, expire, timestamp))

    def review(self, frame):
        self.content(frame, "Load GPG Key", review=True)

    def result(self, frame):
        self.content(frame, "Success" if self.outcome.ok else "Error")

"""GPG key review, date selection, and signature/checksum result screens."""

import calendar
import os
from pathlib import Path
import sys
import re
import time

from .. import sdcard
from ..bip85gpg import creation_text, entropy_path, expiration_seconds, identity, path_text, raw_entropy, secret_armor
from ..entropy import camera_digest
from ..gpg import (
    CHECKSUM_LIMIT, CHECKSUM_NAME, CHECKSUM_SIGNATURE, GpgBackend, GpgError, KEY_LIMIT, Outcome,
    PASSWORD_LIMIT, decrypted_filename, looks_like_sha256sums,
)
from .. import file_qr
from .canvas import BLUE, BODY_SIZE, HEADER, HEIGHT, INK, LINE, MARGIN, MUTED, PAPER, RED, TITLE_SIZE, WARNING, WHITE, WIDTH, Frame, Icons, font, wrap


DATE_NOTE = "Some GPG signatures and keys expire. Set the current date so they can be checked correctly. The air-gapped device has no reliable clock."
SUBKEY_TIME_NOTE = "This time is written on the new subkey. The air-gapped device has no reliable clock."
EXPIRE_NOTE = "This is the UTC time when the subkey expires."
SIGN_NOTE = "Signing a file requires this key's private key."
SIGN_PASSPHRASE_NOTE = "Signing a file requires a key with no passphrase."
SIGN_TIME_NOTE = "This time is written on the signature. The air-gapped device has no reliable clock."
BIP85_EXPIRE_NOTE = "This date is written on the certificate. It does not change the RSA private key."
ENTROPY_INDEX_NOTE = (
    "Choose a unique index that will not be used for other purposes. "
    "A good index could be the number of seconds since 1970-01-01."
)
SUBKEY_NOTE = "Adding a subkey requires the certificate's private key."
PRIVATE_NOTE = "Contains a private key"
_USAGE = (("c", "Certification"), ("s", "Signing"), ("e", "Encryption"), ("a", "Authentication"))
_SUBKEY_ALGOS = (("ed25519", "Ed25519"), ("cv25519", "Curve25519"), ("rsa3072", "RSA-3072"), ("rsa4096", "RSA-4096"))
_SUBKEY_USAGES = (("sign", "Signing"), ("encr", "Encryption"), ("auth", "Authentication"))
_BIP85_BITS = (("3072", "3072 bits"), ("4096", "4096 bits"))
_BIP85_ROLES = (("cert", "Certificate Only"), ("cert-sign", "Certificate and Signing"))


def _companion_looks_like_checksums(relative: str, storage: str) -> bool:
    name = Path(relative).name
    if not name.lower().endswith(".asc") or len(name) <= 4:
        return False
    parent = relative[: -len(name)].rstrip("/")
    companion = sdcard.child_path(parent, name[:-4])
    try:
        if not sdcard.file_exists(companion, storage=storage):
            return False
        if sdcard.file_size(companion, storage=storage) > CHECKSUM_LIMIT:
            return False
        data = sdcard.read_bytes(companion, storage=storage, max_bytes=CHECKSUM_LIMIT)
    except sdcard.SdError:
        return False
    return looks_like_sha256sums(data)


def _default_gpg_backend():
    if sys.platform in ("emscripten", "wasi"):
        from ..openpgpjs import OpenPgpJsBackend
        return OpenPgpJsBackend()
    return GpgBackend()


class _Ready:
    """A finished job, used when OpenPGP.js has to run on the worker thread."""

    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def done(self):
        return True

    def result(self):
        if self._error is not None:
            raise self._error
        return self._result


class GpgUI:
    def __init__(self, app, backend=None):
        self.app = app
        self.backend = backend or _default_gpg_backend()
        self.date = dict(year=2026, month=6, day=15)
        self.subkey_clock = dict(year=2026, month=6, day=15, hour=0, minute=0)
        self.clock = "date"
        self.operation = ""
        self.subkey_algo = "ed25519"
        self.subkey_usage = "sign"
        self.subkey_expire = None
        self.expire_clock = dict(year=2027, month=6, day=15, hour=0)
        self.sign_clock = dict(year=2026, month=6, day=15, hour=0, minute=0)
        self.sign_fingerprint = ""
        self.sign_algorithm = ""
        self.sign_relative = ""
        self.sign_storage = "sd"
        self.sign_folder = False
        self.sign_overwrite = []
        self.camera_for = ""
        self.bip85_fp = None
        self.bip85_bits = 4096
        self.bip85_index = 0
        self.bip85_role = "cert-sign"
        self.bip85_name = ""
        self.bip85_email = ""
        self.bip85_expires = None
        self.bip85_clock = dict(year=2026, month=6, day=15)
        self.bip85_field = "name"
        self.entropy_fp = None
        self.entropy_index = 0
        self.bip85_draft = ""
        self.details_back = []
        self.operation = "detached"
        self.verify_relative = ""
        self.verify_storage = "sd"
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
        self._restore_keys = None
        self.armor = ""
        self.export_secret = False
        self.export_subkey = False
        self.export_fingerprint = ""
        self.export_title = ""
        self.qr_parts = []
        self.qr_index = 0
        self.qr_command = ""
        self.encrypt_selected = set()
        self.encrypt_source = ""
        self.encrypt_storage = "sd"
        self.encrypt_name = ""
        self.encrypt_password = ""
        self.decrypt_source = ""
        self.decrypt_storage = "sd"
        self.decrypt_name = ""
        self.decrypt_password = ""
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
                         "gpg-key-qr": self.key_qr, "gpg-qr-guide": self.qr_guide,
                         "gpg-review": self.review, "gpg-result": self.result,
                         "gpg-subkey-options": self.subkey_options,
                         "gpg-sign-choice": self.sign_choice, "gpg-sign-time": self.date_screen,
                         "gpg-bip85-seed": self.bip85_seeds, "gpg-bip85": self.bip85_options,
                         "gpg-bip85-details": self.bip85_details, "gpg-bip85-text": self.bip85_text,
                         "gpg-bip85-expire": self.date_screen,
                         "gpg-encrypt-menu": self.encrypt_menu,
                         "gpg-encrypt-keys": self.encrypt_keys, "gpg-encrypt-name": self.encrypt_name_screen,
                         "gpg-aes-password": self.aes_password, "gpg-aes-type": self.aes_type,
                         "gpg-decrypt-password": self.decrypt_password_screen, "gpg-decrypt-type": self.decrypt_type,
                         "gpg-entropy": self.entropy_menu, "gpg-entropy-seed": self.entropy_seeds,
                         "gpg-entropy-index": self.entropy_index_screen,
                         "gpg-checksum-warning": self.checksum_warning}

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
        if self.clock == "sign":
            return self.sign_clock
        if self.clock == "bip85":
            return self.bip85_clock
        return self.date

    def timestamp(self):
        date = self.date
        return calendar.timegm((date["year"], date["month"], date["day"], 0, 0, 0))

    def subkey_timestamp(self):
        clock = self.subkey_clock
        return calendar.timegm((clock["year"], clock["month"], clock["day"], clock["hour"], clock["minute"], 0))

    def sign_timestamp(self):
        clock = self.sign_clock
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
        elif action == "gpg-encrypt-menu":
            app.go("gpg-encrypt-menu")
        elif action == "gpg-encrypt":
            self.encrypt_selected = set()
            self.start("encrypt-list", self.backend.list_keys)
        elif action == "gpg-aes":
            self.encrypt_password = ""
            app._open_sd("gpg-aes-file")
        elif action == "gpg-aes-type":
            self.encrypt_password = ""
            app.passphrase_mode = "lower"
            app.go("gpg-aes-type")
        elif action == "gpg-aes-pass-file":
            app._open_sd("gpg-aes-pass")
        elif action == "gpg-aes-continue":
            if self._password_ok(self.encrypt_password):
                self._open_aes_camera()
        elif action == "gpg-decrypt":
            self.decrypt_password = ""
            app._open_sd("gpg-decrypt-file")
        elif action == "gpg-entropy":
            self.entropy_fp = None
            self.entropy_index = 0
            app.go("gpg-entropy")
        elif action == "gpg-entropy-camera":
            app.camera_frames = []
            app.camera_final = b""
            app.camera_purpose = "gpg"
            self.camera_for = "entropy"
            app.go("camera")
        elif action == "gpg-entropy-seed":
            self.entropy_index = 0
            app.go("gpg-entropy-seed")
        elif action.startswith("gpg-entropy-pick:"):
            self._pick_entropy_seed(action.split(":", 1)[1])
        elif action == "gpg-entropy-dec" and self.entropy_index > 0:
            self.entropy_index -= 1
        elif action == "gpg-entropy-inc" and self.entropy_index < 0x7FFFFFFF:
            self.entropy_index += 1
        elif action == "gpg-entropy-edit":
            self._edit_entropy_index()
        elif action == "gpg-entropy-add":
            self._add_seed_entropy()
        elif action == "gpg-decrypt-type":
            self.decrypt_password = ""
            app.passphrase_mode = "lower"
            app.go("gpg-decrypt-type")
        elif action == "gpg-decrypt-pass-file":
            app._open_sd("gpg-decrypt-pass")
        elif action == "gpg-decrypt-continue":
            if self._decrypt_password_ok(self.decrypt_password):
                self.start_decrypt()
        elif action.startswith("gpg-encrypt-toggle:"):
            fingerprint = action.split(":", 1)[1]
            if fingerprint in self.encrypt_selected:
                self.encrypt_selected.discard(fingerprint)
            else:
                self.encrypt_selected.add(fingerprint)
            self.build_encrypt_keys()
        elif action == "gpg-encrypt-continue":
            if self._selected_fingerprints():
                app._open_sd("gpg-encrypt-file")
        elif action == "gpg-encrypt-commit":
            self._commit_encrypt()
        elif action == "gpg-home":
            self.open()
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
        elif action == "gpg-checksum-continue":
            self._start_detached_verify()
        elif action == "gpg-date-continue":
            if self.clock == "subkey":
                self._start_add_subkey()
            elif self.clock == "sign":
                self._start_sign()
            elif self.operation in ("burn-detached", "burn-checksums"):
                self.app.fs.start_signature_check()
            else:
                app._open_sd("gpg-verify")
        elif action == "gpg-sign":
            key = self.selected
            if key is not None:
                self._begin_sign(key.fingerprint, key.algorithm, bool(key.secret_available), key.needs_passphrase)
        elif action.startswith("gpg-sign-subkey:"):
            key = self.selected
            index = int(action.split(":", 1)[1])
            if key is not None and 0 <= index < len(key.subkeys):
                sub = key.subkeys[index]
                self._begin_sign(sub.get("fingerprint", ""), sub.get("algorithm", ""), bool(sub.get("secret")), bool(sub.get("needs_passphrase")))
        elif action == "gpg-sign-file":
            app._open_sd("gpg-sign-file")
        elif action == "gpg-sign-folder":
            app._open_sd("gpg-sign-folder")
        elif action == "gpg-sign-folder-here":
            self._choose_sign_folder()
        elif action == "gpg-sign-commit":
            self._start_sign()
        elif action == "gpg-add-subkey":
            key = self.selected
            if key is None or not key.secret_available:
                return
            self.details_back = list(app.back)
            app.camera_frames = []
            app.camera_final = b""
            app.camera_purpose = "gpg"
            self.camera_for = "subkey"
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
        elif action == "gpg-load-seed":
            self._open_bip85()
        elif action.startswith("gpg-bip85-pick:"):
            self._pick_bip85_seed(action.split(":", 1)[1])
        elif action == "gpg-bip85-dec" and self.bip85_index > 0:
            self.bip85_index -= 1
        elif action == "gpg-bip85-inc" and self.bip85_index < 0x7FFFFFFF:
            self.bip85_index += 1
        elif action == "gpg-bip85-edit":
            self._edit_bip85_index()
        elif action == "gpg-bip85-continue":
            app.open_dropdown = None
            app.go("gpg-bip85-details")
        elif action == "gpg-bip85-name":
            self._edit_bip85_text("name")
        elif action == "gpg-bip85-email":
            self._edit_bip85_text("email")
        elif action == "gpg-bip85-text-save":
            if self.bip85_field == "email":
                self.bip85_email = self.bip85_draft
            else:
                self.bip85_name = self.bip85_draft
            app.back_one()
        elif action == "gpg-bip85-expire":
            self.clock = "bip85"
            app.open_dropdown = None
            self.bip85_clock = dict(self.bip85_expires or dict(year=2026, month=6, day=15))
            app.go("gpg-bip85-expire")
        elif action == "gpg-bip85-clear":
            self.bip85_expires = None
            app.back_one()
        elif action == "gpg-bip85-save":
            self._save_bip85_expiration()
        elif action == "gpg-bip85-create":
            self._create_bip85()
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
        elif action == "gpg-delete":
            if self.selected is None or not self.selected.fingerprint:
                return
            app.confirm = "gpg-delete"
        elif action == "gpg-export-file":
            self._export_file()
        elif action == "gpg-export-qr":
            self._open_key_qr()
        elif action == "gpg-qr-open":
            self._open_key_parts()
        elif action == "gpg-qr-prev":
            self._step_key_qr(-1)
        elif action == "gpg-qr-next":
            self._step_key_qr(1)

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
            if app.sd_expect == "gpg-sign-file":
                self._choose_sign_file(relative)
                return
            if app.sd_expect == "gpg-encrypt-file":
                self._choose_encrypt_file(relative)
                return
            if app.sd_expect == "gpg-aes-file":
                self._choose_aes_file(relative)
                return
            if app.sd_expect == "gpg-aes-pass":
                self._accept_aes_password(relative)
                return
            if app.sd_expect == "gpg-decrypt-file":
                self._choose_decrypt_file(relative)
                return
            if app.sd_expect == "gpg-decrypt-pass":
                self._accept_decrypt_password(relative)
                return
            if not relative.lower().endswith(".asc"):
                raise GpgError("Choose an .asc signature file.")
            storage = app.sd_storage
            checksums = self.operation == "checksums"
            if not checksums and _companion_looks_like_checksums(relative, storage):
                self.verify_relative = relative
                self.verify_storage = storage
                self.close_picker()
                if app.screen == "gpg-date":
                    app.back_one()
                app.go("gpg-checksum-warning")
                return
            self.close_picker()
            self.start("verify", lambda: self.backend.verify(relative, storage, self.timestamp(), checksums))
        except (sdcard.SdError, GpgError) as exc:
            self.show_error(str(exc))

    def delete_selected(self):
        key = self.selected
        if key is None or not key.fingerprint:
            return
        fingerprint = key.fingerprint
        self.start("delete", lambda: self.backend.delete_key(fingerprint), replace=True)

    def start(self, kind, job, *, replace=False):
        self._restore_keys = None
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
            if self.future is None and not getattr(self.backend, "threaded", True):
                try:
                    self.future = _Ready(self.job())
                except Exception as exc:
                    self.future = _Ready(error=exc)
                return
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
        previous_keys = list(self.outcome.keys)
        self.job = self.future = None
        if self.executor is not None:
            self.executor.shutdown(wait=False)
            self.executor = None
        self.outcome = outcome
        if self.operation in ("burn-detached", "burn-checksums"):
            self.operation = ""
            self.app.fs.finish_signature_check(outcome)
            return
        if self.job_kind == "delete":
            fingerprint = self.selected.fingerprint if self.selected is not None else ""
            kept = previous_keys
            if outcome.ok:
                self.selected = None
                kept = [key for key in previous_keys if key.fingerprint != fingerprint]
            self._restore_keys = kept
        if outcome.ok and self.job_kind == "export":
            self.armor = outcome.stages[-1].stdout if outcome.stages else ""
            self.app.screen = "gpg-export"
        elif outcome.ok and self.job_kind in ("list", "preview"):
            self.build_keys(summary=self.job_kind == "list")
            self.app.screen = "gpg-review" if self.job_kind == "preview" else "gpg-keys"
        elif outcome.ok and self.job_kind == "encrypt-list":
            self.build_encrypt_keys()
            self.app.screen = "gpg-encrypt-keys"
        elif outcome.ok and self.job_kind == "decrypt-inspect":
            if outcome.message == "symmetric":
                self.decrypt_password = ""
                self.app.screen = "gpg-decrypt-password"
            elif outcome.message == "key":
                self.start_decrypt(replace=True)
            else:
                self.outcome = Outcome(False, "This file is not an encrypted message.")
                self.build_result()
                self.app.screen = "gpg-result"
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
        y = self._button_row(frame, y, ("Encrypt", "gpg-encrypt-menu"), ("Decrypt", "gpg-decrypt"))
        y = frame.button(y, "Add Entropy to OS", "gpg-entropy")
        frame.text("GPG keys stay in RAM and are cleared when the power is off.", MARGIN, y + 12, size=28, fill=MUTED)

    @staticmethod
    def _button_row(frame, y, left, right):
        gap = 12
        height = max(frame.button_height(left[0]), frame.button_height(right[0]))
        text_delta = frame._button_metrics(left[0], False)[4]
        width = (WIDTH - 2 * MARGIN - gap) // 2
        frame.button_box((MARGIN, y, MARGIN + width, y + height), left[0], left[1], text_delta=text_delta)
        frame.button_box((MARGIN + width + gap, y, WIDTH - MARGIN, y + height), right[0], right[1], text_delta=text_delta)
        return y + height + 12

    def formats(self, frame):
        frame.header("Verify Signature", "back")
        y = frame.button(HEADER + 24, "Detached Signature", "gpg-date:detached")
        y = frame.text("Example: release.zip + release.zip.asc", MARGIN, y, size=28, fill=MUTED)
        y = frame.button(y + 24, "Signed Checksum File", "gpg-date:checksums")
        frame.text("Example: release.tar.gz + SHASUMS.asc, with or without SHASUMS.", MARGIN, y, size=28, fill=MUTED)

    def checksum_warning(self, frame):
        frame.header("Verify Signature", "back")
        label = "Warning"
        face = font(34)
        frame.text(label, (WIDTH - frame.draw.textlength(label, font=face)) / 2, HEADER + 28, size=34, fill=RED)
        y = frame.text(
            "This file looks like a checksum file. Detached Signature verifies only this file's signature.",
            MARGIN, HEADER + 88, size=BODY_SIZE, fill=RED,
        )
        frame.text(
            "Go back and choose Signed Checksum File to verify the signature and check the checksums of the other files.",
            MARGIN, y + 16, size=BODY_SIZE, fill=RED,
        )
        gap = 110 - frame.button_height("Continue")
        frame.button(HEIGHT - frame.button_height("Continue") - gap, "Continue", "gpg-checksum-continue")

    def _start_detached_verify(self):
        relative, storage = self.verify_relative, self.verify_storage
        self.start("verify", lambda: self.backend.verify(relative, storage, self.timestamp(), False), replace=True)

    def date_screen(self, frame):
        app = self.app
        kind = self.clock if self.clock in ("subkey", "expire", "sign", "bip85") else "date"
        notes = {"subkey": SUBKEY_TIME_NOTE, "expire": EXPIRE_NOTE, "sign": SIGN_TIME_NOTE,
                 "date": DATE_NOTE, "bip85": BIP85_EXPIRE_NOTE}
        fields = {"subkey": ("year", "month", "day", "hour", "minute"),
                  "expire": ("year", "month", "day", "hour"),
                  "sign": ("year", "month", "day", "hour", "minute"),
                  "date": ("year", "month", "day"),
                  "bip85": ("year", "month", "day")}
        footers = {"subkey": "Seconds are 00 UTC.", "expire": "Minutes are 00 UTC.",
                   "sign": "Seconds are 00 UTC.", "date": "UTC · 00:00:00",
                   "bip85": "The time is 00:00:00 UTC."}
        frame.header({"subkey": "Time", "expire": "Expires", "sign": "Time", "date": "Date", "bip85": "Expires"}[kind], "back")
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
        if kind in ("expire", "bip85"):
            set_top = HEIGHT - 110
            clear_top = set_top - 16 - frame.button_height("No Expiration")
            clear_action = "gpg-bip85-clear" if kind == "bip85" else "gpg-expire-clear"
            save_action = "gpg-bip85-save" if kind == "bip85" else "gpg-expire-save"
            frame.button(clear_top, "No Expiration", clear_action)
            frame.button(set_top, "Set Expiration", save_action)
        elif kind == "sign":
            frame.button(HEIGHT - 110, "Sign File", "gpg-sign-commit")
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
        y = frame.button(y, "Scan QR Code", "gpg-scan-key", icon=Icons.CAMERA, awesome=True)
        frame.button(y, "Load RSA Key from Bitcoin Seed (BIP-85)", "gpg-load-seed", icon=Icons.SEED, awesome=True)

    def working(self, frame):
        frame.header("GPG")
        labels = {"list": "Listing GPG Keys…", "preview": "Reading GPG Key…", "import": "Importing GPG Key…",
                  "verify": "Verifying Signature…", "export": self._export_progress(),
                  "add-subkey": "Adding a Subkey…", "sign": "Signing File…", "delete": "Deleting GPG Key…",
                  "bip85": "Creating a GPG Key…", "encrypt-list": "Listing GPG Keys…",
                  "encrypt": "Encrypting File…", "decrypt-inspect": "Reading Encrypted File…",
                  "decrypt": "Decrypting File…"}
        frame.text(labels.get(self.job_kind, "Working…"), MARGIN, HEADER + 40, size=BODY_SIZE)
        self.work_shown = True

    def reset_layout(self):
        self.rows, self.cards, self.card_actions, self.buttons = [], [], [], []
        self.content_end = HEADER + 20
        self.scratch = Frame()

    def add_button(self, text, action, *, inset=0, enabled=True, color=BLUE):
        height = self.scratch.button_height(text, inset=inset)
        self.buttons.append((self.content_end, text, action, height, inset, enabled, color))
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
                color = item[4] if len(item) > 4 else BLUE
                self.add_button(text, action, inset=16, enabled=enabled, color=color)
                if len(item) > 3 and item[3]:
                    self.add_text(item[3], fill=MUTED, size=28, inset=16)
            if note:
                self.add_text(note, fill=MUTED, size=28, inset=16)
        self.content_end += 8
        self.cards.append((MARGIN, top, WIDTH - MARGIN, self.content_end))
        self.card_actions.append(open_action)
        self.content_end += 16

    def build_details(self):
        key = self.selected
        self._key_cards([] if key is None else [key], summary=False, open_cards=False, exports=True)

    def build_encrypt_keys(self):
        self.reset_layout()
        keys = [key for key in self.outcome.keys if self._encryption_subkeys(key)]
        if not keys:
            self.add_text("No encryption subkeys are loaded.")
            return
        for key in keys:
            top = self.content_end
            self.content_end += 16
            for user_id in key.user_ids or [key.fingerprint]:
                self.add_text(user_id, inset=16)
            self.content_end += 8
            for sub in self._encryption_subkeys(key):
                self.add_text("Encryption", fill=MUTED, inset=16)
                self._add_value("Algorithm:", sub.get("algorithm", ""))
                self._add_value("Fingerprint:", sub.get("fingerprint", ""))
                label = "Selected" if sub.get("fingerprint") in self.encrypt_selected else "Select"
                self.add_button(label, "gpg-encrypt-toggle:" + sub.get("fingerprint", ""), inset=16)
                self.content_end += 8
            self.content_end += 8
            self.cards.append((MARGIN, top, WIDTH - MARGIN, self.content_end))
            self.card_actions.append("")
            self.content_end += 16

    def encrypt_menu(self, frame):
        frame.header("Encrypt", "back")
        y = frame.button(HEADER + 24, "Encrypt to GPG Keys", "gpg-encrypt")
        frame.button(y, "Encrypt with AES256", "gpg-aes")

    def aes_password(self, frame):
        frame.header("Password", "back")
        y = frame.button(HEADER + 24, "Enter Password", "gpg-aes-type")
        y = frame.button(y, "Load from File", "gpg-aes-pass-file", icon=Icons.FILE, awesome=True)
        frame.text("The password can be at most 255 bytes.", MARGIN, y, size=28, fill=MUTED)

    def aes_type(self, frame):
        frame.header("Password", "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        self.app._paint_hscroll_field(frame, box, self.encrypt_password, len(self.encrypt_password), "Password")
        y = frame.button(box[3] + 16, "Continue", "gpg-aes-continue", enabled=self._password_ok(self.encrypt_password))
        frame.text("At most 255 bytes.", MARGIN, y, size=28, fill=MUTED)
        self.app._passphrase_keyboard(frame)

    def decrypt_password_screen(self, frame):
        frame.header("Password", "back")
        y = frame.button(HEADER + 24, "Enter Password", "gpg-decrypt-type")
        y = frame.button(y, "Load from File", "gpg-decrypt-pass-file", icon=Icons.FILE, awesome=True)
        frame.text("The password can be at most 255 characters.", MARGIN, y, size=28, fill=MUTED)

    def decrypt_type(self, frame):
        frame.header("Password", "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        self.app._paint_hscroll_field(frame, box, self.decrypt_password, len(self.decrypt_password), "Password")
        y = frame.button(box[3] + 16, "Continue", "gpg-decrypt-continue", enabled=self._decrypt_password_ok(self.decrypt_password))
        frame.text("At most 255 characters.", MARGIN, y, size=28, fill=MUTED)
        self.app._passphrase_keyboard(frame)

    def encrypt_keys(self, frame):
        ready = bool(self._selected_fingerprints())
        self.content(frame, "Encrypt to Keys", footer=("Continue", "gpg-encrypt-continue", ready))

    def encrypt_name_screen(self, frame):
        frame.header("Encrypted File", "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        self.app._paint_hscroll_field(frame, box, self.encrypt_name, len(self.encrypt_name), "File name")
        y = frame.button(box[3] + 16, "Encrypt", "gpg-encrypt-commit", enabled=bool(self.encrypt_name.strip()))
        frame.text("Saved in the same folder as the original file.", MARGIN, y, size=28, fill=MUTED)
        self.app._passphrase_keyboard(frame)

    def _encryption_subkeys(self, key):
        return [sub for sub in key.subkeys if "e" in sub.get("capabilities", "").lower() and sub.get("fingerprint")]

    def _selected_fingerprints(self):
        chosen = []
        for key in self.outcome.keys:
            for sub in self._encryption_subkeys(key):
                fingerprint = sub.get("fingerprint", "")
                if fingerprint in self.encrypt_selected:
                    chosen.append(fingerprint)
        return chosen

    def _prepare_encrypt_name(self, relative):
        from .app import _unused_filename

        self.encrypt_source = relative
        self.encrypt_storage = self.app.sd_storage
        parent = str(Path(relative.replace("\\", "/")).parent)
        parent = "" if parent == "." else parent
        try:
            taken = {item["name"] for item in sdcard.list_folder(parent, storage=self.encrypt_storage)}
        except sdcard.SdError:
            taken = set()
        self.encrypt_name = _unused_filename(Path(relative).name + ".enc.asc", taken)

    def _choose_encrypt_file(self, relative):
        self.close_picker()
        self._prepare_encrypt_name(relative)
        self.app.passphrase_mode = "lower"
        self.app.go("gpg-encrypt-name")

    def _choose_aes_file(self, relative):
        self.close_picker()
        self._prepare_encrypt_name(relative)
        self.encrypt_password = ""
        self.app.go("gpg-aes-password")

    def _accept_aes_password(self, relative):
        try:
            data = sdcard.read_bytes(relative, storage=self.app.sd_storage, max_bytes=PASSWORD_LIMIT + 1)
        except sdcard.SdError as exc:
            message = "The password is longer than 255 bytes." if str(exc) == "That file is too large." else str(exc)
            self.app.set_error(message)
            return
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        try:
            password = data.decode("utf-8")
        except UnicodeDecodeError:
            self.app.set_error("The password file is not text.")
            return
        if not password:
            self.app.set_error("The password file is empty.")
            return
        if not self._password_ok(password):
            self.app.set_error(
                "The password is longer than 255 bytes."
                if len(password.encode("utf-8")) > PASSWORD_LIMIT else "The password is not valid."
            )
            return
        self.encrypt_password = password
        self.close_picker()
        self._open_aes_camera()

    def _password_ok(self, password):
        if not password or "\x00" in password or "\n" in password or "\r" in password:
            return False
        return len(password.encode("utf-8")) <= PASSWORD_LIMIT

    def type_aes_password(self, key):
        if key in ("enter", "\n"):
            return
        if key == "backspace":
            self.encrypt_password = self.encrypt_password[:-1]
            return
        if len(key) != 1:
            return
        candidate = self.encrypt_password + key
        if self._password_ok(candidate):
            self.encrypt_password = candidate

    def _open_aes_camera(self):
        app = self.app
        app.camera_frames = []
        app.camera_final = b""
        app.camera_purpose = "gpg"
        self.camera_for = "aes"
        app.go("camera")

    def start_aes_encrypt(self):
        password = self.encrypt_password
        self.encrypt_password = ""
        if not self._password_ok(password):
            return
        name = self.encrypt_name.strip()
        source, storage = self.encrypt_source, self.encrypt_storage
        self.start("encrypt", lambda: self.backend.encrypt_symmetric(source, name, storage, password))

    def _choose_decrypt_file(self, relative):
        from .app import _unused_filename

        self.close_picker()
        self.decrypt_source = relative
        self.decrypt_storage = self.app.sd_storage
        self.decrypt_password = ""
        parent = str(Path(relative.replace("\\", "/")).parent)
        parent = "" if parent == "." else parent
        suggested = decrypted_filename(Path(relative).name)
        if suggested == Path(relative).name:
            suggested += ".dec"
        try:
            taken = {item["name"] for item in sdcard.list_folder(parent, storage=self.decrypt_storage)}
        except sdcard.SdError:
            taken = set()
        self.decrypt_name = _unused_filename(suggested, taken)
        source, storage = self.decrypt_source, self.decrypt_storage
        self.start("decrypt-inspect", lambda: self._decrypt_kind(source, storage))

    def _decrypt_kind(self, source, storage):
        try:
            kind = self.backend.encryption_kind(source, storage)
        except GpgError as exc:
            return Outcome(False, str(exc))
        return Outcome(True, message=kind)

    def _accept_decrypt_password(self, relative):
        password = self._password_from_file(relative, characters=True)
        if password is None:
            return
        self.decrypt_password = password
        self.close_picker()
        self.start_decrypt()

    def _password_from_file(self, relative, *, characters):
        try:
            data = sdcard.read_bytes(relative, storage=self.app.sd_storage, max_bytes=PASSWORD_LIMIT * 4 + 1)
        except sdcard.SdError as exc:
            too_long = "The password is longer than 255 characters." if characters else "The password is longer than 255 bytes."
            self.app.set_error(too_long if str(exc) == "That file is too large." else str(exc))
            return None
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        try:
            password = data.decode("utf-8")
        except UnicodeDecodeError:
            self.app.set_error("The password file is not text.")
            return None
        if not password:
            self.app.set_error("The password file is empty.")
            return None
        if characters:
            if len(password) > PASSWORD_LIMIT or "\n" in password or "\r" in password or "\x00" in password:
                self.app.set_error(
                    "The password is longer than 255 characters." if len(password) > PASSWORD_LIMIT else "The password is not valid."
                )
                return None
        elif not self._password_ok(password):
            self.app.set_error(
                "The password is longer than 255 bytes."
                if len(password.encode("utf-8")) > PASSWORD_LIMIT else "The password is not valid."
            )
            return None
        return password

    def _decrypt_password_ok(self, password):
        if not password or "\x00" in password or "\n" in password or "\r" in password:
            return False
        return len(password) <= PASSWORD_LIMIT

    def type_decrypt_password(self, key):
        if key in ("enter", "\n"):
            return
        if key == "backspace":
            self.decrypt_password = self.decrypt_password[:-1]
            return
        if len(key) != 1:
            return
        candidate = self.decrypt_password + key
        if self._decrypt_password_ok(candidate):
            self.decrypt_password = candidate

    def start_decrypt(self, *, replace=False):
        password = self.decrypt_password if self._decrypt_password_ok(self.decrypt_password) else None
        self.decrypt_password = ""
        name = self.decrypt_name.strip()
        source, storage = self.decrypt_source, self.decrypt_storage
        self.start("decrypt", lambda: self.backend.decrypt_file(source, name, storage, password), replace=replace)

    def _encrypt_parent(self):
        parent = str(Path(self.encrypt_source.replace("\\", "/")).parent)
        return "" if parent == "." else parent

    def type_encrypt_name(self, key):
        if key in ("enter", "\n"):
            return
        if key == "backspace":
            self.encrypt_name = self.encrypt_name[:-1]
            return
        if len(key) != 1 or len(self.encrypt_name.encode()) >= 240:
            return
        self.encrypt_name += key

    def encrypt_overwrite_message(self):
        return f"{self.encrypt_name.strip()} already exists and will be replaced."

    def _commit_encrypt(self):
        name = self.encrypt_name.strip()
        if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
            self.app.set_error("The file name is not valid.")
            return
        if name == Path(self.encrypt_source).name:
            self.app.set_error("Choose a different file name.")
            return
        self.encrypt_name = name
        try:
            exists = sdcard.file_exists(sdcard.child_path(self._encrypt_parent(), name), storage=self.encrypt_storage)
        except sdcard.SdError as exc:
            self.app.set_error(str(exc))
            return
        if exists:
            self.app.confirm = "gpg-encrypt-replace"
            return
        self.start_encrypt()

    def start_encrypt(self):
        fingerprints = self._selected_fingerprints()
        if not fingerprints:
            return
        name = self.encrypt_name.strip()
        source, storage = self.encrypt_source, self.encrypt_storage
        self.start("encrypt", lambda: self.backend.encrypt_file(fingerprints, source, name, storage))

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
            if exports:
                buttons.append(("Export Public Key", "gpg-export-public"))
                if key.secret_available:
                    buttons.append(("Export Private Key", "gpg-export-private"))
                buttons.append(("Add a Subkey", "gpg-add-subkey", bool(key.secret_available),
                                 "" if key.secret_available else SUBKEY_NOTE))
                if "s" in key.capabilities.lower():
                    buttons.append(self._sign_button("gpg-sign", bool(key.secret_available), key.needs_passphrase))
                buttons.append(("Delete", "gpg-delete", True, "", RED))
            self._card(values, fields, open_action=f"gpg-open:{index}" if open_cards else "",
                       private=not summary and key.contains_private, buttons=buttons)
            if not summary:
                labels = [self._subkey_export_label(sub) if sub.get("secret") else "" for sub in key.subkeys]
                for sub_index, sub in enumerate(key.subkeys):
                    buttons = []
                    if exports and sub.get("secret"):
                        label = labels[sub_index]
                        if labels.count(label) > 1 and sub.get("key_id"):
                            label = f"{label} {sub['key_id']}"
                        buttons.append((label, f"gpg-export-subkey:{sub_index}"))
                    if exports and "s" in sub.get("capabilities", "").lower():
                        buttons.append(self._sign_button(f"gpg-sign-subkey:{sub_index}", bool(sub.get("secret")), bool(sub.get("needs_passphrase"))))
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
        if self.outcome.unverified:
            self.add_text("Other files in the folder were not verified.", fill=WARNING)
            for filename in self.outcome.unverified[:3]:
                self.add_text(filename, fill=WARNING)
            if len(self.outcome.unverified) > 3:
                self.add_text("and more...", fill=WARNING)

    def content(self, frame, title, review=False, footer=None):
        gap = 20
        footer_h = gap + frame.button_height(footer[0]) + gap if footer else 0
        offset = self.app._scroll_offset(self.app.screen, self.content_end, clearance=(footer_h + 12) if footer else (132 if review else 20))
        bottom = HEIGHT - footer_h if footer else (HEIGHT - 128 if review else HEIGHT)
        for (left, top, right, end), action in zip(self.cards, self.card_actions):
            if end - offset > HEADER and top - offset < bottom:
                frame.draw.rounded_rectangle((left, top - offset, right, end - offset), radius=12, fill=WHITE, outline=LINE, width=2)
                if action:
                    frame.hit((left, max(top - offset, HEADER), right, min(end - offset, bottom)), action, "GPG Key")
        for y, text, action, _height, inset, enabled, color in self.buttons:
            top = y - offset
            if top >= HEADER and top < bottom:
                frame.button(top, text, action, color=color, inset=inset, enabled=enabled)
        for x, y, text, size, fill, mono in self.rows:
            y -= offset
            if y + size + 8 > HEADER and y < bottom:
                frame.text(text, x, y, size=size, fill=fill, mono=mono)
        if footer:
            frame.draw.rectangle((0, bottom, WIDTH, HEIGHT), fill=PAPER)
            frame.button(HEIGHT - gap - frame.button_height(footer[0]), footer[0], footer[1], enabled=footer[2])
        if review:
            frame.draw.rectangle((0, bottom, WIDTH, HEIGHT), fill=PAPER)
            self.app._dialog_button(frame, (MARGIN, HEIGHT - 96, 234, HEIGHT - 24), "Cancel", "gpg-cancel-key", (132, 138, 148))
            self.app._dialog_button(frame, (246, HEIGHT - 96, WIDTH - MARGIN, HEIGHT - 24), "Confirm", "gpg-confirm-key", BLUE)
        frame.header(title, "back")

    def keys(self, frame):
        if self._restore_keys is not None:
            self.outcome = Outcome(True, keys=self._restore_keys)
            self._restore_keys = None
            self.build_keys(summary=True)
        self.content(frame, "List GPG Keys")

    def details(self, frame):
        self.content(frame, "GPG Key")

    def _export_filename(self) -> str:
        kind = "public" if not self.export_secret else "private"
        fingerprint = self.export_fingerprint or (self.selected.fingerprint if self.selected else "key")
        return f"{fingerprint}-{kind}.asc"

    def _open_key_qr(self):
        """One QR of a short armor. A longer armor uses the file QR sequence."""
        data = self.armor.encode("utf-8")
        if len(data) > file_qr.QR_SPLIT_LIMIT:
            return
        from .app import QR_BRIGHTNESS_DEFAULT

        app = self.app
        app.qr_brightness = QR_BRIGHTNESS_DEFAULT
        if len(data) <= file_qr.TEXT_DIRECT:
            self.qr_parts = [self.armor]
            self.qr_index = 0
            self.qr_command = ""
            app.qr_text = self.armor
            app.go("gpg-key-qr")
            return
        self.qr_parts = file_qr.spaced_parts(file_qr.gzip_base64(data))
        self.qr_index = 0
        self.qr_command = file_qr.recovery_command(self._export_filename())
        app.scroll["gpg-qr-guide"] = 0
        app.go("gpg-qr-guide")

    def _open_key_parts(self):
        if not self.qr_parts:
            return
        from .app import QR_BRIGHTNESS_DEFAULT

        self.qr_index = 0
        self.app.qr_text = self.qr_parts[0]
        self.app.qr_brightness = QR_BRIGHTNESS_DEFAULT
        self.app.go("gpg-key-qr")

    def _step_key_qr(self, delta: int):
        if len(self.qr_parts) < 2 or self.app.screen != "gpg-key-qr":
            return
        self.qr_index = (self.qr_index + delta) % len(self.qr_parts)
        self.app.qr_text = self.qr_parts[self.qr_index]

    def export_choice(self, frame):
        title = self._export_title()
        frame.header(title, "back")
        y = frame.button(HEADER + 24, "Export to File", "gpg-export-file")
        too_long = len(self.armor.encode("utf-8")) > file_qr.QR_SPLIT_LIMIT
        y = frame.button(y, "Show QR Code", "gpg-export-qr", enabled=not too_long)
        if too_long:
            frame.text("This key is too long to show as a QR code.", MARGIN, y, size=28, fill=MUTED)

    def qr_guide(self, frame):
        app = self.app
        label = "Show QR Code" if len(self.qr_parts) == 1 else "Show QR Codes"
        button_h = frame.button_height(label)
        footer = HEIGHT - 16 - button_h
        frame.clip_bottom = footer - 20
        end = self._guide_body(frame, False, 0)
        offset = app._scroll_offset("gpg-qr-guide", end, clearance=HEIGHT - footer + 16)
        self._guide_body(frame, True, offset)
        frame.clip_bottom = HEIGHT
        frame.button(footer, label, "gpg-qr-open")
        frame.header("Key QR", "back")

    def _guide_body(self, frame, paint, offset):
        app = self.app
        count = len(self.qr_parts)
        codes = "1 QR code" if count == 1 else f"{count} QR codes"
        intro = (
            f"This key is large and has been split over {codes}. "
            "Save the content of each QR code in a file. "
            "Name them file-part-00, file-part-01, and so on, starting with the first QR code. "
            "On a Mac or Linux, run:"
        )
        y = HEADER + 20
        y = app._flow_text(frame, y, intro, paint, offset, BODY_SIZE)
        y += 8
        app.fs.qr_command = self.qr_command
        return app.fs._command_block(frame, y, paint, offset)

    def key_qr(self, frame):
        from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

        app = self.app
        many = len(self.qr_parts) > 1
        light = _qr_light(QR_BRIGHTNESS_DEFAULT)
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
        payload = self.qr_parts[self.qr_index] if self.qr_parts else self.armor
        if many:
            top = HEADER + 16
            bright_y = HEIGHT - 88 - 12 - 52
            box = min(WIDTH - 2 * MARGIN, bright_y - 12 - top)
            image = _qr_image(payload, max(160, box), light)
            frame.image.paste(image, ((WIDTH - image.width) // 2, top))
            app._brightness_control(frame, HEIGHT - 88 - 12 - 52)
            app._format_switcher(
                frame, f"{self.qr_index + 1} of {len(self.qr_parts)}", "gpg-qr-prev", "gpg-qr-next",
            )
            frame.header("Key QR", "back")
            return
        top = HEADER + 24
        image = _qr_image(payload, WIDTH - 2 * MARGIN, light)
        frame.image.paste(image, (MARGIN, top))
        app._brightness_control(frame, top + image.height + 24)
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
        elif name == "gpg-bits" and key in dict(_BIP85_BITS):
            self.bip85_bits = int(key)
        elif name == "gpg-role" and key in dict(_BIP85_ROLES):
            self.bip85_role = key

    def accept_camera(self, frames, final):
        serial = os.environ.get("BIGSIGNER_CPU_SERIAL", "bigsigner-emulator").encode()
        digest = camera_digest(frames, final, serial, str(time.time()))
        self.app.camera_frames = []
        self.app.camera_final = b""
        try:
            mixed = self.backend.mix_entropy(digest)
        except GpgError as exc:
            self.camera_for = ""
            self.show_error(str(exc))
            return
        if self.camera_for == "sign":
            self.camera_for = ""
            self.app.go("gpg-sign-choice")
            return
        if self.camera_for == "aes":
            self.camera_for = ""
            self.start_aes_encrypt()
            return
        if self.camera_for == "entropy":
            self.camera_for = ""
            self._show_entropy_result(mixed is not False)
            return
        self.camera_for = ""
        self.subkey_algo = "ed25519"
        self.subkey_usage = "sign"
        self.subkey_expire = None
        self.app.open_dropdown = None
        self.app.go("gpg-subkey-options")

    def sign_choice(self, frame):
        frame.header("Sign File", "back")
        y = frame.button(HEADER + 24, "Sign a Single File", "gpg-sign-file")
        frame.button(y + 12, "Sign All Files in a Folder", "gpg-sign-folder")

    def _sign_button(self, action, secret, needs_passphrase):
        if not secret:
            return ("Sign File", action, False, SIGN_NOTE)
        if needs_passphrase:
            return ("Sign File", action, False, SIGN_PASSPHRASE_NOTE)
        return ("Sign File", action, True, "")

    def _begin_sign(self, fingerprint, algorithm, secret, needs_passphrase=False):
        if not secret or not fingerprint or needs_passphrase:
            return
        self.sign_fingerprint = fingerprint
        self.sign_algorithm = algorithm
        app = self.app
        app.camera_frames = []
        app.camera_final = b""
        app.camera_purpose = "gpg"
        self.camera_for = "sign"
        app.go("camera")

    def _choose_sign_file(self, relative):
        self.sign_folder = False
        self.sign_relative = relative
        self.sign_storage = self.app.sd_storage
        name = Path(relative).name + ".asc"
        parent = str(Path(relative).parent) if "/" in relative.replace("\\", "/") else ""
        if parent == ".":
            parent = ""
        self.sign_overwrite = [name] if sdcard.file_exists(sdcard.child_path(parent, name), storage=self.sign_storage) else []
        self._overwrite_or_time()

    def _choose_sign_folder(self):
        app = self.app
        try:
            entries = sdcard.list_folder(app.sd_dir, storage=app.sd_storage)
        except sdcard.SdError as exc:
            app.set_error(str(exc))
            return
        files = [item["name"] for item in entries if item["kind"] == "file" and item["name"] not in (CHECKSUM_NAME, CHECKSUM_SIGNATURE)]
        if not files:
            app.set_error("This folder has no files to sign.")
            return
        self.sign_folder = True
        self.sign_relative = app.sd_dir
        self.sign_storage = app.sd_storage
        self.sign_overwrite = [name for name in (CHECKSUM_NAME, CHECKSUM_SIGNATURE)
                               if sdcard.file_exists(sdcard.child_path(app.sd_dir, name), storage=app.sd_storage)]
        if any(item["kind"] == "dir" for item in entries):
            app.confirm = "gpg-sign-subfolders"
            return
        self._overwrite_or_time()

    def overwrite_or_time(self):
        if self.sign_overwrite:
            self.app.confirm = "gpg-sign-replace"
            return
        self.open_sign_time()

    def _overwrite_or_time(self):
        self.overwrite_or_time()

    def open_sign_time(self):
        self.clock = "sign"
        self.app.open_dropdown = None
        self.app.go("gpg-sign-time")

    def overwrite_message(self):
        names = self.sign_overwrite
        if len(names) == 1:
            return f"{names[0]} already exists and will be replaced."
        return " and ".join(names) + " already exist and will be replaced."

    def _start_sign(self):
        if not self.sign_fingerprint:
            return
        fingerprint, relative, storage = self.sign_fingerprint, self.sign_relative, self.sign_storage
        timestamp = self.sign_timestamp()
        if self.sign_folder:
            self.start("sign", lambda: self.backend.sign_folder(fingerprint, relative, storage, timestamp))
        else:
            self.start("sign", lambda: self.backend.sign_file(fingerprint, relative, storage, timestamp))

    def _start_add_subkey(self):
        key = self.selected
        if key is None or not key.secret_available or not key.fingerprint:
            return
        algo, usage, expire = self.subkey_algo, self.subkey_usage, self.expire_argument()
        timestamp = self.subkey_timestamp()
        self.start("add-subkey", lambda: self.backend.add_subkey(key.fingerprint, algo, usage, expire, timestamp))

    def _seed_records(self):
        found = []
        for record in self.app.session.fingerprints.values():
            for key in record.keys:
                if key.has_seed and getattr(key, "root", None) is not None:
                    found.append((key.added, record))
                    break
        found.sort(key=lambda item: item[0])
        return [record for _added, record in found]

    def _open_bip85(self):
        self.bip85_bits = 4096
        self.bip85_index = 0
        self.bip85_role = "cert-sign"
        self.bip85_name = ""
        self.bip85_email = ""
        self.bip85_expires = None
        self.bip85_fp = None
        self.app.open_dropdown = None
        self.app.go("gpg-bip85-seed")

    def _pick_bip85_seed(self, fingerprint):
        try:
            fp = bytes.fromhex(fingerprint)
        except ValueError:
            return
        if not any(record.fingerprint == fp for record in self._seed_records()):
            self.app.set_error("This seed is no longer loaded.")
            return
        self.bip85_fp = fp
        self.app.open_dropdown = None
        self.app.go("gpg-bip85")

    def _edit_bip85_index(self):
        if self.bip85_fp not in self.app.session.fingerprints:
            self.app.set_error("This seed is no longer loaded.")
            return
        self.app.account_fp = self.bip85_fp
        self.app.account_text = str(self.bip85_index)
        self.app.account_for = "gpg-bip85"
        self.app.go("account")

    def _edit_bip85_text(self, field):
        self.bip85_field = field
        self.bip85_draft = self.bip85_name if field == "name" else self.bip85_email
        self.app.passphrase_mode = "lower"
        self.app.go("gpg-bip85-text")

    def type_bip85(self, key):
        if key in ("enter", "\n"):
            return
        if key == "backspace":
            self.bip85_draft = self.bip85_draft[:-1]
            return
        if len(self.bip85_draft) >= 128 or len(key) != 1:
            return
        self.bip85_draft += key

    def _save_bip85_expiration(self):
        clock = self.bip85_clock
        try:
            expiration_seconds((clock["year"], clock["month"], clock["day"]))
        except ValueError as exc:
            self.app.set_error(str(exc))
            return
        self.bip85_expires = dict(year=clock["year"], month=clock["month"], day=clock["day"])
        self.app.back_one()

    def _create_bip85(self):
        try:
            identity(self.bip85_name, self.bip85_email)
            expires = None
            if self.bip85_expires is not None:
                expires = (self.bip85_expires["year"], self.bip85_expires["month"], self.bip85_expires["day"])
                expiration_seconds(expires)
        except ValueError as exc:
            self.app.set_error(str(exc))
            return
        fingerprint, bits, index = self.bip85_fp, self.bip85_bits, self.bip85_index
        name, email = self.bip85_name, self.bip85_email
        signing = self.bip85_role == "cert-sign"
        session = self.app.session

        def job():
            root = None
            record = session.fingerprints.get(fingerprint)
            if record is not None:
                for key in record.keys:
                    if key.has_seed and getattr(key, "root", None) is not None:
                        root = key.root
                        break
            if root is None:
                return Outcome(False, "This seed is no longer loaded.")
            try:
                payload = secret_armor(root, bits, index, name, email, signing=signing, expires_on=expires)
            except ValueError as exc:
                return Outcome(False, str(exc))
            return self.backend.import_key(payload.encode())

        self.start("bip85", job)

    def bip85_seeds(self, frame):
        self._seed_cards(frame, "Load a seed before deriving a GPG key.", "gpg-bip85-seed", "gpg-bip85-pick:")

    def entropy_menu(self, frame):
        frame.header("Add Entropy", "back")
        y = frame.button(HEADER + 24, "Camera", "gpg-entropy-camera", icon=Icons.CAMERA, awesome=True)
        frame.button(y, "Bitcoin Seed Raw Entropy (BIP-85)", "gpg-entropy-seed", icon=Icons.SEED, awesome=True)

    def entropy_seeds(self, frame):
        self._seed_cards(frame, "Load a seed before deriving entropy.", "gpg-entropy-seed", "gpg-entropy-pick:")

    def entropy_index_screen(self, frame):
        app = self.app
        frame.header("Raw Entropy", "back")
        if not any(record.fingerprint == self.entropy_fp for record in self._seed_records()):
            frame.text("This seed is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
            return
        y = HEADER + 16
        y = app._account_selector(
            frame, y, self.entropy_index, True, 0, caption="Index",
            down="gpg-entropy-dec", up="gpg-entropy-inc", edit="gpg-entropy-edit", maximum=0x7FFFFFFF,
        )
        y = frame.text(ENTROPY_INDEX_NOTE, MARGIN, y, size=28, fill=MUTED)
        y = frame.text("Derivation Path:", MARGIN, y + 12, size=TITLE_SIZE, fill=MUTED)
        face = font(22, mono=True)
        for line in wrap(frame.draw, entropy_path(self.entropy_index), face, WIDTH - 2 * MARGIN):
            width = frame.draw.textlength(line, font=face)
            x = max(MARGIN, (WIDTH - width) / 2)
            frame.draw.text((x, y), line, font=face, fill=MUTED)
            frame.mark(line, frame.draw.textbbox((x, y), line, font=face))
            y += 30
        frame.button(y + 8, "Add Entropy", "gpg-entropy-add")

    def _show_entropy_result(self, mixed):
        message = "Entropy was added to the OS." if mixed else "The emulator uses the browser's random source."
        self.outcome = Outcome(True, message)
        self.build_result()
        self.app.go("gpg-result")
        self.app.scroll["gpg-result"] = 0

    def _pick_entropy_seed(self, fingerprint):
        try:
            fp = bytes.fromhex(fingerprint)
        except ValueError:
            return
        if not any(record.fingerprint == fp for record in self._seed_records()):
            self.app.set_error("This seed is no longer loaded.")
            return
        self.entropy_fp = fp
        self.entropy_index = 0
        self.app.go("gpg-entropy-index")

    def _edit_entropy_index(self):
        if self.entropy_fp not in self.app.session.fingerprints:
            self.app.set_error("This seed is no longer loaded.")
            return
        self.app.account_fp = self.entropy_fp
        self.app.account_text = str(self.entropy_index)
        self.app.account_for = "gpg-entropy"
        self.app.go("account")

    def _add_seed_entropy(self):
        root = None
        record = self.app.session.fingerprints.get(self.entropy_fp)
        if record is not None:
            for key in record.keys:
                if key.has_seed and getattr(key, "root", None) is not None:
                    root = key.root
                    break
        if root is None:
            self.show_error("This seed is no longer loaded.")
            return
        try:
            mixed = self.backend.mix_entropy(raw_entropy(root, self.entropy_index))
        except (ValueError, GpgError) as exc:
            self.show_error(str(exc))
            return
        self._show_entropy_result(mixed is not False)

    def _seed_cards(self, frame, empty, screen, prefix):
        app = self.app
        records = self._seed_records()
        if not records:
            frame.header("Select Seed", "back")
            frame.text(empty, MARGIN, HEADER + 24, size=TITLE_SIZE)
            return
        y = HEADER + 24
        placed = []
        for record in records:
            placed.append((y, record))
            y += app._key_card_height(frame, record) + 12
        offset = app._scroll_offset(screen, y, clearance=24)
        for top, record in placed:
            card_top = top - offset
            height = app._key_card_height(frame, record)
            if card_top >= HEIGHT or card_top + height <= HEADER:
                continue
            frame.draw.rounded_rectangle((MARGIN, card_top, WIDTH - MARGIN, card_top + height), radius=16, fill=WHITE, outline=LINE)
            app._key_card_body(frame, card_top, record, record.fingerprint, paint=True)
            frame.hit(
                (MARGIN, max(card_top, HEADER), WIDTH - MARGIN, min(card_top + height, HEIGHT)),
                prefix + record.fingerprint.hex(),
                record.nickname,
            )
        frame.header("Select Seed", "back")

    def bip85_options(self, frame):
        app = self.app
        frame.header("BIP-85 RSA Key", "back")
        if not any(record.fingerprint == self.bip85_fp for record in self._seed_records()):
            frame.text("This seed is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
            return
        y = HEADER + 16
        y = self._choice(frame, y, "Number of Bits", "gpg-bits", _BIP85_BITS, str(self.bip85_bits))
        y = app._account_selector(
            frame, y + 16, self.bip85_index, True, 0, caption="Index",
            down="gpg-bip85-dec", up="gpg-bip85-inc", edit="gpg-bip85-edit", maximum=0x7FFFFFFF,
        )
        y = frame.text("Derivation Path:", MARGIN, y, size=TITLE_SIZE, fill=MUTED)
        face = font(22, mono=True)
        for line in wrap(frame.draw, path_text(self.bip85_bits, self.bip85_index), face, WIDTH - 2 * MARGIN):
            width = frame.draw.textlength(line, font=face)
            frame.draw.text((max(MARGIN, (WIDTH - width) / 2), y), line, font=face, fill=MUTED)
            frame.mark(line, frame.draw.textbbox((max(MARGIN, (WIDTH - width) / 2), y), line, font=face))
            y += 30
        y += 8
        y = frame.text("BigSigner only generates primary keys, not subkeys.", MARGIN, y, size=28, fill=MUTED)
        frame.button(y + 16, "Continue", "gpg-bip85-continue")
        if app.open_dropdown == "gpg-bits":
            app._dropdown_menu(frame, self._choice_box, "gpg-bits", _BIP85_BITS, str(self.bip85_bits))

    def bip85_details(self, frame):
        app = self.app
        frame.header("Primary Key", "back")
        y = HEADER + 16
        y = self._choice(frame, y, "Usage", "gpg-role", _BIP85_ROLES, self.bip85_role)
        y = self._bip85_value(frame, y + 16, "Name", self.bip85_name, "Required", "gpg-bip85-name")
        y = self._bip85_value(frame, y + 16, "Email", self.bip85_email, "Optional", "gpg-bip85-email")
        expires = "No Expiration" if not self.bip85_expires else (
            f"{self.bip85_expires['year']:04d}-{self.bip85_expires['month']:02d}-{self.bip85_expires['day']:02d}"
        )
        y = self._bip85_value(frame, y + 16, "Expires", expires, expires, "gpg-bip85-expire")
        y = frame.text("Created " + creation_text() + ", as BIP-85 requires.", MARGIN, y + 12, size=28, fill=MUTED)
        frame.button(y + 16, "Create Key", "gpg-bip85-create", enabled=bool(self.bip85_name.strip()))
        if app.open_dropdown == "gpg-role":
            app._dropdown_menu(frame, self._choice_box, "gpg-role", _BIP85_ROLES, self.bip85_role)

    def _bip85_value(self, frame, y, label, value, placeholder, action):
        y = frame.text(label, MARGIN, y, size=TITLE_SIZE, fill=MUTED)
        top = y + 8
        height = 64
        box = (MARGIN, top, WIDTH - MARGIN, top + height)
        frame.draw.rounded_rectangle(box, radius=14, fill=WHITE, outline=LINE, width=2)
        shown = value or placeholder
        face = font(TITLE_SIZE)
        room = box[2] - box[0] - 40
        if frame.draw.textlength(shown, font=face) > room:
            while shown and frame.draw.textlength(shown + "…", font=face) > room:
                shown = shown[:-1]
            shown += "…"
        _left, ascent, _right, descent = frame.draw.textbbox((0, 0), shown, font=face)
        text_x = MARGIN + 20
        text_y = top + (height - (descent - ascent)) / 2 - ascent
        frame.draw.text((text_x, text_y), shown, font=face, fill=INK if value else MUTED)
        frame.mark(shown, frame.draw.textbbox((text_x, text_y), shown, font=face))
        frame.hit(box, action, label)
        return box[3]

    def bip85_text(self, frame):
        title = "Email" if self.bip85_field == "email" else "Name"
        frame.header(title, "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        self.app._paint_hscroll_field(frame, box, self.bip85_draft, len(self.bip85_draft), title)
        frame.button(box[3] + 12, "Save", "gpg-bip85-text-save")
        self.app._passphrase_keyboard(frame)

    def review(self, frame):
        self.content(frame, "Load GPG Key", review=True)

    def result(self, frame):
        self.content(frame, "Success" if self.outcome.ok else "Error", footer=("Done", "gpg-home", True))

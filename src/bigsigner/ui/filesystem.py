"""File System screens, using the same storage and keyboard as imports/exports."""

from pathlib import Path
import base64
import binascii
import hashlib
import re
import sys

from .. import archive, file_qr, sdcard
from ..diskimage import BurnResult, CardBurner, header_from_bytes, header_from_path, looks_like_disk_image
from .canvas import BLUE, BODY_SIZE, GREEN, HEADER, HEIGHT, INK, LINE, MARGIN, MUTED, RED, TITLE_SIZE, WHITE, WIDTH, Frame, Icons, font, wrap
from .text_editor import TextEditor


class _Ready:
    """A finished burn, used when the page cannot start a thread."""

    def __init__(self, result):
        self._result = result

    def done(self):
        return True

    def result(self):
        return self._result


OPEN_LIMIT = 50_000
SEQUENCE_NOTE = "Scanning content spread over a sequence of QR codes is not supported. Only a single QR code was captured. Its raw content will be used."
SCAN_NOTE = "Non-textual data may not scan, or may come back as different content. Encode it in base64 and decode it after scanning."
BINARY_QR_NOTE = "Non-textual data may not scan, or may come back as different content."
BASE64_NOTE = "This content is encoded in base64."
SD_DELETE_NOTE = "Deleted content on SD cards may still be restored. Wipe the SD card thoroughly before using it in a device connected to the internet. Deleting a file does not securely erase its contents."
_BASE64_BODY = re.compile(rb"[A-Za-z0-9+/]+={0,2}\Z")


def is_text(data):
    return sdcard.ascii_text(data)


def decoded_base64(data: bytes) -> bytes | None:
    """The decoded bytes of one base64 value, or None when data is not that.

    Spaces are rejected. One newline at the end is allowed. The alphabet is
    the standard base64 alphabet, including padding.
    """
    body = data[:-1] if data.endswith(b"\n") else data
    if not body or _BASE64_BODY.fullmatch(body) is None or len(body) % 4:
        return None
    try:
        return base64.b64decode(body, validate=True)
    except (ValueError, binascii.Error):
        return None


class FileSystemUI:
    def __init__(self, app):
        self.app = app
        self.editor = TextEditor(OPEN_LIMIT)
        self.path = ""
        self.storage = "sd"
        self.sd_missing = False
        self.is_new = False
        self.data = b""
        self.base64_decoded = b""
        self.name_mode = "create"
        self.transfer = "move"
        self.destination_storage = "sd"
        self.destination_dir = ""
        self.file_kind = ""
        self.file_target = ""
        self.file_done = 0
        self.file_total = 1
        self.file_shown = False
        self.file_future = None
        self.file_executor = None
        self.qr_parts: list = []
        self.qr_index = 0
        self.qr_note = ""
        self.qr_mono = ""
        self.qr_command = ""
        self._text_key = None
        self._text_value = False
        self._image_key = None
        self._image_value = False
        self.burner = CardBurner()
        self.burn_asc_files: list[str] = []
        self.burn_signature = ""
        self.burn_status = ""
        self.burn_done = 0
        self.burn_total = 1
        self.burn_shown = False
        self.burn_future = None
        self.burn_executor = None
        self.burn_ok = False
        self.burn_message = ""
        self.burn_remove = False
        self.burn_held = False
        self.burn_copy = ""
        self.sha_digest = ""
        self.sha_done = 0
        self.sha_total = 1
        self.sha_shown = False
        self.sha_future = None
        self.sha_executor = None
        self._sha_qr_image = None
        self._sha_qr_key = None
        self.painters = {
            "filesystem": app._storage,
            "fs-details": self.details,
            "fs-new-source": self.new_source,
            "fs-edit": self.edit,
            "fs-binary": self.binary,
            "fs-name": self.name,
            "fs-move-storage": self.move_storage,
            "fs-move": self.move_browser,
            "fs-delete": self.delete_warning,
            "fs-qr-warning": self.qr_warning,
            "fs-base64": self.base64_choice,
            "fs-qr-guide": self.guide,
            "fs-burn-verify": self.burn_verify,
            "fs-burn-checksums": self.burn_checksums,
            "fs-burn-progress": self.burn_progress,
            "fs-burn-result": self.burn_result,
            "fs-sha-progress": self.sha_progress,
            "fs-sha256": self.sha_result,
            "fs-file-progress": self.file_progress,
        }

    def open(self):
        app = self.app
        if app.screen == "wallet":
            app._restore_wallet_accounts()
        app.sd_mode = "manage"
        app.sd_dir = ""
        app.back = []
        app.screen = "filesystem"
        app.menu = app.add_menu = False
        app.open_dropdown = None

    def _show_filesystem(self):
        """Leave a file flow and show the SD Card and Temporary FS choice."""
        app = self.app
        app.sd_mode = "manage"
        app.sd_dir = ""
        app.back = []
        app.screen = "filesystem"
        app.confirm = None
        app.menu = app.add_menu = False
        app.open_dropdown = None

    def act(self, action):
        app = self.app
        try:
            if action.startswith("fs-select:"):
                self.path = action[len("fs-select:"):]
                self.storage = app.sd_storage
                sdcard.file_size(self.path, storage=self.storage)
                self.sd_missing = False
                app.scroll["fs-details"] = 0
                app.go("fs-details")
            elif action.startswith("fs-move-storage:"):
                self.destination_storage = action.split(":", 1)[1]
                sdcard.list_folder("", storage=self.destination_storage)
                self.destination_dir = ""
                app.scroll["fs-move"] = 0
                app.go("fs-move")
            elif action.startswith("fs-move-into:"):
                self.destination_dir = action.split(":", 1)[1]
                app.scroll["fs-move"] = 0
            elif action == "fs-move-up":
                self.destination_dir = sdcard.parent_path(self.destination_dir)
                app.scroll["fs-move"] = 0
            elif action == "fs-move-here":
                target = sdcard.child_path(self.destination_dir, Path(self.path).name)
                sdcard.move_file(self.path, target, storage=self.storage, destination_storage=self.destination_storage)
                self.storage, self.path = self.destination_storage, target
                self.to_browser()
                app.set_notice("The file was moved.")
            elif action in ("fs-copy-folder", "fs-gzip-folder"):
                suggested = Path(self.path).name
                if action == "fs-gzip-folder":
                    suggested += ".gz"
                self.begin_name("copy" if action == "fs-copy-folder" else "gzip", suggested)
            elif action == "fs-gunzip-here":
                self._begin_file_job("gunzip", self.destination_dir)
            elif action == "fs-open":
                self.data = sdcard.read_bytes(self.path, storage=self.storage, max_bytes=OPEN_LIMIT)
                self.is_new = False
                self.open_data()
            elif action == "fs-show-qr":
                self._show_text_qr()
            elif action == "fs-show-binary":
                self._show_binary_qr()
            elif action == "fs-show-base64":
                self._show_base64_qr()
            elif action == "fs-qr-open":
                self._open_parts()
            elif action == "fs-qr-prev":
                self._step_part(-1)
            elif action == "fs-qr-next":
                self._step_part(1)
            elif action == "fs-new-directory":
                self.begin_name("directory", "")
            elif action == "fs-new-file":
                app.go("fs-new-source")
            elif action == "fs-manual":
                self.is_new = True
                self.data = b""
                self.open_data()
            elif action == "fs-scan":
                app.scan_kind = "file"
                app.go("scan")
            elif action == "fs-focus":
                self.editor.focus(*getattr(app, "_last_tap", (MARGIN, HEADER)))
            elif action == "fs-hide":
                self.editor.keyboard = False
            elif action == "fs-save":
                self.data = self.editor.text.encode("ascii")
                self.save()
            elif action == "fs-save-binary":
                self.save()
            elif action == "fs-name-save":
                self.save_name()
            elif action == "fs-rename":
                self.begin_name("rename", Path(self.path).name)
            elif action == "fs-move":
                self.transfer = "move"
                app.go("fs-move-storage")
            elif action == "fs-copy":
                self.transfer = "copy"
                app.go("fs-move-storage")
            elif action == "fs-archive":
                self.transfer = "gunzip" if self._starts_with_gzip() else "gzip"
                app.go("fs-move-storage")
            elif action == "fs-sha256":
                self.begin_sha()
            elif action == "fs-delete":
                message = f'Delete "{Path(self.path).name}"?'
                if self.storage == "sd" or app._text_height(Frame(), message, BODY_SIZE) > 320:
                    app.scroll["fs-delete"] = 0
                    app.go("fs-delete")
                else:
                    app.confirm = "fs-delete"
            elif action == "fs-delete-confirm":
                self.delete()
            elif action == "fs-burn":
                self.open_burn()
            elif action == "fs-burn-detached":
                self.open_detached()
            elif action == "fs-burn-checksums":
                self.open_checksums()
            elif action.startswith("fs-burn-asc:"):
                self.choose_checksum(action[len("fs-burn-asc:"):])
            elif action == "fs-burn-skip":
                app.confirm = "fs-burn-skip"
            elif action == "fs-burn-done":
                self.leave_burn_result()
                self._show_filesystem()
            elif action == "fs-qr-ok":
                app.back_one()
                self.open_data()
            elif action == "fs-base64-keep":
                self._leave_base64(self.data)
            elif action == "fs-base64-decode":
                self._leave_base64(self.base64_decoded)
        except (sdcard.SdError, UnicodeEncodeError) as exc:
            app.set_error(str(exc) if isinstance(exc, sdcard.SdError) else "Only ASCII text can be saved in this editor.")
        finally:
            app.add_menu = False

    def to_browser(self):
        app = self.app
        app.sd_mode = "manage"
        app.sd_storage = self.storage
        app.sd_dir = sdcard.parent_path(self.path)
        app.screen = "sd"
        app.back = ["filesystem"]
        app.confirm = None
        app.add_menu = False
        self.editor.load("")
        self.data = b""

    def begin_name(self, mode, name):
        app = self.app
        self.name_mode = mode
        app.filename = name
        app.filename_cursor = len(name)
        app.passphrase_mode = "lower"
        app.add_menu = False
        app.go("fs-name")

    def save_name(self):
        app = self.app
        name = app.filename
        if not name.strip() or name in (".", "..") or any(char in name for char in "/\\\x00\n\r"):
            raise sdcard.SdError("Choose a different name.")
        if self.name_mode == "rename":
            target = sdcard.child_path(sdcard.parent_path(self.path), name)
            sdcard.move_file(self.path, target, storage=self.storage)
            self.path = target
            app.back_one()
            app.set_notice("The file was renamed.")
            return
        if self.name_mode in ("copy", "gzip"):
            target = sdcard.child_path(self.destination_dir, name)
            if sdcard.path_exists(target, storage=self.destination_storage):
                raise sdcard.SdError("A file or directory already has that name.")
            self._begin_file_job(self.name_mode, target)
            return
        target = sdcard.child_path(app.sd_dir, name)
        if self.name_mode == "directory":
            sdcard.create_directory(target, storage=app.sd_storage)
            app.back_one()
            app.set_notice("The directory was created.")
        else:
            value = self.data.decode("ascii") if is_text(self.data) else self.data
            sdcard.create_file(target, value, storage=app.sd_storage)
            self.path, self.storage = target, app.sd_storage
            self.is_new = False
            self.to_browser()
            app.set_notice(f"Saved {name}.")

    def save(self):
        app = self.app
        if self.is_new:
            name = "file.txt" if is_text(self.data) else "file.bin"
            self.begin_name("create", app._unused_export_name(name))
        else:
            sdcard.write_text(self.path, self.editor.text, storage=self.storage)
            self.editor.original = self.editor.text
            app.set_notice("The file was saved.")

    def delete(self):
        sdcard.delete_file(self.path, storage=self.storage)
        self.to_browser()
        self.app.set_notice("The file was deleted.")

    def open_data(self):
        app = self.app
        if is_text(self.data):
            self.editor.load(self.data.decode("ascii"))
            app.passphrase_mode = "lower"
            app.go("fs-edit")
        else:
            app.scroll["fs-binary"] = 0
            app.go("fs-binary")

    def accept_qr(self, text):
        app = self.app
        data = text if isinstance(text, bytes) else text.encode("utf-8")
        prefix = text.decode("latin-1") if isinstance(text, bytes) else text
        if len(data) > OPEN_LIMIT:
            app.set_error("The QR code content is larger than 50 KB.")
            app.back_one()
            return
        app.back_one()
        self.data = data
        self.is_new = True
        # Prefixes of UR, BBQr, Specter and common numbered-part transports.
        if re.match(r"^(?:ur:|b\$|p\d+of\d+\b|\d+[/:-]\d+\s|\d+of\d+\s)", prefix.lstrip(), re.I):
            app.go("fs-qr-warning")
            return
        decoded = decoded_base64(data)
        if decoded is not None:
            self.base64_decoded = decoded
            app.go("fs-base64")
            return
        self.open_data()

    def _leave_base64(self, data: bytes):
        if self.app.screen != "fs-base64":
            return
        self.data = data
        self.app.back_one()
        self.open_data()

    def before_back(self):
        app = self.app
        if app.screen == "fs-burn-result":
            self.leave_burn_result()
        if app.screen == "fs-details" and self.sd_missing:
            self._show_filesystem()
            return True
        if app.screen != "fs-edit":
            return False
        if self.editor.changed:
            app.confirm = "fs-discard"
            return True
        self.editor.load("")
        self.data = b""
        return False

    def discard(self):
        self.editor.load(self.editor.original)
        self.app.back_one()

    def _file_bytes(self, limit: int) -> bytes:
        size = sdcard.file_size(self.path, storage=self.storage)
        if size > limit:
            raise sdcard.SdError("That file is too large.")
        return sdcard.read_bytes(self.path, storage=self.storage, max_bytes=limit)

    def _show_text_qr(self):
        data = self._file_bytes(file_qr.QR_SPLIT_LIMIT)
        if not is_text(data):
            raise sdcard.SdError("That file is not text.")
        if len(data) <= file_qr.TEXT_DIRECT:
            self._show_codes([data])
        else:
            self._show_guide(file_qr.spaced_parts(file_qr.gzip_base64(data)))

    def _show_binary_qr(self):
        self._show_codes([self._file_bytes(file_qr.BINARY_DIRECT)], note=BINARY_QR_NOTE)

    def _show_base64_qr(self):
        data = self._file_bytes(file_qr.QR_SPLIT_LIMIT)
        if len(data) <= file_qr.BASE64_DIRECT:
            encoded = file_qr.plain_base64(data)
            self._show_codes(
                [encoded],
                note="Save this QR code as file. Decoding the file is done with:",
                mono=file_qr.BASE64_DECODE,
            )
        else:
            self._show_guide(file_qr.spaced_parts(file_qr.gzip_base64(data)))

    def _show_codes(self, parts, note="", mono=""):
        from .app import QR_BRIGHTNESS_DEFAULT

        app = self.app
        self.qr_parts = parts
        self.qr_index = 0
        self.qr_note = note
        self.qr_mono = mono
        app.qr_text = parts[0]
        app._open_qr(parts[0])
        app.qr_kind = "file"
        app.qr_brightness = QR_BRIGHTNESS_DEFAULT

    def _show_guide(self, parts):
        app = self.app
        self.qr_parts = parts
        self.qr_index = 0
        self.qr_note = ""
        self.qr_mono = ""
        self.qr_command = file_qr.recovery_command(Path(self.path).name)
        app.scroll["fs-qr-guide"] = 0
        app.go("fs-qr-guide")

    def _open_parts(self):
        if not self.qr_parts:
            return
        self.qr_index = 0
        self._show_codes(self.qr_parts)

    def _step_part(self, delta: int):
        if len(self.qr_parts) < 2 or self.app.screen != "qr":
            return
        self.qr_index = (self.qr_index + delta) % len(self.qr_parts)
        self.app.qr_text = self.qr_parts[self.qr_index]
        self.app.qr_zoom = None

    def _starts_with_gzip(self) -> bool:
        try:
            return sdcard.read_prefix(self.path, storage=self.storage, size=2).startswith(b"\x1f\x8b")
        except sdcard.SdError:
            return False

    def _is_disk_image(self, size: int) -> bool:
        key = (self.storage, self.path, size)
        if self._image_key != key:
            self._image_key = key
            self._image_value = looks_like_disk_image(self._image_header())
        return self._image_value

    def _image_header(self) -> bytes:
        """First 512 image bytes. Gzip is inflated only that far."""
        path = sdcard.native_path(self.path, storage=self.storage)
        if path is not None:
            return header_from_path(path)
        try:
            data = b"".join(sdcard.read_chunks(self.path, storage=self.storage))
        except sdcard.SdError:
            return b""
        return header_from_bytes(data)

    def _signature_path(self) -> str:
        return sdcard.child_path(sdcard.parent_path(self.path), Path(self.path).name + ".asc")

    def open_burn(self):
        size = sdcard.file_size(self.path, storage=self.storage)
        if self._is_ascii_file(size) or not self._is_disk_image(size):
            return
        self.app.scroll["fs-burn-verify"] = 0
        self.app.go("fs-burn-verify")

    def open_detached(self):
        signature = self._signature_path()
        if not sdcard.file_exists(signature, storage=self.storage):
            return
        self.burn_signature = signature
        self.app.gpg.operation = "burn-detached"
        self.app.gpg.clock = "date"
        self.app.go("gpg-date")

    def open_checksums(self):
        parent = sdcard.parent_path(self.path)
        entries = sdcard.list_folder(parent, storage=self.storage)
        self.burn_asc_files = [
            item["name"] for item in entries
            if item["kind"] == "file" and item["name"].lower().endswith(".asc")
        ]
        self.app.scroll["fs-burn-checksums"] = 0
        self.app.go("fs-burn-checksums")

    def choose_checksum(self, name: str):
        if name not in self.burn_asc_files:
            return
        self.burn_signature = sdcard.child_path(sdcard.parent_path(self.path), name)
        self.app.gpg.operation = "burn-checksums"
        self.app.gpg.clock = "date"
        self.app.go("gpg-date")

    def burn_verify(self, frame):
        frame.header("Verify Image", "back")
        y = frame.text(
            "How would you like to verify the GPG signature of this file?",
            MARGIN, HEADER + 20, size=BODY_SIZE,
        )
        y = frame.text(
            "Continuing erases the SD card and writes this image.",
            MARGIN, y + 16, size=BODY_SIZE, fill=RED,
        )
        y += 16
        try:
            present = sdcard.file_exists(self._signature_path(), storage=self.storage)
        except sdcard.SdError:
            present = False
        y = frame.button(y, "Detached Signature", "fs-burn-detached", enabled=present)
        if not present:
            y = frame.text("A similar filename.asc file was not found.", MARGIN, y, size=28, fill=MUTED)
            y += 8
        y = frame.button(y, "Signed Checksum File", "fs-burn-checksums")
        frame.button(y, "Skip Verification", "fs-burn-skip")

    def burn_checksums(self, frame):
        app = self.app
        end = self._checksum_flow(frame, False, 0)
        offset = app._scroll_offset("fs-burn-checksums", end, clearance=20)
        self._checksum_flow(frame, True, offset)
        frame.header("Signed Checksum File", "back")

    def _checksum_flow(self, frame, paint, offset):
        app = self.app
        y = HEADER + 20
        if not self.burn_asc_files:
            return app._flow_text(frame, y, "This folder has no .asc file.", paint, offset, BODY_SIZE, MUTED)
        y = app._flow_text(frame, y, "Choose a signed checksum file in this folder.", paint, offset, 28, MUTED)
        y += 8
        for name in self.burn_asc_files:
            y = app._flow_button(frame, y, name, f"fs-burn-asc:{name}", paint, offset)
        return y

    def start_signature_check(self):
        checksums = self.app.gpg.operation == "burn-checksums"
        relative, storage = self.burn_signature, self.storage
        only = Path(self.path).name if checksums else None
        timestamp = self.app.gpg.timestamp()
        backend = self.app.gpg.backend
        self.app.gpg.start(
            "verify",
            lambda: backend.verify(relative, storage, timestamp, checksums, only=only),
        )

    def finish_signature_check(self, outcome):
        self._drop_burn_detour()
        if outcome.ok:
            self.begin_burn()
            return
        self.burn_ok = False
        self.burn_message = outcome.message or "Signature verification failed."
        self.burn_remove = False
        self.burn_held = False
        self.burn_copy = ""
        self.app.screen = "fs-burn-result"
        self.app.scroll["fs-burn-result"] = 0
        self.app._arm_search_touch_quiet()

    def begin_burn(self):
        self._drop_burn_detour()
        self.burn_status = "Preparing the image\u2026"
        self.burn_done = 0
        self.burn_total = 1
        self.burn_shown = False
        self.burn_future = None
        self.app.confirm = None
        self.app.menu = False
        self.app.screen = "fs-burn-progress"

    def _drop_burn_detour(self):
        while self.app.back and self.app.back[-1] in ("gpg-date", "gpg-number", "gpg-working"):
            self.app.back.pop()

    def burn_progress(self, frame):
        message = self.burn_status or "Preparing the image\u2026"
        face = font(BODY_SIZE)
        lines = wrap(frame.draw, message, face, WIDTH - 2 * MARGIN) or [""]
        bar_h = 28
        bar_bottom = HEIGHT - 110
        bar_top = bar_bottom - bar_h
        text_h = len(lines) * (BODY_SIZE + 8)
        y = max(MARGIN, (HEIGHT - text_h) // 2)
        for line in lines:
            width = frame.draw.textlength(line, font=face)
            x = (WIDTH - width) / 2
            frame.draw.text((x, y), line, font=face, fill=INK)
            frame.mark(line, frame.draw.textbbox((x, y), line, font=face))
            y += BODY_SIZE + 8
        left, right = MARGIN, WIDTH - MARGIN
        frame.draw.rounded_rectangle((left, bar_top, right, bar_bottom), radius=10, outline=LINE, width=2, fill=WHITE)
        span = right - left - 8
        total = self.burn_total if self.burn_total > 0 else 1
        filled = int(span * min(1.0, self.burn_done / total))
        if filled > 0:
            frame.draw.rounded_rectangle(
                (left + 4, bar_top + 4, left + 4 + filled, bar_bottom - 4),
                radius=6, fill=BLUE,
            )
        self.burn_shown = True

    def burn_delay(self) -> float:
        if self.burn_future is None:
            return 0
        return 0 if self.burn_future.done() else 0.2

    def advance_burn(self):
        if self.app.screen != "fs-burn-progress" or not self.burn_shown:
            return
        try:
            if self.burn_future is None:
                if sys.platform in ("emscripten", "wasi"):
                    self.burn_future = _Ready(self._burn_job())
                else:
                    from concurrent.futures import ThreadPoolExecutor

                    if self.burn_executor is None:
                        self.burn_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bigsigner-burn")
                    self.burn_future = self.burn_executor.submit(self._burn_job)
                return
            if not self.burn_future.done():
                return
            result = self.burn_future.result()
        except Exception as exc:
            result = BurnResult(False, str(exc))
        self.finish_burn(result)

    def _burn_job(self) -> BurnResult:
        path = sdcard.native_path(self.path, storage=self.storage)
        if path is None:
            return BurnResult(False, "Burning an image requires the device.")
        return self.burner.burn(path, on_card=self.storage == "sd", progress=self._burn_progress)

    def _burn_progress(self, message: str, done: int, total: int):
        self.burn_status = message
        self.burn_done = done
        self.burn_total = max(1, total)

    def finish_burn(self, result: BurnResult):
        if self.burn_executor is not None:
            self.burn_executor.shutdown(wait=False)
            self.burn_executor = None
        self.burn_future = None
        self.burn_ok = result.ok
        self.burn_message = result.message
        self.burn_remove = result.remove_card
        self.burn_held = result.held
        self.burn_copy = result.copy_path
        self.app.screen = "fs-burn-result"
        self.app.scroll["fs-burn-result"] = 0
        self.app._arm_search_touch_quiet()

    def burn_result(self, frame):
        frame.header("Image Written" if self.burn_ok else "Error", "back")
        y = frame.text(self.burn_message, MARGIN, HEADER + 24, size=BODY_SIZE, fill=GREEN if self.burn_ok else RED)
        if self.burn_remove:
            y = frame.text("You can remove the SD card.", MARGIN, y + 16, size=BODY_SIZE)
        frame.button(max(y + 24, HEIGHT - 16 - frame.button_height("Done")), "Done", "fs-burn-done")

    def leave_burn_result(self):
        if self.burn_held:
            try:
                self.burner.release()
            except Exception:
                pass
            self.burn_held = False
        if self.burn_copy:
            try:
                Path(self.burn_copy).unlink(missing_ok=True)
            except OSError:
                pass
            self.burn_copy = ""

    def begin_sha(self):
        size = sdcard.file_size(self.path, storage=self.storage)
        if self.sha_executor is not None:
            self.sha_executor.shutdown(wait=False)
            self.sha_executor = None
        self.sha_digest = ""
        self.sha_done = 0
        self.sha_total = max(1, size)
        self.sha_shown = False
        self.sha_future = None
        self._sha_qr_image = None
        self._sha_qr_key = None
        self.app.confirm = None
        self.app.menu = False
        self.app.go("fs-sha-progress")

    def sha_delay(self) -> float:
        if self.sha_future is None:
            return 0
        return 0 if self.sha_future.done() else 0.2

    def advance_sha(self):
        if self.app.screen != "fs-sha-progress" or not self.sha_shown:
            return
        try:
            if self.sha_future is None:
                if sys.platform in ("emscripten", "wasi"):
                    self.sha_future = _Ready(self._sha_job())
                else:
                    from concurrent.futures import ThreadPoolExecutor

                    if self.sha_executor is None:
                        self.sha_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bigsigner-sha")
                    self.sha_future = self.sha_executor.submit(self._sha_job)
                return
            if not self.sha_future.done():
                return
            digest = self.sha_future.result()
        except Exception as exc:
            message = str(exc) if isinstance(exc, sdcard.SdError) else "Could not calculate SHA256."
            self.finish_sha(error=message)
            return
        self.finish_sha(digest)

    def _sha_job(self) -> str:
        digest = hashlib.sha256()
        read = 0
        for chunk in sdcard.read_chunks(self.path, storage=self.storage):
            digest.update(chunk)
            read += len(chunk)
            self.sha_done = read
            if read > self.sha_total:
                self.sha_total = read
        self.sha_done = self.sha_total = max(self.sha_total, read, 1)
        return digest.hexdigest()

    def finish_sha(self, digest: str = "", error: str = ""):
        if self.sha_executor is not None:
            self.sha_executor.shutdown(wait=False)
            self.sha_executor = None
        self.sha_future = None
        if error or not digest:
            self.sha_digest = ""
            self._sha_qr_image = None
            self._sha_qr_key = None
            if self.app.screen == "fs-sha-progress":
                self.app.back_one()
            self.app.set_error(error or "Could not calculate SHA256.")
            # A press that began on the calculation screen must not click File Details.
            self.app._arm_search_touch_quiet()
            return
        self.sha_digest = digest
        self._sha_qr_image = None
        self._sha_qr_key = None
        self.app.scroll["fs-sha256"] = 0
        self.app.screen = "fs-sha256"
        self.app._arm_search_touch_quiet()

    def _begin_file_job(self, kind, target):
        app = self.app
        if self.file_executor is not None:
            self.file_executor.shutdown(wait=False)
            self.file_executor = None
        self.file_kind = kind
        self.file_target = target
        self.file_done = 0
        self.file_total = 1
        if kind != "gunzip":
            self.file_total = max(1, sdcard.file_size(self.path, storage=self.storage))
        self.file_shown = False
        self.file_future = None
        app.confirm = None
        app.menu = False
        app.go("fs-file-progress")

    def file_delay(self) -> float:
        if self.file_future is None:
            return 0
        return 0 if self.file_future.done() else 0.2

    def advance_file(self):
        if self.app.screen != "fs-file-progress" or not self.file_shown:
            return
        try:
            if self.file_future is None:
                if sys.platform in ("emscripten", "wasi"):
                    self.file_future = _Ready(self._file_job())
                else:
                    from concurrent.futures import ThreadPoolExecutor

                    if self.file_executor is None:
                        self.file_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="bigsigner-file")
                    self.file_future = self.file_executor.submit(self._file_job)
                return
            if not self.file_future.done():
                return
            notice = self.file_future.result()
        except Exception as exc:
            message = str(exc) if isinstance(exc, sdcard.SdError) else "Could not finish that file."
            self.finish_file(error=message)
            return
        self.finish_file(notice)

    def _file_progress(self, done, total):
        self.file_done = done
        self.file_total = max(1, total)

    def _file_job(self) -> str:
        if self.file_kind == "copy":
            sdcard.copy_file(
                self.path, self.file_target,
                storage=self.storage, destination_storage=self.destination_storage,
                progress=self._file_progress,
            )
            return "The file was copied."
        if self.file_kind == "gzip":
            archive.gzip_file(
                self.path, self.file_target,
                storage=self.storage, destination_storage=self.destination_storage,
                progress=self._file_progress,
            )
            return "The file was compressed."
        archive.extract_gzip(
            self.path, self.file_target,
            storage=self.storage, destination_storage=self.destination_storage,
            progress=self._file_progress,
        )
        return "The file was extracted."

    def finish_file(self, notice: str = "", error: str = ""):
        app = self.app
        if self.file_executor is not None:
            self.file_executor.shutdown(wait=False)
            self.file_executor = None
        self.file_future = None
        if error or not notice:
            if app.screen == "fs-file-progress":
                app.back_one()
            app.set_error(error or "Could not finish that file.")
            app._arm_search_touch_quiet()
            return
        self.storage = self.destination_storage
        self.path = self.file_target if self.file_kind != "gunzip" else sdcard.child_path(self.destination_dir, "extracted")
        self.to_browser()
        app.set_notice(notice)
        app._arm_search_touch_quiet()

    def file_progress(self, frame):
        message = {"copy": "Copying\u2026", "gzip": "Compressing\u2026", "gunzip": "Extracting\u2026"}.get(self.file_kind, "Copying\u2026")
        self._progress_bar(frame, message, self.file_done, self.file_total)
        self.file_shown = True

    def sha_progress(self, frame):
        message = "Calculating SHA256\u2026"
        face = font(BODY_SIZE)
        lines = wrap(frame.draw, message, face, WIDTH - 2 * MARGIN) or [""]
        bar_h = 28
        bar_bottom = HEIGHT - 110
        bar_top = bar_bottom - bar_h
        text_h = len(lines) * (BODY_SIZE + 8)
        y = max(MARGIN, (HEIGHT - text_h) // 2)
        for line in lines:
            width = frame.draw.textlength(line, font=face)
            x = (WIDTH - width) / 2
            frame.draw.text((x, y), line, font=face, fill=INK)
            frame.mark(line, frame.draw.textbbox((x, y), line, font=face))
            y += BODY_SIZE + 8
        left, right = MARGIN, WIDTH - MARGIN
        frame.draw.rounded_rectangle((left, bar_top, right, bar_bottom), radius=10, outline=LINE, width=2, fill=WHITE)
        span = right - left - 8
        total = self.sha_total if self.sha_total > 0 else 1
        filled = int(span * min(1.0, self.sha_done / total))
        if filled > 0:
            frame.draw.rounded_rectangle(
                (left + 4, bar_top + 4, left + 4 + filled, bar_bottom - 4),
                radius=6, fill=BLUE,
            )
        self.sha_shown = True

    def _progress_bar(self, frame, message, done, total):
        face = font(BODY_SIZE)
        lines = wrap(frame.draw, message, face, WIDTH - 2 * MARGIN) or [""]
        bar_h = 28
        bar_bottom = HEIGHT - 110
        bar_top = bar_bottom - bar_h
        text_h = len(lines) * (BODY_SIZE + 8)
        y = max(MARGIN, (HEIGHT - text_h) // 2)
        for line in lines:
            width = frame.draw.textlength(line, font=face)
            x = (WIDTH - width) / 2
            frame.draw.text((x, y), line, font=face, fill=INK)
            frame.mark(line, frame.draw.textbbox((x, y), line, font=face))
            y += BODY_SIZE + 8
        left, right = MARGIN, WIDTH - MARGIN
        frame.draw.rounded_rectangle((left, bar_top, right, bar_bottom), radius=10, outline=LINE, width=2, fill=WHITE)
        span = right - left - 8
        total = total if total > 0 else 1
        filled = int(span * min(1.0, done / total))
        if filled > 0:
            frame.draw.rounded_rectangle(
                (left + 4, bar_top + 4, left + 4 + filled, bar_bottom - 4),
                radius=6, fill=BLUE,
            )

    def sha_result(self, frame):
        from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

        app = self.app
        light = _qr_light(QR_BRIGHTNESS_DEFAULT)
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
        control_h = 52
        bright_y = HEIGHT - 16 - control_h
        view_top = HEADER + 16
        view_bottom = bright_y - 12
        image = self._sha_code(_qr_image, light)
        face = font(TITLE_SIZE, mono=True)
        lines = wrap(frame.draw, self.sha_digest, face, WIDTH - 2 * MARGIN) or [""]
        line_h = TITLE_SIZE + 8
        text_top = view_top + image.height + 16
        content_end = text_top + len(lines) * line_h
        offset = app._scroll_offset("fs-sha256", content_end, clearance=HEIGHT - view_bottom)
        self._paste_visible(frame, image, (WIDTH - image.width) // 2, view_top - offset, HEADER, view_bottom)
        for index, line in enumerate(lines):
            y = text_top + index * line_h - offset
            # A line that would run into the brightness control waits until it fits.
            if y + TITLE_SIZE <= view_bottom and y + TITLE_SIZE > HEADER:
                frame.draw.text((MARGIN, y), line, font=face, fill=INK)
                frame.mark(line, frame.draw.textbbox((MARGIN, y), line, font=face))
        app._brightness_control(frame, bright_y)
        app._still_boxes.append((0, view_bottom, WIDTH, HEIGHT))
        frame.header("SHA256", "back")

    def _sha_code(self, qr_image, light):
        box = WIDTH - 2 * MARGIN
        key = (self.sha_digest, box, light)
        if self._sha_qr_image is None or self._sha_qr_key != key:
            self._sha_qr_image = qr_image(self.sha_digest, box, light)
            self._sha_qr_key = key
        return self._sha_qr_image

    @staticmethod
    def _paste_visible(frame, image, x, y, top, bottom):
        if y >= bottom or y + image.height <= top:
            return
        src_top = max(0, top - y)
        src_bottom = min(image.height, bottom - y)
        if src_bottom <= src_top:
            return
        frame.image.paste(
            image.crop((0, int(src_top), image.width, int(src_bottom))),
            (int(x), int(y + src_top)),
        )

    def _is_ascii_file(self, size: int) -> bool:
        key = (self.storage, self.path, size)
        if self._text_key != key:
            self._text_key = key
            self._text_value = sdcard.file_is_ascii_text(self.path, storage=self.storage)
        return self._text_value

    def details(self, frame):
        app = self.app
        try:
            size = sdcard.file_size(self.path, storage=self.storage)
            text = self._is_ascii_file(size)
        except sdcard.SdError as exc:
            self.sd_missing = self.storage == "sd" and str(exc) == "No SD card is available."
            frame.header("File Details", "back")
            frame.text(str(exc), MARGIN, HEADER + 24, size=TITLE_SIZE, fill=RED)
            return
        self.sd_missing = False
        end = self._details_flow(frame, size, text, False, 0)
        offset = app._scroll_offset("fs-details", end, clearance=20)
        self._details_flow(frame, size, text, True, offset)
        frame.header("File Details", "back")

    @staticmethod
    def centered(frame, text, y, size, *, mono=False, fill=INK):
        face = font(size, mono=mono)
        for line in wrap(frame.draw, text, face, WIDTH - 2 * MARGIN):
            width = frame.draw.textlength(line, font=face)
            frame.text(line, (WIDTH - width) / 2, y, size=size, mono=mono, fill=fill)
            y += size + 8
        return y

    def _details_flow(self, frame, size, text, paint, offset):
        app = self.app
        y = HEADER + 20
        size_text = f"{size:,} {'byte' if size == 1 else 'bytes'}"
        y = app._flow_text(frame, y, "Filename:", paint, offset, BODY_SIZE, MUTED)
        if paint:
            self.centered(frame, Path(self.path).name, y - offset, BODY_SIZE)
        y += app._text_height(frame, Path(self.path).name, BODY_SIZE) + 12
        size_font = BODY_SIZE
        while frame.draw.textlength(f"Size: {size_text}", font=font(size_font)) > WIDTH - 2 * MARGIN:
            size_font -= 1
        if paint:
            frame.text("Size:", MARGIN, y - offset, size=size_font, fill=MUTED)
            value_x = MARGIN + frame.draw.textlength("Size: ", font=font(size_font))
            frame.text(size_text, value_x, y - offset, size=size_font)
        y += size_font + 20
        y = app._flow_button(frame, y + 8, "Open", "fs-open", paint, offset, enabled=size <= OPEN_LIMIT)
        if size > OPEN_LIMIT:
            y = app._flow_text(frame, y, "Files larger than 50 KB cannot be opened.", paint, offset, 28, MUTED)
            y += 8
        if text:
            y = app._flow_button(frame, y, "Show QR", "fs-show-qr", paint, offset, enabled=size <= file_qr.QR_SPLIT_LIMIT)
            if size > file_qr.QR_SPLIT_LIMIT:
                y = app._flow_text(frame, y, "This file is too long to show as a QR code.", paint, offset, 28, MUTED)
                y += 8
        else:
            y = self._binary_qr_row(frame, y, size, paint, offset)
        y = self._action_row(frame, y, paint, offset, ("Rename", "fs-rename"), ("Move", "fs-move"))
        archive_label = "GUNZIP" if self._starts_with_gzip() else "GZIP"
        y = self._action_row(frame, y, paint, offset, ("Copy", "fs-copy"), (archive_label, "fs-archive"))
        y = app._flow_button(frame, y, "Calculate SHA256", "fs-sha256", paint, offset)
        if not text:
            image = self._is_disk_image(size)
            y = app._flow_button(frame, y, "Burn to SD Card", "fs-burn", paint, offset, enabled=image)
            if not image:
                y = app._flow_text(frame, y, "This file is not a disk image.", paint, offset, 28, MUTED)
                y += 8
        return app._flow_button(frame, y, "Delete", "fs-delete", paint, offset, color=RED)

    def _action_row(self, frame, y, paint, offset, left, right):
        gap = 12
        height = max(frame.button_height(left[0]), frame.button_height(right[0]))
        top = y - offset
        clip_top = getattr(frame, "clip_top", HEADER)
        clip_bottom = getattr(frame, "clip_bottom", HEIGHT)
        width = (WIDTH - 2 * MARGIN - gap) // 2
        if paint and top + height >= clip_top and top < clip_bottom:
            text_delta = frame._button_metrics(left[0], False)[4]
            frame.button_box(
                (MARGIN, top, MARGIN + width, top + height), left[0], left[1], text_delta=text_delta,
            )
            frame.button_box(
                (MARGIN + width + gap, top, WIDTH - MARGIN, top + height), right[0], right[1], text_delta=text_delta,
            )
        return y + height + 12

    def _binary_qr_row(self, frame, y, size, paint, offset):
        app = self.app
        label = "Show QR Code"
        if paint:
            self.centered(frame, label, y - offset, BODY_SIZE, fill=MUTED)
        y += app._text_height(frame, label, BODY_SIZE) + 8
        binary_ok = size <= file_qr.BINARY_DIRECT
        base64_ok = size <= file_qr.QR_SPLIT_LIMIT
        height = max(frame.button_height("Binary"), frame.button_height("Base64"))
        top = y - offset
        gap = 12
        width = (WIDTH - 2 * MARGIN - gap) // 2
        if paint and top + height > HEADER and top < HEIGHT:
            text_delta = frame._button_metrics("Base64", False)[4]
            frame.button_box(
                (MARGIN, top, MARGIN + width, top + height), "Binary", "fs-show-binary",
                text_delta=text_delta, enabled=binary_ok,
            )
            frame.button_box(
                (MARGIN + width + gap, top, WIDTH - MARGIN, top + height), "Base64", "fs-show-base64",
                text_delta=text_delta, enabled=base64_ok,
            )
        y += height + 12
        if not binary_ok or not base64_ok:
            y = app._flow_text(frame, y, "Large files cannot be displayed in some QR formats.", paint, offset, 28, MUTED)
            y += 8
        return y

    def guide(self, frame):
        app = self.app
        label = "Show QR Code" if len(self.qr_parts) == 1 else "Show QR Codes"
        button_h = frame.button_height(label)
        footer = HEIGHT - 16 - button_h
        frame.clip_bottom = footer - 20
        end = self._guide_body(frame, False, 0)
        offset = app._scroll_offset("fs-qr-guide", end, clearance=HEIGHT - footer + 16)
        self._guide_body(frame, True, offset)
        frame.clip_bottom = HEIGHT
        frame.button(footer, label, "fs-qr-open")
        frame.header("File QR", "back")

    def _guide_body(self, frame, paint, offset):
        app = self.app
        count = len(self.qr_parts)
        if count <= 1:
            lead = "This file is large and has been compressed to 1 QR code."
        else:
            lead = f"This file is large and has been split over {count} QR codes."
        intro = (
            f"{lead} "
            "Save the content of each QR code in a file. "
            "Name them file-part-00, file-part-01, and so on, starting with the first QR code. "
            "On a Mac or Linux, run:"
        )
        y = HEADER + 20
        y = app._flow_text(frame, y, intro, paint, offset, BODY_SIZE)
        y += 8
        return self._command_block(frame, y, paint, offset)

    def _command_block(self, frame, y, paint, offset):
        """The recovery command at the title size. Quoted words are not split on their spaces."""
        size = TITLE_SIZE
        face = font(size, mono=True)
        width = WIDTH - 2 * MARGIN
        lines = []
        for paragraph in self.qr_command.split("\n"):
            current = ""
            for word in file_qr.shell_words(paragraph):
                trial = word if not current else f"{current} {word}"
                if frame.draw.textlength(trial, font=face) <= width:
                    current = trial
                    continue
                if current:
                    lines.append(current)
                if frame.draw.textlength(word, font=face) <= width:
                    current = word
                    continue
                chunk = ""
                for char in word:
                    if frame.draw.textlength(chunk + char, font=face) <= width:
                        chunk += char
                    else:
                        lines.append(chunk)
                        chunk = char
                current = chunk
            if current:
                lines.append(current)
        clip_top = getattr(frame, "clip_top", HEADER)
        clip_bottom = getattr(frame, "clip_bottom", HEIGHT)
        for line in lines:
            shown = y - offset
            # A line that starts above the button still has to finish above it.
            if paint and shown >= clip_top and shown + size <= clip_bottom:
                frame.draw.text((MARGIN, shown), line, font=face, fill=INK)
                frame.mark(line, frame.draw.textbbox((MARGIN, shown), line, font=face))
            y += size + 8
        return y

    def qr(self, frame):
        from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

        app = self.app
        many = len(self.qr_parts) > 1
        top = HEADER + 16
        light = _qr_light(QR_BRIGHTNESS_DEFAULT)
        frame.draw.rectangle((0, 0, WIDTH, HEIGHT), fill=light)
        if many:
            bright_y = HEIGHT - 88 - 12 - 52
            box = min(WIDTH - 2 * MARGIN, bright_y - 12 - top)
        else:
            below = 52 + 16
            if self.qr_note:
                below += app._text_height(frame, self.qr_note, 28) + 8
            if self.qr_mono:
                below += app._text_height(frame, self.qr_mono, 28, mono=True) + 8
            box = min(WIDTH - 2 * MARGIN, HEIGHT - 16 - below - top)
        image = _qr_image(app.qr_text, max(160, box), light)
        frame.image.paste(image, ((WIDTH - image.width) // 2, top))
        if many:
            app._brightness_control(frame, HEIGHT - 88 - 12 - 52)
            app._format_switcher(
                frame, f"{self.qr_index + 1} of {len(self.qr_parts)}", "fs-qr-prev", "fs-qr-next",
            )
        else:
            bright_y = top + image.height + 12
            app._brightness_control(frame, bright_y)
            y = bright_y + 52 + 12
            if self.qr_note:
                fill = MUTED if self.qr_note == BINARY_QR_NOTE else INK
                y = frame.text(self.qr_note, MARGIN, y, size=28, fill=fill)
            if self.qr_mono:
                frame.text(self.qr_mono, MARGIN, y + 4, size=28, mono=True)
        frame.header("File QR", "back")

    def new_source(self, frame):
        frame.header("New File", "back")
        y = frame.button(HEADER + 24, "Manual Entry", "fs-manual")
        y = frame.button(y, "Scan QR Code", "fs-scan", icon=Icons.CAMERA, awesome=True)
        frame.text(SCAN_NOTE, MARGIN, y, size=28, fill=MUTED)

    def base64_choice(self, frame):
        frame.header("New File", "back")
        y = frame.text(BASE64_NOTE, MARGIN, HEADER + 24, size=BODY_SIZE)
        y = frame.button(y + 12, "Keep Original Data", "fs-base64-keep")
        frame.button(y, "Decode Base64", "fs-base64-decode")

    def edit(self, frame):
        app = self.app
        from .app import KEYBOARD_TOP

        keyboard = self.editor.keyboard
        button = "Hide Keyboard" if keyboard else "Save"
        button_h = frame.button_height(button, icon=keyboard)
        bottom = KEYBOARD_TOP - 12 if keyboard else HEIGHT - 16
        button_y = bottom - button_h
        if keyboard:
            frame.hit((0, 0, WIDTH, HEIGHT), "fs-hide", "outside")
        self.editor.paint(frame, (MARGIN, HEADER + 16, WIDTH - MARGIN, button_y - 12))
        if keyboard:
            frame.button(button_y, button, "fs-hide", icon=Icons.CHEVRON_DOWN)
            app._passphrase_keyboard(frame)
        else:
            frame.button(button_y, button, "fs-save", enabled=self.is_new or self.editor.changed)
        frame.header("ASCII Text File", "back")

    def binary(self, frame):
        app = self.app
        size = TITLE_SIZE
        while frame.draw.textlength("ff ff ff ff ff ff ff ff", font=font(size, mono=True)) > WIDTH - 2 * MARGIN:
            size -= 1
        line_h = size + 8
        # Eight bytes per row, as in OP_RETURN. Only visible rows are formatted.
        rows = (len(self.data) + 7) // 8
        button_h = frame.button_height("Save") if self.is_new else 0
        bottom = HEIGHT - button_h - 36 if self.is_new else HEIGHT - 20
        label_height = TITLE_SIZE + 12
        top = HEADER + 16 + label_height
        offset = app._scroll_offset("fs-binary", top + rows * line_h, clearance=HEIGHT - bottom)
        label_y = HEADER + 16 - offset
        if label_y + TITLE_SIZE + 8 > HEADER:
            frame.text("Hex Content:", MARGIN, label_y, size=TITLE_SIZE, fill=MUTED)
        first = max(0, (offset - label_height) // line_h)
        for row in range(first, min(rows, first + (bottom - HEADER) // line_h + 2)):
            y = top + row * line_h - offset
            if y < HEADER or y + line_h > bottom:
                continue
            value = " ".join(f"{byte:02x}" for byte in self.data[row * 8:row * 8 + 8])
            frame.text(value, MARGIN, y, size=size, mono=True)
        if self.is_new:
            frame.button(HEIGHT - 16 - button_h, "Save", "fs-save-binary")
        frame.header("Binary File", "back")

    def name(self, frame):
        app = self.app
        title = {
            "directory": "New Folder", "create": "New File", "rename": "Rename File",
            "copy": "Copy File", "gzip": "GZIP File",
        }[self.name_mode]
        frame.header(title, "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        app._paint_hscroll_field(frame, box, app.filename, app.filename_cursor, "Name")
        enabled = bool(app.filename.strip()) and (self.name_mode != "rename" or app.filename != Path(self.path).name)
        frame.button(box[3] + 12, "Save", "fs-name-save", enabled=enabled)
        app._passphrase_keyboard(frame)

    def move_storage(self, frame):
        title = {"move": "Move File", "copy": "Copy File", "gzip": "GZIP File", "gunzip": "GUNZIP File"}[self.transfer]
        frame.header(title, "back")
        y = frame.button(HEADER + 24, "SD Card", "fs-move-storage:sd")
        frame.button(y, "Temporary FS", "fs-move-storage:temporary")

    def move_browser(self, frame):
        app = self.app
        saved = app.sd_dir, app.sd_storage, app.sd_mode
        app.sd_dir, app.sd_storage, app.sd_mode = self.destination_dir, self.destination_storage, self.transfer
        try:
            app._sd(frame)
        finally:
            app.sd_dir, app.sd_storage, app.sd_mode = saved

    def delete_warning(self, frame):
        app = self.app
        message = f'Delete "{Path(self.path).name}"?'
        if self.storage == "sd":
            message += "\n\n" + SD_DELETE_NOTE
        end = HEADER + 24 + app._text_height(frame, message, TITLE_SIZE)
        offset = app._scroll_offset("fs-delete", end, clearance=140)
        frame.text(message, MARGIN, HEADER + 24 - offset, size=TITLE_SIZE, fill=RED)
        # Footer stays clear of the scrolling warning.
        from .canvas import PAPER
        frame.draw.rectangle((0, HEIGHT - 120, WIDTH, HEIGHT), fill=PAPER)
        app._dialog_button(frame, (MARGIN, HEIGHT - 96, 234, HEIGHT - 24), "Cancel", "back", (132, 138, 148))
        app._dialog_button(frame, (246, HEIGHT - 96, WIDTH - MARGIN, HEIGHT - 24), "Confirm", "fs-delete-confirm", RED)
        frame.header("Delete File", "back")

    def qr_warning(self, frame):
        frame.header("New File", "back")
        frame.text(SEQUENCE_NOTE, MARGIN, HEADER + 24, size=BODY_SIZE, fill=RED)
        frame.button(HEIGHT - 110, "OK", "fs-qr-ok")

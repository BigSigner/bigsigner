"""File System screens, using the same storage and keyboard as imports/exports."""

from pathlib import Path
import re

from .. import sdcard
from .canvas import BODY_SIZE, HEADER, HEIGHT, INK, MARGIN, MUTED, RED, TITLE_SIZE, WIDTH, Frame, Icons, font, wrap
from .text_editor import TextEditor


OPEN_LIMIT = 50_000
SEQUENCE_NOTE = "Scanning content spread over a sequence of QR codes is not supported. Only a single QR code was captured. Its raw content will be used."
SD_DELETE_NOTE = "Deleted content on SD cards may still be restored. Wipe the SD card thoroughly before using it in a device connected to the internet. Deleting a file does not securely erase its contents."


def is_text(data):
    return all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in data)


class FileSystemUI:
    def __init__(self, app):
        self.app = app
        self.editor = TextEditor(OPEN_LIMIT)
        self.path = ""
        self.storage = "sd"
        self.is_new = False
        self.data = b""
        self.name_mode = "create"
        self.destination_storage = "sd"
        self.destination_dir = ""
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

    def act(self, action):
        app = self.app
        try:
            if action.startswith("fs-select:"):
                self.path = action[len("fs-select:"):]
                self.storage = app.sd_storage
                sdcard.file_size(self.path, storage=self.storage)
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
            elif action == "fs-open":
                self.data = sdcard.read_bytes(self.path, storage=self.storage, max_bytes=OPEN_LIMIT)
                self.is_new = False
                self.open_data()
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
                app.go("fs-move-storage")
            elif action == "fs-delete":
                message = f'Delete "{Path(self.path).name}"?'
                if self.storage == "sd" or app._text_height(Frame(), message, BODY_SIZE) > 320:
                    app.scroll["fs-delete"] = 0
                    app.go("fs-delete")
                else:
                    app.confirm = "fs-delete"
            elif action == "fs-delete-confirm":
                self.delete()
            elif action == "fs-qr-ok":
                app.back_one()
                self.open_data()
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
        self.open_data()

    def before_back(self):
        app = self.app
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

    def details(self, frame):
        app = self.app
        try:
            size = sdcard.file_size(self.path, storage=self.storage)
        except sdcard.SdError as exc:
            frame.header("File Details", "back")
            frame.text(str(exc), MARGIN, HEADER + 24, size=TITLE_SIZE, fill=RED)
            return
        end = self._details_flow(frame, size, False, 0)
        offset = app._scroll_offset("fs-details", end, clearance=20)
        self._details_flow(frame, size, True, offset)
        frame.header("File Details", "back")

    @staticmethod
    def centered(frame, text, y, size, *, mono=False):
        face = font(size, mono=mono)
        for line in wrap(frame.draw, text, face, WIDTH - 2 * MARGIN):
            width = frame.draw.textlength(line, font=face)
            frame.text(line, (WIDTH - width) / 2, y, size=size, mono=mono)
            y += size + 8
        return y

    def _details_flow(self, frame, size, paint, offset):
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
        y = app._flow_button(frame, y, "Rename", "fs-rename", paint, offset)
        y = app._flow_button(frame, y, "Move", "fs-move", paint, offset)
        return app._flow_button(frame, y, "Delete", "fs-delete", paint, offset, color=RED)

    def new_source(self, frame):
        frame.header("New File", "back")
        y = frame.button(HEADER + 24, "Manual Entry", "fs-manual")
        frame.button(y, "Scan QR Code", "fs-scan", icon=Icons.CAMERA, awesome=True)

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
        title = {"directory": "New Directory", "create": "New File", "rename": "Rename File"}[self.name_mode]
        frame.header(title, "back")
        box = (MARGIN, HEADER + 16, WIDTH - MARGIN, HEADER + 88)
        app._paint_hscroll_field(frame, box, app.filename, app.filename_cursor, "Name")
        enabled = bool(app.filename.strip()) and (self.name_mode != "rename" or app.filename != Path(self.path).name)
        frame.button(box[3] + 12, "Save", "fs-name-save", enabled=enabled)
        app._passphrase_keyboard(frame)

    def move_storage(self, frame):
        frame.header("Move File", "back")
        y = frame.button(HEADER + 24, "SD Card", "fs-move-storage:sd")
        frame.button(y, "Temporary FS", "fs-move-storage:temporary")

    def move_browser(self, frame):
        app = self.app
        saved = app.sd_dir, app.sd_storage, app.sd_mode
        app.sd_dir, app.sd_storage, app.sd_mode = self.destination_dir, self.destination_storage, "move"
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

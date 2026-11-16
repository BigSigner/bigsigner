"""Storage mutations and the File System screens, including bounded viewers."""

import base64
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from bigsigner import sdcard
from bigsigner.qr import MAX_BYTE_PAYLOAD
from bigsigner.ui.app import App, QR_BRIGHTNESS_DEFAULT
from bigsigner.ui.canvas import BLUE, HEADER, HEIGHT, MARGIN, WIDTH
from bigsigner.ui.filesystem import OPEN_LIMIT, SD_DELETE_NOTE, SEQUENCE_NOTE
from test_sdcard import _tap


@pytest.fixture(autouse=True)
def temporary_memory(monkeypatch):
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", True)
    monkeypatch.setattr(sdcard, "_temporary_memory", {"dirs": set(), "files": {}})


def _browser(files=None, storage="sd", dirs=None):
    sdcard.mount_memory({"files": files or {}, "dirs": dirs or []})
    if storage == "temporary":
        for directory in dirs or []:
            sdcard.create_directory(directory, storage="temporary")
        for path, data in (files or {}).items():
            sdcard.create_file(path, data.encode("ascii") if isinstance(data, str) else data, storage="temporary")
    app = App()
    app.screen = "keys"
    app._act("menu")
    _tap(app, "File System")
    assert app.screen == "filesystem"
    _tap(app, "SD Card" if storage == "sd" else "Temporary FS")
    assert app.screen == "sd"
    app.render()
    return app


def _details(data=b"hello", storage="sd", name="file.txt"):
    value = data if isinstance(data, str) else {"base64": base64.b64encode(data).decode()} if storage == "sd" else data
    app = _browser({name: value}, storage=storage)
    _tap(app, name)
    assert app.screen == "fs-details"
    app.render()
    return app


@pytest.mark.parametrize("storage", ["sd", "temporary"])
def test_create_rename_move_delete_and_card_change_notifications(storage):
    sdcard.mount_memory({"files": {}})
    sdcard.create_directory("folder", storage=storage)
    sdcard.create_file("a.txt", b" a\r\nb \n", storage=storage)
    assert sdcard.file_size("a.txt", storage=storage) == 7
    sdcard.move_file("a.txt", "folder/b.txt", storage=storage)
    assert not sdcard.file_exists("a.txt", storage=storage)
    assert sdcard.read_bytes("folder/b.txt", storage=storage) == b" a\r\nb \n"
    sdcard.delete_file("folder/b.txt", storage=storage)
    assert sdcard.list_folder("folder", storage=storage) == []
    changed = sdcard.consume_memory_change()
    assert (changed is not None) == (storage == "sd")
    assert sdcard.memory_snapshot()["files"] == {}


def test_collisions_and_path_escapes_preserve_files():
    sdcard.mount_memory({"dirs": ["folder"], "files": {"a.txt": "a", "b.txt": "b"}})
    for name in ("b.txt", "folder", "../escape"):
        with pytest.raises(sdcard.SdError):
            sdcard.move_file("a.txt", name)
        assert sdcard.read_text("a.txt") == "a"
    with pytest.raises(sdcard.SdError):
        sdcard.create_file("b.txt", b"overwrite")
    with pytest.raises(sdcard.SdError):
        sdcard.create_directory("b.txt")
    with pytest.raises(sdcard.SdError):
        sdcard.delete_file("folder")
    assert sdcard.read_text("b.txt") == "b"


@pytest.mark.parametrize("disk", [False, True])
def test_file_operations_preserve_spaces_and_do_not_target_a_different_name(monkeypatch, tmp_path, disk):
    if disk:
        monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    else:
        sdcard.mount_memory({"files": {}})
    sdcard.create_file("name.txt", b"keep")
    sdcard.create_file(" name.txt ", b"selected")
    assert sdcard.file_size(" name.txt ") == 8
    sdcard.move_file(" name.txt ", " renamed.txt ")
    assert sdcard.read_bytes(" renamed.txt ") == b"selected"
    sdcard.delete_file(" renamed.txt ")
    assert sdcard.read_bytes("name.txt") == b"keep"


def test_memory_move_between_storages_can_move_a_file_too_large_to_open():
    data = b"x" * (OPEN_LIMIT + 1)
    sdcard.mount_memory({"files": {"large.bin": data}})
    sdcard.move_file("large.bin", "large.bin", destination_storage="temporary")
    assert not sdcard.file_exists("large.bin")
    assert sdcard.read_bytes("large.bin", storage="temporary") == data
    sdcard.move_file("large.bin", "returned.bin", storage="temporary", destination_storage="sd")
    assert sdcard.read_bytes("returned.bin") == data


def test_full_destination_does_not_remove_the_original(monkeypatch):
    sdcard.mount_memory({"files": {"source.txt": "source"}})
    monkeypatch.setattr(sdcard, "MEMORY_CAPACITY", 2)
    with pytest.raises(sdcard.SdError, match="free space"):
        sdcard.move_file("source.txt", "new.txt", destination_storage="temporary")
    assert sdcard.read_text("source.txt") == "source"
    assert not sdcard.file_exists("new.txt", storage="temporary")


def test_native_move_refuses_a_file_larger_than_available_ram(monkeypatch, tmp_path):
    root, ram = tmp_path / "card", tmp_path / "ram"
    root.mkdir()
    ram.mkdir()
    (root / "large.bin").write_bytes(b"x" * 2000)
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(root))
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", False)
    monkeypatch.setattr(sdcard, "_temporary_root", lambda: ram)
    monkeypatch.setattr(sdcard, "disk_usage", lambda **kwargs: (100, 0, 100))
    with pytest.raises(sdcard.SdError, match="free space"):
        sdcard.move_file("large.bin", "large.bin", destination_storage="temporary")
    assert (root / "large.bin").stat().st_size == 2000
    assert list(ram.iterdir()) == []


def test_native_operations_and_failed_atomic_save(monkeypatch, tmp_path):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    sdcard.create_directory("folder")
    sdcard.create_file("a.txt", b"original")
    sdcard.move_file("a.txt", "folder/b.txt")
    assert (tmp_path / "folder/b.txt").read_bytes() == b"original"
    with monkeypatch.context() as broken:
        broken.setattr(sdcard.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(sdcard.SdError):
            sdcard.write_bytes("folder/b.txt", b"replacement")
    assert (tmp_path / "folder/b.txt").read_bytes() == b"original"
    assert list((tmp_path / "folder").iterdir()) == [tmp_path / "folder/b.txt"]
    sdcard.delete_file("folder/b.txt")
    assert sdcard.list_folder("folder") == []


def test_native_cross_storage_move_streams_and_keeps_source_when_copy_fails(monkeypatch, tmp_path):
    card, ram = tmp_path / "card", tmp_path / "ram"
    card.mkdir()
    ram.mkdir()
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(card))
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", False)
    monkeypatch.setattr(sdcard, "_temporary_root", lambda: ram)
    data = b"x" * 300_000
    (card / "source.bin").write_bytes(data)
    with monkeypatch.context() as broken:
        broken.setattr(sdcard.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(sdcard.SdError):
            sdcard.move_file("source.bin", "target.bin", destination_storage="temporary")
    assert (card / "source.bin").read_bytes() == data
    assert not (ram / "target.bin").exists()
    sdcard.move_file("source.bin", "target.bin", destination_storage="temporary")
    assert not (card / "source.bin").exists()
    assert (ram / "target.bin").read_bytes() == data


def test_native_paths_cannot_escape_through_a_symlink(monkeypatch, tmp_path):
    root, outside = tmp_path / "card", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "a.txt").write_text("a")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(root))
    for operation in (
        lambda: sdcard.create_directory("escape/dir"),
        lambda: sdcard.create_file("escape/file", b"data"),
        lambda: sdcard.move_file("a.txt", "escape/file"),
        lambda: sdcard.file_size("escape/file"),
    ):
        with pytest.raises(sdcard.SdError, match="outside"):
            operation()
    assert list(outside.iterdir()) == []
    assert (root / "a.txt").exists()


def test_read_bound_is_enforced_even_if_the_file_grows_after_stat(monkeypatch):
    class GrowingFile:
        def is_file(self):
            return True

        def stat(self):
            return SimpleNamespace(st_size=1)

    class Reader(io.BytesIO):
        def read(self, size=-1):
            assert size == OPEN_LIMIT + 1
            return super().read(size)

    monkeypatch.setattr(sdcard, "_disk_path", lambda *args: GrowingFile())
    monkeypatch.setattr(sdcard, "open", lambda *args: Reader(b"x" * (OPEN_LIMIT + 2)), raising=False)
    with pytest.raises(sdcard.SdError, match="too large"):
        sdcard.read_bytes("file", max_bytes=OPEN_LIMIT)


def test_browser_usage_plus_menu_and_create_directory_and_file():
    app = _browser()
    assert any(item["text"].startswith("Used:") for item in app.texts)
    _tap(app, "plus")
    _tap(app, "New Directory")
    for key in "folder":
        app._act("passkey-" + key)
    _tap(app, "Save")
    _tap(app, "folder/")
    assert app.sd_dir == "folder"
    _tap(app, "plus")
    _tap(app, "New File")
    _tap(app, "Manual Entry")
    assert app.screen == "fs-edit" and not app.fs.editor.keyboard
    _tap(app, "Text")
    for key in ("h", "i", "enter", "!"):
        app._act("passkey-" + key)
    assert app.fs.editor.text == "hi\n!"
    _tap(app, "Hide Keyboard")
    _tap(app, "Save")
    assert app.screen == "fs-name"
    _tap(app, "Save")
    assert app.screen == "sd"
    assert sdcard.read_bytes("folder/file.txt") == b"hi\n!"


@pytest.mark.parametrize("size,can_open", [(0, True), (OPEN_LIMIT, True), (OPEN_LIMIT + 1, False)])
def test_file_details_show_exact_size_and_open_limit(size, can_open):
    app = _details(b"a" * size)
    app.render()
    assert f"{size:,} bytes" in [item["text"] for item in app.texts]
    assert any(hit["action"] == "fs-open" for hit in app.hits) == can_open
    if can_open:
        _tap(app, "Open")
        assert app.screen == "fs-edit"
    else:
        assert "Files larger than 50 KB cannot" in " ".join(item["text"] for item in app.texts)
        assert {hit["label"] for hit in app.hits} >= {"Rename", "Move", "Delete"}


@pytest.mark.parametrize("size", [0, MAX_BYTE_PAYLOAD, MAX_BYTE_PAYLOAD + 1, OPEN_LIMIT + 1])
def test_file_qr_capacity_uses_file_size_without_reading_oversized_content(size, monkeypatch):
    original = sdcard.read_bytes
    reads = []

    def read(path, **kwargs):
        reads.append(kwargs["max_bytes"])
        return original(path, **kwargs)

    monkeypatch.setattr(sdcard, "read_bytes", read)
    app = _details(b"x" * size)
    assert not reads
    enabled = size <= MAX_BYTE_PAYLOAD
    assert any(hit["action"] == "fs-show-qr" for hit in app.hits) == enabled
    if enabled:
        _tap(app, "Show QR")
        assert reads == [MAX_BYTE_PAYLOAD]
        assert app.screen == "qr" and app.qr_kind == "file"
        app.render()
    else:
        assert "too large for a single QR code." in " ".join(item["text"] for item in app.texts)


@pytest.mark.parametrize("storage", ["sd", "temporary"])
@pytest.mark.parametrize("data", [b"  hello\r\nworld! \n", bytes(range(256))])
def test_file_qr_preserves_bytes_and_dims_the_whole_screen(storage, data):
    app = _details(data, storage=storage)
    _tap(app, "Show QR")
    assert app._qr_payload() == data
    normal = app.render()
    assert "File QR" in [item["text"] for item in app.texts]
    assert app._shown_to_a_camera()
    assert {hit["action"] for hit in app.hits} >= {"brightness-down", "brightness-up", "back"}
    _tap(app, "brightness-down")
    dimmed = app.render()
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT - 1
    assert dimmed.getpixel((0, HEIGHT - 1))[0] < normal.getpixel((0, HEIGHT - 1))[0]
    assert dimmed.getpixel((WIDTH - 1, 0))[2] < normal.getpixel((WIDTH - 1, 0))[2]
    assert (0, 0, 0) in [color for _count, color in dimmed.getcolors(WIDTH * HEIGHT)]
    _tap(app, "back")
    assert app.screen == "fs-details"
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT


def test_file_qr_refuses_a_file_that_grows_after_details_are_shown():
    app = _details(b"small")
    sdcard.write_text("file.txt", "x" * (MAX_BYTE_PAYLOAD + 1))
    app._act("fs-show-qr")
    assert app.screen == "fs-details"
    assert app.notice_error and "too large" in app.notice


def test_text_edit_save_disabled_until_changed_and_back_warns():
    app = _details(b"hello\r\nworld\t!\n")
    _tap(app, "Open")
    assert not any(hit["action"] == "fs-save" for hit in app.hits)
    _tap(app, "Text")
    app._act("passkey-X")
    _tap(app, "back")
    assert app.confirm == "fs-discard"
    assert "will not be saved" in app._confirm_message()
    _tap(app, "Cancel")
    assert app.fs.editor.changed
    _tap(app, "Hide Keyboard")
    _tap(app, "Save")
    assert sdcard.read_bytes("file.txt") == app.fs.editor.text.encode("ascii")
    app.render()
    assert not any(hit["action"] == "fs-save" for hit in app.hits)
    assert b"\r\n" in sdcard.read_bytes("file.txt")


def test_confirm_discard_leaves_saved_content_unchanged():
    app = _details(b"original")
    _tap(app, "Open")
    _tap(app, "Text")
    app._act("passkey-X")
    _tap(app, "back")
    _tap(app, "Confirm")
    assert app.screen == "fs-details"
    assert sdcard.read_bytes("file.txt") == b"original"


def test_large_editor_scrolls_only_its_area_and_keeps_input_bounded():
    app = _details(b"a" * OPEN_LIMIT)
    _tap(app, "Open")
    app.render()
    editor = app.fs.editor
    layout = editor.starts
    app.pointer_down(50, 400)
    app.pointer_move(50, 200)
    app.pointer_up(50, 200)
    app.render()
    assert editor.scroll > 0
    assert editor.starts is layout
    editor.cursor = len(editor.text)
    editor.type("x")
    assert len(editor.text) == OPEN_LIMIT
    editor.type("backspace")
    editor.type("x")
    assert len(editor.text) == OPEN_LIMIT
    assert editor.changed


@pytest.mark.parametrize("data", [b"\x00\x01\xff", "not ASCII: é".encode("utf-8")])
def test_non_text_files_open_as_scrollable_hex(data):
    app = _details(data)
    _tap(app, "Open")
    assert app.screen == "fs-binary"
    assert app.fs.data == data
    app.render()
    assert any(item["text"] == " ".join(f"{byte:02x}" for byte in data[:8]) for item in app.texts)


def test_rename_and_move_to_another_storage_from_file_details():
    app = _details(b"content")
    _tap(app, "Rename")
    app.filename = "renamed.txt"
    _tap(app, "Save")
    assert app.screen == "fs-details"
    assert not sdcard.file_exists("file.txt")
    _tap(app, "Move")
    _tap(app, "Temporary FS")
    _tap(app, "Move Here")
    assert app.screen == "sd" and app.sd_storage == "temporary"
    assert sdcard.read_bytes("renamed.txt", storage="temporary") == b"content"
    assert not sdcard.file_exists("renamed.txt")


def test_move_browser_only_lists_directories_and_disables_same_destination():
    app = _details(b"content")
    sdcard.create_directory("folder")
    _tap(app, "Move")
    _tap(app, "SD Card")
    assert not any(hit["label"] in ("file.txt", "Move Here") for hit in app.hits)
    _tap(app, "folder/")
    _tap(app, "Move Here")
    assert app.sd_dir == "folder"
    assert sdcard.read_bytes("folder/file.txt") == b"content"


@pytest.mark.parametrize("storage", ["sd", "temporary"])
def test_delete_confirmation_and_cancel(storage):
    app = _details(b"content", storage=storage)
    _tap(app, "Delete")
    app.render()
    if storage == "sd":
        assert app.screen == "fs-delete"
        assert "may still be restored" in " ".join(item["text"] for item in app.texts)
    else:
        assert app.confirm == "fs-delete"
        assert "SD" not in app._confirm_message()
    _tap(app, "Cancel")
    assert sdcard.file_exists("file.txt", storage=storage)
    _tap(app, "Delete")
    _tap(app, "Confirm")
    assert app.screen == "sd"
    assert not sdcard.file_exists("file.txt", storage=storage)


def _new_qr(app, payload):
    _tap(app, "plus")
    _tap(app, "New File")
    _tap(app, "Scan QR Code")
    app.accept_qr(payload)
    app.render()


def test_single_qr_preserves_whitespace_without_parsing_its_content():
    app = _browser()
    _new_qr(app, "  hello\nworld \n")
    assert app.screen == "fs-edit"
    assert app.fs.editor.text == "  hello\nworld \n"
    _tap(app, "Save")
    _tap(app, "Save")
    assert sdcard.read_bytes("file.txt") == b"  hello\nworld \n"


@pytest.mark.parametrize("payload", [b"\x00\xff\x80\x01", bytes(range(256)) * 10, "not ASCII: é"], ids=["binary", "scrollable", "non-ascii"])
def test_single_binary_qr_preserves_its_original_bytes(payload):
    app = _browser()
    _new_qr(app, payload)
    assert app.screen == "fs-binary"
    assert any(item["text"] == "Binary File" for item in app.texts)
    assert not any(hit["action"] == "fs-focus" for hit in app.hits)
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    if len(data) > 256:
        assert app.scroll_max["fs-binary"] > 0
        app.pointer_down(50, 500)
        app.pointer_move(50, 200)
        app.pointer_up(50, 200)
        app.render()
        assert app.scroll["fs-binary"] > 0
        app._scroll_at = 0
    _tap(app, "Save")
    assert app.filename == "file.bin"
    _tap(app, "Save")
    assert sdcard.read_bytes("file.bin") == data


def test_camera_keeps_raw_file_qr_bytes_and_existing_text_decoding(monkeypatch):
    import sys
    from PIL import Image
    from bigsigner.hardware.camera import read_qr

    data = b"\x00\xff\x80\x01"
    decoder = SimpleNamespace(decode=lambda image: [SimpleNamespace(type="QRCODE", data=data)])
    monkeypatch.setitem(sys.modules, "pyzbar", SimpleNamespace(__path__=[]))
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", decoder)
    image = Image.new("RGB", (40, 40), "white")
    assert read_qr(image, raw=True) == data
    assert read_qr(image) == data.decode("latin-1")


@pytest.mark.parametrize("prefix", ["ur:bytes/1-3/abc", "UR:BYTES/abc", "B$2Z0100abc", "p1of2 abc", "1/3 abc", b"p1of2 \x00\xff"])
def test_sequence_prefix_warns_then_continues_with_its_raw_content(prefix):
    app = _browser()
    _new_qr(app, prefix)
    assert app.screen == "fs-qr-warning"
    assert sdcard.list_folder("") == []
    assert "sequence of QR codes is not" in " ".join(item["text"] for item in app.texts)
    _tap(app, "OK")
    assert app.screen == ("fs-binary" if isinstance(prefix, bytes) else "fs-edit")
    if isinstance(prefix, str):
        assert app.fs.editor.text == prefix
    _tap(app, "Save")
    name = "file.bin" if isinstance(prefix, bytes) else "file.txt"
    assert app.filename == name
    _tap(app, "Save")
    assert sdcard.read_bytes(name) == (prefix if isinstance(prefix, bytes) else prefix.encode("utf-8"))


def test_filesystem_screens_save_screenshots():
    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_filesystem_screens_save_screenshots"))
    app = _browser({"hello.txt": "hello\nworld\n"}, dirs=["folder"])
    record.shot(app, "browser")
    record.click(app, "plus")
    record.shot(app, "plus-menu")
    record.click(app, "New File")
    record.shot(app, "new-source")
    record.click(app, "Manual Entry")
    record.shot(app, "new-text")
    record.click(app, "Text")
    app._act("passkey-h")
    record.shot(app, "keyboard")
    record.click(app, "back")
    record.shot(app, "discard")
    record.click(app, "Confirm")
    record.click(app, "back")
    record.click(app, "hello.txt")
    record.shot(app, "file-details")
    record.click(app, "Show QR")
    record.shot(app, "file-qr")
    record.click(app, "brightness-down")
    record.shot(app, "file-qr-dimmed")
    record.click(app, "back")
    record.click(app, "Open")
    record.shot(app, "text-save-disabled")
    record.click(app, "Text")
    app._act("passkey-x")
    record.click(app, "Hide Keyboard")
    record.shot(app, "text-save-enabled")
    record.click(app, "back")
    record.click(app, "Confirm")
    record.click(app, "Rename")
    record.shot(app, "rename")
    record.click(app, "back")
    record.click(app, "Move")
    record.shot(app, "move-storage")
    record.click(app, "SD Card")
    record.click(app, "folder/")
    record.shot(app, "move-folder")
    record.click(app, "back")
    record.click(app, "back")
    record.click(app, "Delete")
    record.shot(app, "sd-delete-warning")
    app = _details(b"x" * (OPEN_LIMIT + 1))
    record.shot(app, "too-large")
    app = _details(bytes(range(256)) * 100)
    record.click(app, "Open")
    record.shot(app, "binary")
    app.scroll["fs-binary"] = 10**9
    record.shot(app, "binary-bottom")
    app = _browser()
    _new_qr(app, "ur:bytes/1-3/example")
    record.shot(app, "qr-sequence-warning")
    app = _details(b"content", storage="temporary")
    record.click(app, "Delete")
    record.shot(app, "temporary-delete")

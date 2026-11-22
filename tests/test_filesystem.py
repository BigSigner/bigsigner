"""Storage mutations and the File System screens, including bounded viewers."""

import base64
import gzip
import hashlib
import io
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from bigsigner import file_qr, sdcard
from bigsigner.diskimage import BurnResult
from bigsigner.gpg import GpgError, Outcome
from bigsigner.ui.app import App, QR_BRIGHTNESS_DEFAULT
from bigsigner.ui.canvas import BLUE, HEADER, HEIGHT, INK, MARGIN, MUTED, PAPER, RED, WIDTH
from bigsigner.ui.filesystem import OPEN_LIMIT, SD_DELETE_NOTE, SEQUENCE_NOTE, is_text
from test_sdcard import _tap as _tap_hit


def _tap(app, label):
    app.render()
    if not any(hit["label"] == label or hit["action"] == label for hit in app.hits):
        app.scroll[app.screen] = 10**9
        app.render()
    _tap_hit(app, label)


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


def _noisy(count):
    """Bytes that do not shrink much under gzip, so a QR split has several parts."""
    value = 1
    out = bytearray()
    for _ in range(count):
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        out.append(value & 0xFF)
    return bytes(out)


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
    _tap(app, "New Folder")
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
        app.scroll["fs-details"] = 10**9
        app.render()
        assert {hit["label"] for hit in app.hits} >= {"Copy", "GZIP", "Delete"}


@pytest.mark.parametrize("size", [0, file_qr.TEXT_DIRECT, file_qr.TEXT_DIRECT + 1, file_qr.QR_SPLIT_LIMIT, file_qr.QR_SPLIT_LIMIT + 1, OPEN_LIMIT + 1])
def test_text_file_qr_follows_the_size_limits(size):
    app = _details(b"x" * size)
    enabled = size <= file_qr.QR_SPLIT_LIMIT
    assert any(hit["action"] == "fs-show-qr" for hit in app.hits) == enabled
    if not enabled:
        assert "too long to show as a QR code." in " ".join(item["text"] for item in app.texts)
        return
    _tap(app, "Show QR")
    if size <= file_qr.TEXT_DIRECT:
        assert app.screen == "qr" and app.qr_kind == "file"
        assert app._qr_payload() == b"x" * size
        app.render()
    else:
        assert app.screen == "fs-qr-guide"
        app.render()
        shown = " ".join(item["text"] for item in app.texts)
        if len(app.fs.qr_parts) <= 1:
            assert "This file is large and has been compressed to 1 QR code." in shown
            assert "split over" not in shown
        else:
            assert f"split over {len(app.fs.qr_parts)} QR codes" in shown
        app.scroll["fs-qr-guide"] = 10**9
        app.render()
        assert "'file.txt'" in app.fs.qr_command
        assert "'file.txt'" in " ".join(item["text"] for item in app.texts)


@pytest.mark.parametrize("storage", ["sd", "temporary"])
@pytest.mark.parametrize("data", [b"  hello\r\nworld! \n", bytes(range(256))])
def test_file_qr_preserves_bytes_and_dims_the_whole_screen(storage, data):
    app = _details(data, storage=storage)
    _tap(app, "Show QR" if is_text(data) else "Binary")
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
    sdcard.write_text("file.txt", "x" * (file_qr.QR_SPLIT_LIMIT + 1))
    app._act("fs-show-qr")
    assert app.screen == "fs-details"
    assert app.notice_error and "too large" in app.notice


@pytest.mark.parametrize(
    "size,binary,base64",
    [(1, True, True), (file_qr.BINARY_DIRECT, True, True), (file_qr.BINARY_DIRECT + 1, False, True), (file_qr.QR_SPLIT_LIMIT, False, True), (file_qr.QR_SPLIT_LIMIT + 1, False, False)],
)
def test_binary_file_offers_binary_and_base64_qr(size, binary, base64):
    app = _details(bytes(index % 256 for index in range(size)) or b"\xff")
    actions = {hit["action"] for hit in app.hits}
    assert "fs-show-qr" not in actions
    assert ("fs-show-binary" in actions) == binary
    assert ("fs-show-base64" in actions) == base64
    assert ("Large files cannot be displayed in some QR formats." in " ".join(item["text"] for item in app.texts)) == (not binary or not base64)


def test_split_guide_quotes_spaces_and_a_single_quote_in_the_file_name():
    app = _details(b"y" * 500, name="my file's data.bin")
    _tap(app, "Show QR")
    assert app.screen == "fs-qr-guide"
    assert app.fs.qr_command.startswith("filename='my file'\\''s data.bin'")
    app.render()
    assert app.scroll_max["fs-qr-guide"] > 0


def test_short_binary_base64_is_one_qr_with_the_decode_command():
    data = bytes(range(200))
    app = _details(data)
    _tap(app, "Base64")
    assert app.screen == "qr" and app._qr_payload() == file_qr.plain_base64(data)
    app.render()
    shown = " ".join(item["text"] for item in app.texts)
    assert file_qr.BASE64_DECODE in shown
    assert {hit["action"] for hit in app.hits} >= {"brightness-down", "brightness-up", "back"}


def test_long_binary_base64_splits_and_pages_with_brightness():
    data = _noisy(1500)
    app = _details(data)
    _tap(app, "Base64")
    assert app.screen == "fs-qr-guide" and len(app.fs.qr_parts) > 1
    app.render()
    assert f"This file is large and has been split over {len(app.fs.qr_parts)} QR codes." in _shown(app)
    app.scroll["fs-qr-guide"] = 10**9
    app.render()
    shown = " ".join(item["text"] for item in app.texts)
    assert "gunzip \"${filename}.gz\"" in app.fs.qr_command and "filename='file.txt'" in shown
    assert app.scroll_max["fs-qr-guide"] > 0
    app.scroll["fs-qr-guide"] = 0
    app.pointer_down(200, 400)
    app.pointer_move(200, 200)
    app.pointer_up(200, 200)
    assert app.scroll["fs-qr-guide"] > 0
    app._scroll_at = None
    _tap(app, "Show QR Codes")
    assert app.screen == "qr" and app.qr_kind == "file"
    first = app._qr_payload()
    assert first.startswith(" " * (len(app.fs.qr_parts) + 1))
    assert not first.endswith(" ")
    app.render()
    assert {hit["action"] for hit in app.hits} >= {"brightness-down", "brightness-up", "fs-qr-next"}
    _tap(app, ">")
    second = app._qr_payload()
    assert second != first and second.endswith(" ")
    _tap(app, "back")
    assert app.screen == "fs-qr-guide"
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT


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


def _finish_sha(app):
    if not app.fs.sha_shown:
        app.render()
    try:
        digest = app.fs._sha_job()
    except sdcard.SdError as exc:
        app.fs.finish_sha(error=str(exc))
    else:
        app.fs.finish_sha(digest)
    app._search_touch_at -= 1
    app._ignore_search_touch()
    app.render()


def _hex_lines(app):
    app.render()
    return [
        item for item in app.texts
        if item["text"] and set(item["text"]) <= set("0123456789abcdef")
    ]


def test_rename_and_move_share_a_row_and_sha256_sits_above_delete():
    app = _details(b"hello")
    rename = next(hit for hit in app.hits if hit["label"] == "Rename")
    move = next(hit for hit in app.hits if hit["label"] == "Move")
    copy = next(hit for hit in app.hits if hit["label"] == "Copy")
    gzip_button = next(hit for hit in app.hits if hit["label"] == "GZIP")
    sha = next(hit for hit in app.hits if hit["label"] == "Calculate SHA256")
    delete = next(hit for hit in app.hits if hit["label"] == "Delete")
    assert rename["box"][1] == move["box"][1]
    assert rename["box"][3] == move["box"][3]
    assert rename["box"][2] <= move["box"][0]
    assert rename["box"][0] == MARGIN and move["box"][2] == WIDTH - MARGIN
    assert copy["box"][1] == gzip_button["box"][1]
    assert copy["box"][1] >= rename["box"][3]
    assert copy["box"][0] == MARGIN and gzip_button["box"][2] == WIDTH - MARGIN
    assert sha["box"][1] >= copy["box"][3]
    assert delete["box"][1] >= sha["box"][3]
    assert "fs-burn" not in {hit["action"] for hit in app.hits}
    assert sha["box"][0] == MARGIN and sha["box"][2] == WIDTH - MARGIN
    assert sha["box"][3] - sha["box"][1] == rename["box"][3] - rename["box"][1]


def test_calculate_sha256_shows_progress_then_qr_and_left_aligned_hex():
    data = b"hello"
    app = _details(data)
    _tap(app, "Calculate SHA256")
    assert app.screen == "fs-sha-progress"
    app.render()
    assert [item["text"] for item in app.texts] == ["Calculating SHA256\u2026"]
    assert app.hits == []
    app.pointer_down(240, 400)
    app.pointer_up(240, 400)
    assert app.screen == "fs-sha-progress"
    _finish_sha(app)
    digest = hashlib.sha256(data).hexdigest()
    assert app.screen == "fs-sha256" and app.fs.sha_digest == digest
    assert app._shown_to_a_camera()
    lines = _hex_lines(app)
    assert lines
    assert all(item["box"][0] <= MARGIN + 4 for item in lines)
    assert lines[-1]["box"][0] < WIDTH // 3
    from bigsigner.ui.app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

    code = _qr_image(digest, WIDTH - 2 * MARGIN, _qr_light(QR_BRIGHTNESS_DEFAULT))
    image = app.render()
    crop = image.crop((MARGIN, HEADER + 16, MARGIN + code.width, HEADER + 16 + code.height))
    assert crop.tobytes() == code.tobytes()
    bright = next(hit["box"] for hit in app.hits if hit["action"] == "brightness-down")
    assert bright[1] > max(item["box"][3] for item in lines)
    app.scroll["fs-sha256"] = 10**9
    app.render()
    assert next(hit["box"] for hit in app.hits if hit["action"] == "brightness-down") == bright
    collected = ""
    offset = 0
    limit = app.scroll_max["fs-sha256"]
    while True:
        app.scroll["fs-sha256"] = offset
        chunk = "".join(item["text"] for item in _hex_lines(app))
        if chunk:
            if not collected:
                collected = chunk
            else:
                for count in range(len(chunk), -1, -1):
                    if collected.endswith(chunk[:count]):
                        collected += chunk[count:]
                        break
        if offset >= limit:
            break
        offset = min(limit, offset + 24)
    assert collected == digest
    app.scroll["fs-sha256"] = 0
    normal = app.render()
    _tap(app, "brightness-down")
    dimmed = app.render()
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT - 1
    assert dimmed.getpixel((0, HEIGHT - 1))[0] < normal.getpixel((0, HEIGHT - 1))[0]
    assert (0, 0, 0) in [color for _count, color in dimmed.getcolors(WIDTH * HEIGHT)]
    _tap(app, "back")
    assert app.screen == "fs-details"
    assert app.qr_brightness == QR_BRIGHTNESS_DEFAULT


def test_sha256_of_a_large_file_matches_and_a_missing_file_returns_to_details():
    data = b"xyz" * 100_000
    app = _details(data, name="big.bin")
    _tap(app, "Calculate SHA256")
    _finish_sha(app)
    assert app.fs.sha_digest == hashlib.sha256(data).hexdigest()
    app = _details(b"hello", storage="temporary")
    _tap(app, "Calculate SHA256")
    app.render()
    sdcard.delete_file("file.txt", storage="temporary")
    _finish_sha(app)
    assert app.screen == "fs-details"
    assert "not a file" in app.notice


def test_read_chunks_hashes_a_disk_file_past_the_open_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    data = bytes(range(256)) * 2000
    (tmp_path / "big.bin").write_bytes(data)
    digest = hashlib.sha256()
    total = 0
    chunks = 0
    for chunk in sdcard.read_chunks("big.bin", chunk_size=1000):
        digest.update(chunk)
        total += len(chunk)
        chunks += 1
        assert len(chunk) <= 1000
    assert chunks > 1 and total == len(data)
    assert digest.hexdigest() == hashlib.sha256(data).hexdigest()
    (tmp_path / "empty.bin").write_bytes(b"")
    assert list(sdcard.read_chunks("empty.bin")) == []


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


def test_new_file_explains_that_non_textual_qr_data_may_not_scan():
    app = _browser()
    _tap(app, "plus")
    _tap(app, "New File")
    image = app.render()
    scan = next(hit for hit in app.hits if hit["label"] == "Scan QR Code")
    notes = [item for item in app.texts if "unscannable" in item["text"] or "base64" in item["text"]]
    assert notes
    assert notes[0]["box"][1] >= scan["box"][3]
    assert all(item["box"][2] <= WIDTH - MARGIN for item in notes)
    def apart(left, right):
        return sum((left[i] - right[i]) ** 2 for i in range(3))

    painted = False
    for item in notes:
        left, top, right, bottom = item["box"]
        for y in range(top, bottom):
            for x in range(left, right):
                pixel = image.getpixel((x, y))[:3]
                if pixel == PAPER:
                    continue
                assert apart(pixel, MUTED) < apart(pixel, INK)
                painted = True
    assert painted


def test_a_base64_qr_can_be_kept_or_decoded_as_text_or_binary():
    app = _browser()
    _new_qr(app, "aaaa\n")
    assert app.screen == "fs-base64"
    assert "encoded in base64" in " ".join(item["text"] for item in app.texts)
    app.back_one()
    assert app.screen == "fs-new-source"
    assert sdcard.list_folder("") == []

    kept = _browser()
    _new_qr(kept, "aaaa\n")
    _tap(kept, "Keep Original Data")
    assert kept.screen == "fs-edit"
    assert kept.fs.editor.text == "aaaa\n"
    kept.back_one()
    assert kept.screen == "fs-new-source"

    binary = _browser()
    _new_qr(binary, "aaaa\n")
    _tap(binary, "Decode Base64")
    assert binary.screen == "fs-binary"
    assert binary.fs.data == b"\x69\xa6\x9a"
    binary.back_one()
    assert binary.screen == "fs-new-source"

    text = _browser()
    _new_qr(text, "aGVsbG8=\n")
    _tap(text, "Decode Base64")
    assert text.screen == "fs-edit"
    assert text.fs.editor.text == "hello"

    plain = _browser()
    _new_qr(plain, "hello world\n")
    assert plain.screen == "fs-edit"
    wrapped = _browser()
    _new_qr(wrapped, "YQ==\nYQ==")
    assert wrapped.screen == "fs-edit"
    spaced = _browser()
    _new_qr(spaced, "YQ== YQ==")
    assert spaced.screen == "fs-edit"


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
    record.click(app, "Calculate SHA256")
    record.shot(app, "sha-progress")
    _finish_sha(app)
    record.shot(app, "sha-result")
    if app.scroll_max.get("fs-sha256", 0) > 0:
        app.scroll["fs-sha256"] = 10**9
        record.shot(app, "sha-result-bottom")
    record.click(app, "back")
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
    app = _details(bytes(range(200)))
    record.shot(app, "binary-choice")
    record.click(app, "Base64")
    record.shot(app, "base64-direct")
    app = _details(_noisy(1500))
    record.shot(app, "binary-large-choice")
    record.click(app, "Base64")
    record.shot(app, "split-guide")
    record.click(app, "Show QR Codes")
    record.shot(app, "split-qr")
    record.click(app, ">")
    record.shot(app, "split-qr-next")
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


def _mbr():
    data = bytearray(512)
    data[446] = 0x80
    data[450] = 0x0C
    data[458:462] = (2048).to_bytes(4, "little")
    data[510:512] = b"\x55\xaa"
    return bytes(data)


def _shown(app):
    app.render()
    return " ".join(item["text"] for item in app.texts)


def _shows(image, box, color):
    x0, y0, x1, y1 = box
    return any(image.getpixel((x, y))[:3] == color for y in range(y0, y1) for x in range(x0, x1))


def _finish_burn(app):
    if not app.fs.burn_shown:
        app.render()
    app.fs.finish_burn(app.fs._burn_job())
    app._search_touch_at -= 1
    app._ignore_search_touch()
    app.render()


def _reveal(app, label, key="fs-details"):
    app.render()
    if any(hit["label"] == label or hit["action"] == label for hit in app.hits):
        return
    app.scroll[key] = 10**9
    app.render()


def test_a_binary_file_that_is_not_an_image_cannot_be_burned():
    app = _details(b"\xff" * 64, name="blob.bin")
    _reveal(app, "Delete")
    delete = next(hit for hit in app.hits if hit["label"] == "Delete")
    note = next(item for item in app.texts if item["text"] == "This file is not a disk image.")
    assert "fs-burn" not in {hit["action"] for hit in app.hits}
    assert note["box"][3] <= delete["box"][1]
    app = _details(_mbr(), name="os.img")
    _reveal(app, "Delete")
    burn = next(hit for hit in app.hits if hit["label"] == "Burn to SD Card")
    sha = next(hit for hit in app.hits if hit["label"] == "Calculate SHA256")
    delete = next(hit for hit in app.hits if hit["label"] == "Delete")
    assert sha["box"][3] <= burn["box"][1]
    assert burn["box"][3] <= delete["box"][1]
    app = _details(b"hello")
    assert "fs-burn" not in {hit["action"] for hit in app.hits}
    assert "disk image" not in _shown(app)


def test_a_gzip_image_can_be_burned_without_storing_the_uncompressed_bytes():
    app = _details(gzip.compress(_mbr()), name="os.img.gz")
    _tap(app, "Burn to SD Card")
    assert app.screen == "fs-burn-verify"
    plain = _details(gzip.compress(b"\xff" * 64), name="notes.gz")
    plain.scroll["fs-details"] = 10**9
    assert "fs-burn" not in {hit["action"] for hit in plain.hits}
    assert "This file is not a disk image." in _shown(plain)


def test_an_image_opens_verification_and_detached_signature_needs_a_companion():
    app = _details(_mbr(), name="os.img")
    _tap(app, "Burn to SD Card")
    assert app.screen == "fs-burn-verify"
    assert "fs-burn-detached" not in {hit["action"] for hit in app.hits}
    shown = _shown(app)
    assert "A similar filename.asc file was not found." in shown
    assert "How would you like to verify the GPG signature of this file?" in shown
    assert "Continuing erases the SD card and writes this image." in shown
    image = app.render()
    question = next(item for item in app.texts if item["text"].startswith("How would you like"))
    warning = next(item for item in app.texts if item["text"].startswith("Continuing erases"))
    assert question["box"][3] < warning["box"][1]
    assert _shows(image, question["box"], INK) and not _shows(image, question["box"], RED)
    assert _shows(image, warning["box"], RED) and not _shows(image, warning["box"], INK)
    skip = next(hit for hit in app.hits if hit["label"] == "Skip Verification")
    assert skip["box"][3] <= HEIGHT


def test_detached_signature_uses_the_gpg_date_and_a_failed_check_does_not_unmount():
    image = {"base64": base64.b64encode(_mbr()).decode()}
    app = _browser({"os.img": image, "os.img.asc": "signature"})
    _tap(app, "os.img")
    _tap(app, "Burn to SD Card")
    _tap(app, "Detached Signature")
    assert app.screen == "gpg-date"
    assert app.gpg.operation == "burn-detached"

    def fail(*args, **kwargs):
        raise GpgError("Signature verification failed.")

    app.gpg.backend.verify = fail
    _tap(app, "Continue")
    assert app.screen == "gpg-working"
    app.render()
    try:
        outcome = app.gpg.job()
    except Exception as exc:
        outcome = Outcome(False, str(exc))
    app.gpg.finish(outcome)
    app._search_touch_at -= 1
    app._ignore_search_touch()
    app.render()
    assert app.screen == "fs-burn-result"
    assert "Signature verification failed." in _shown(app)
    assert "You can remove the SD card." not in _shown(app)


def test_signed_checksum_file_lists_only_asc_files_in_the_same_folder():
    image = {"base64": base64.b64encode(_mbr()).decode()}
    app = _browser({
        "os.img": image,
        "SHA256SUMS.asc": "signed",
        "other.asc": "signed",
        "note.txt": "plain",
    })
    _tap(app, "os.img")
    _tap(app, "Burn to SD Card")
    _tap(app, "Signed Checksum File")
    assert app.screen == "fs-burn-checksums"
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert {"SHA256SUMS.asc", "other.asc"} <= labels
    assert "note.txt" not in labels
    _tap(app, "SHA256SUMS.asc")
    assert app.screen == "gpg-date"
    assert app.gpg.operation == "burn-checksums"
    assert app.fs.burn_signature == "SHA256SUMS.asc"


def test_skip_verification_warns_and_the_emulator_does_not_write():
    app = _details(_mbr(), name="os.img")
    _tap(app, "Burn to SD Card")
    _tap(app, "Skip Verification")
    assert "no signature check" in app._confirm_message()
    _tap(app, "Confirm")
    assert app.screen == "fs-burn-progress"
    _finish_burn(app)
    assert "Burning an image requires the device." in _shown(app)
    assert "You can remove the SD card." not in _shown(app)


def test_done_releases_the_hold_and_deletes_the_ram_copy(monkeypatch, tmp_path):
    copy = tmp_path / "image"
    copy.write_bytes(b"copy")
    released = []
    app = _details(_mbr(), name="os.img")
    monkeypatch.setattr(sdcard, "native_path", lambda relative, storage="sd": tmp_path / "os.img")

    def fake_burn(source, *, on_card, progress):
        progress("Writing the image\u2026", 1, 1)
        return BurnResult(True, "The image was written.", str(copy), True, True)

    app.fs.burner.burn = fake_burn
    app.fs.burner.release = lambda: released.append(True)
    _tap(app, "Burn to SD Card")
    _tap(app, "Skip Verification")
    _tap(app, "Confirm")
    _finish_burn(app)
    assert "The image was written." in _shown(app)
    assert "You can remove the SD card." in _shown(app)
    _tap(app, "Done")
    assert released == [True]
    assert not copy.exists()
    assert app.screen == "filesystem"
    assert app.back == []


def test_a_removed_sd_card_on_file_details_returns_to_file_system(monkeypatch):
    app = _details(b"hello")
    assert app.screen == "fs-details"

    def missing(*_args, **_kwargs):
        raise sdcard.SdError("No SD card is available.")

    monkeypatch.setattr(sdcard, "file_size", missing)
    app.render()
    assert "No SD card is available." in _shown(app)
    _tap(app, "back")
    assert app.screen == "filesystem"
    assert app.back == []


def _finish_file(app):
    if not app.fs.file_shown:
        app.render()
    try:
        notice = app.fs._file_job()
    except sdcard.SdError as exc:
        app.fs.finish_file(error=str(exc))
    else:
        app.fs.finish_file(notice)
    app._search_touch_at -= 1
    app._ignore_search_touch()
    app.render()


def _gzip_with_name(name, payload):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, filename=name, mode="wb", mtime=0) as handle:
        handle.write(payload)
    return buffer.getvalue()


def _tar_gz(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload in entries:
            if payload is None:
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
                continue
            if isinstance(payload, tuple):
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = payload[1]
                archive.addfile(info)
                continue
            data = payload if isinstance(payload, bytes) else payload.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_copy_asks_for_a_folder_and_a_new_filename():
    app = _details(b"content")
    sdcard.create_directory("folder")
    _tap(app, "Copy")
    assert app.screen == "fs-move-storage"
    assert "Copy File" in _shown(app)
    _tap(app, "SD Card")
    _tap(app, "folder/")
    _tap(app, "Select Folder")
    assert app.screen == "fs-name"
    assert app.filename == "file.txt"
    app.filename = "copy.txt"
    app.filename_cursor = len(app.filename)
    _tap(app, "Save")
    assert app.screen == "fs-file-progress"
    app.render()
    assert [item["text"] for item in app.texts] == ["Copying\u2026"]
    assert app.hits == []
    app.pointer_down(240, 400)
    app.pointer_up(240, 400)
    assert app.screen == "fs-file-progress"
    _finish_file(app)
    assert app.screen == "sd"
    assert app.sd_dir == "folder"
    assert sdcard.read_bytes("folder/copy.txt") == b"content"
    assert sdcard.read_bytes("file.txt") == b"content"


def test_gzip_suggests_a_gz_name_and_gunzip_extracts_inside_the_folder():
    app = _details(b"content")
    sdcard.create_directory("folder")
    _tap(app, "GZIP")
    assert "GZIP File" in _shown(app)
    _tap(app, "Temporary FS")
    _tap(app, "Select Folder")
    assert app.filename == "file.txt.gz"
    _tap(app, "Save")
    assert "Compressing\u2026" in _shown(app)
    _finish_file(app)
    assert app.sd_storage == "temporary"
    packed = sdcard.read_bytes("file.txt.gz", storage="temporary")
    assert gzip.decompress(packed) == b"content"
    assert sdcard.read_bytes("file.txt") == b"content"
    _tap(app, "file.txt.gz")
    _reveal(app, "GUNZIP")
    assert any(hit["label"] == "GUNZIP" for hit in app.hits)
    _tap(app, "GUNZIP")
    assert "GUNZIP File" in _shown(app)
    _tap(app, "SD Card")
    _tap(app, "folder/")
    _tap(app, "Extract Here")
    assert "Extracting\u2026" in _shown(app)
    _finish_file(app)
    assert app.sd_dir == "folder"
    assert sdcard.read_bytes("folder/file.txt") == b"content"


def test_gunzip_extracts_a_tar_tree_and_refuses_paths_outside_the_folder():
    nested = _tar_gz([("nested", None), ("nested/inside.txt", b"yes")])
    app = _details(nested, name="tree.tar.gz")
    sdcard.create_directory("folder")
    _tap(app, "GUNZIP")
    _tap(app, "SD Card")
    _tap(app, "folder/")
    _tap(app, "Extract Here")
    _finish_file(app)
    assert sdcard.read_bytes("folder/nested/inside.txt") == b"yes"
    outside = _tar_gz([("ok.txt", b"kept"), ("/etc/passwd", b"no"), ("../escape.txt", b"no"), ("link", ("symlink", "/etc/passwd"))])
    app = _details(outside, name="bad.tar.gz")
    _tap(app, "GUNZIP")
    _tap(app, "SD Card")
    _tap(app, "Extract Here")
    _finish_file(app)
    assert app.notice_error
    assert "outside the selected folder" in app.notice
    assert not sdcard.file_exists("ok.txt")
    assert not sdcard.file_exists("etc/passwd")
    assert not sdcard.file_exists("escape.txt")
    planted = _gzip_with_name("/etc/passwd", b"secret")
    app = _details(planted, name="notes.gz")
    sdcard.create_directory("safe")
    _tap(app, "GUNZIP")
    _tap(app, "SD Card")
    _tap(app, "safe/")
    _tap(app, "Extract Here")
    _finish_file(app)
    assert sdcard.read_bytes("safe/notes") == b"secret"
    assert not sdcard.path_exists("etc/passwd")

"""Both storage destinations, their lifetimes, and the fixed export usage area."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from bigsigner import sdcard
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEIGHT, WIDTH
from test_domain import expression
from test_psbt_load import ABANDON, _native, _psbt
from test_sdcard import _tap


@pytest.fixture(autouse=True)
def temporary_memory(monkeypatch):
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", True)
    monkeypatch.setattr(sdcard, "_temporary_memory", {"dirs": set(), "files": {}})


@pytest.mark.parametrize("action,expect", [
    ("add-sd", "key"), ("wallet-sd", "descriptor"),
    ("address-sd", "address"), ("message-sd", "message"),
    ("address-message-sd", "address-message"), ("psbt-sd", "psbt"),
])
def test_every_load_route_opens_storage_choice(action, expect):
    app = App()
    app.screen = "keys"
    app._act(action)
    app.render()
    assert app.screen == "storage"
    assert app.sd_expect == expect
    assert [hit["label"] for hit in app.hits if hit["action"].startswith("storage-")] == ["SD Card", "Temporary FS"]
    _tap(app, "Temporary FS")
    assert app.screen == "sd" and app.sd_storage == "temporary"
    app.back_one()
    assert app.screen == "storage"
    app.back_one()
    assert app.screen == "keys"


def _export_app(kind):
    app = App()
    app.session = _native()
    app.selected_fp = next(iter(app.session.fingerprints))
    app.screen = "key"
    app.back = ["keys"]
    if kind == "seed":
        app._act("export-seed")
        _tap(app, "Continue")
    elif kind == "derived":
        app._act("derive-native")
        app._act("export-derived")
        app._act("export-format-0")
    elif kind == "external":
        app.session.fingerprints.clear()
        added = app.session.add_text(expression(ABANDON, "m/84h/0h/0h"))
        app.selected_fp = added["fingerprint"]
        app._act("export-key")
        app._act("export-format-0")
    elif kind in ("wallet", "address"):
        app.screen = kind
        app._act("export-wallet" if kind == "wallet" else "export-address")
    elif kind == "signature":
        app.screen = "message-signed"
        app.message_signature = "test signature"
        app._act("message-export")
    else:
        app.screen = "psbt-share"
        app.signed_psbt = _psbt(app.session)
        app._act("psbt-export")
        app._act("psbt-export-binary" if kind == "psbt-binary" else "psbt-export-base64")
    return app


@pytest.mark.parametrize("kind", ["seed", "derived", "external", "wallet", "address", "signature", "psbt-binary", "psbt-base64"])
@pytest.mark.parametrize("destination,storage", [("SD Card", "sd"), ("Temporary FS", "temporary")])
def test_every_export_route_writes_to_selected_storage_and_returns(kind, destination, storage):
    sdcard.mount_memory({"files": {}})
    app = _export_app(kind)
    assert app.screen == "storage"
    expected = app.export_bytes if app.export_binary else app.export_text.encode("utf-8")
    origin, back = app.export_return, list(app.export_back)
    _tap(app, destination)
    assert app.screen == "sd"
    assert app.sd_storage == storage
    _tap(app, "New File")
    _tap(app, "Save")
    assert sdcard.read_bytes(app.filename, storage=storage) == expected
    other = "temporary" if storage == "sd" else "sd"
    assert not sdcard.file_exists(app.filename, storage=other)
    assert app.screen == origin and app.back == back


def test_temporary_export_can_be_loaded_again_without_an_sd_card():
    app = _export_app("seed")
    _tap(app, "Temporary FS")
    _tap(app, "New File")
    _tap(app, "Save")
    assert sdcard.consume_memory_change() is None
    fresh = App()
    fresh.screen = "keys"
    _tap(fresh, "plus")
    _tap(fresh, "Load from File")
    _tap(fresh, "Temporary FS")
    _tap(fresh, app.filename)
    assert fresh.screen == "key"
    assert fresh.notice == "The seed was added successfully."


def test_binary_psbt_loads_from_temporary_fs_and_back_returns_to_load_transaction():
    app = App()
    app.session = _native()
    app.screen = "load-psbt"
    app.back = ["wallets", "wallet"]
    sdcard.write_bytes("transaction.psbt", _psbt(app.session).serialize(), storage="temporary")
    _tap(app, "Load from File")
    _tap(app, "Temporary FS")
    _tap(app, "transaction.psbt")
    assert app.screen == "psbt-yaml"
    app.back_one()
    assert app.screen == "load-psbt"
    assert app.back == ["wallets", "wallet"]


def test_message_command_from_temporary_fs_preserves_whitespace():
    app = App()
    app.session = _native()
    app.screen = "wallet"
    app._act("sign-message")
    sdcard.write_text("message.txt", "signmessage m/84h/0h/0h/0/0 ascii:  hello\n", storage="temporary")
    _tap(app, "Load from File")
    _tap(app, "Temporary FS")
    _tap(app, "message.txt")
    assert app.screen == "message-edit"
    assert app.message_text == "  hello\n"
    assert "storage" not in app.back and "sd" not in app.back


def test_switching_export_destination_resets_folder_scroll_and_name_collision():
    sdcard.mount_memory({"files": {"folder/old.txt": "card"}})
    app = _export_app("seed")
    _tap(app, "SD Card")
    _tap(app, "folder/")
    _tap(app, "old.txt")
    assert app.confirm == "replace-file"
    app._act("confirm-yes")
    assert sdcard.read_text("folder/old.txt") == ABANDON
    app._act("export-seed")
    _tap(app, "Continue")
    _tap(app, "Temporary FS")
    assert app.sd_dir == "" and app.scroll["sd"] == 0
    _tap(app, "New File")
    _tap(app, "Save")
    name = app.filename
    app._act("export-seed")
    _tap(app, "Continue")
    _tap(app, "Temporary FS")
    _tap(app, "New File")
    assert app.filename != name and " (1).txt" in app.filename


def test_missing_sd_card_is_a_popup_and_leaves_temporary_fs_accessible(monkeypatch, tmp_path):
    monkeypatch.setattr(sdcard, "DEFAULT_DISK_ROOT", str(tmp_path))
    monkeypatch.delenv("BIGSIGNER_SDCARD_PATH", raising=False)
    app = App()
    app.screen = "keys"
    app._act("add-sd")
    _tap(app, "SD Card")
    assert app.screen == "storage"
    assert app.notice == "No SD card is available."
    _tap(app, "dismiss-notice")
    _tap(app, "Temporary FS")
    assert app.screen == "sd"
    assert app.sd_storage == "temporary"
    with pytest.raises(sdcard.SdError, match="No SD card"):
        sdcard.write_text("should-not-exist.txt", "no")
    assert not (tmp_path / "should-not-exist.txt").exists()


def test_removing_card_during_export_refuses_write(monkeypatch, tmp_path):
    card = tmp_path / "card"
    card.mkdir()
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(card))
    app = _export_app("seed")
    _tap(app, "SD Card")
    _tap(app, "New File")
    card.rmdir()
    _tap(app, "Save")
    assert app.screen == "export-name"
    assert app.notice == "No SD card is available."


def test_temporary_files_never_appear_in_sd_snapshots_and_have_byte_usage():
    sdcard.mount_memory({"files": {"note.txt": "card"}})
    sdcard.write_text("note.txt", "é", storage="temporary")
    sdcard.write_bytes("data.bin", b"\x00\xff", storage="temporary")
    total, used, free = sdcard.disk_usage(storage="temporary")
    assert (total, used, free) == (sdcard.MEMORY_CAPACITY, 4, sdcard.MEMORY_CAPACITY - 4)
    assert sdcard.read_text("note.txt") == "card"
    assert sdcard.consume_memory_change() is None
    assert sdcard.memory_snapshot()["files"] == {"note.txt": "card"}
    sdcard.unmount_memory()
    assert sdcard.read_text("note.txt", storage="temporary") == "é"
    for operation in (sdcard.list_folder, sdcard.read_bytes, sdcard.file_exists):
        with pytest.raises(sdcard.SdError, match="outside"):
            operation("../escape", storage="temporary")
    with pytest.raises(sdcard.SdError, match="outside"):
        sdcard.write_text("../escape", "no", storage="temporary")


def test_virtual_storage_full_preserves_existing_file(monkeypatch):
    monkeypatch.setattr(sdcard, "MEMORY_CAPACITY", 4)
    sdcard.write_text("note.txt", "éé", storage="temporary")
    with pytest.raises(sdcard.SdError, match="free space"):
        sdcard.write_text("note.txt", "ééé", storage="temporary")
    assert sdcard.read_text("note.txt", storage="temporary") == "éé"
    sdcard.write_text("note.txt", "a", storage="temporary")
    assert sdcard.disk_usage(storage="temporary") == (4, 1, 3)


def test_native_temporary_directory_is_created_on_ram_and_refuses_symlink_escape(monkeypatch, tmp_path):
    root = tmp_path / "ram" / "bigsigner"
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", False)
    monkeypatch.setattr(sdcard, "TEMPORARY_ROOT", str(root))
    monkeypatch.setattr(sdcard, "_mounted_filesystems", lambda: [(tmp_path, "tmpfs")])
    assert sdcard.list_folder("", storage="temporary") == []
    assert root.is_dir()
    assert root.stat().st_mode & 0o777 == 0o700
    sdcard.write_bytes("test.psbt", b"psbt\xff", storage="temporary")
    assert (root / "test.psbt").read_bytes() == b"psbt\xff"
    (root / "escape").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(sdcard.SdError, match="outside"):
        sdcard.write_text("escape/no.txt", "no", storage="temporary")
    assert not (tmp_path / "no.txt").exists()


def test_temporary_directory_is_never_created_on_persistent_storage(monkeypatch, tmp_path):
    root = tmp_path / "bigsigner"
    monkeypatch.setattr(sdcard, "TEMPORARY_ROOT", str(root))
    monkeypatch.setattr(sdcard, "_mounted_filesystems", lambda: [(Path("/"), "ext4")])
    with pytest.raises(sdcard.SdError, match="No RAM filesystem"):
        sdcard._temporary_root()
    assert not root.exists()


def test_disk_usage_counts_used_and_available_blocks(monkeypatch, tmp_path):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    stats = SimpleNamespace(f_blocks=100, f_bfree=30, f_bavail=20, f_frsize=1024)
    monkeypatch.setattr(sdcard.os, "statvfs", lambda path: stats)
    assert sdcard.disk_usage() == (102400, 71680, 20480)


def test_ramfs_usage_uses_available_system_memory(monkeypatch, tmp_path):
    monkeypatch.setattr(sdcard, "MEMORY_TEMPORARY", False)
    monkeypatch.setattr(sdcard, "_temporary_root", lambda: tmp_path)
    stats = SimpleNamespace(f_blocks=0, f_bfree=0, f_bavail=0, f_frsize=4096)
    monkeypatch.setattr(sdcard.os, "statvfs", lambda path: stats)
    monkeypatch.setattr(Path, "read_text", lambda self: "MemTotal: 1024 kB\nMemFree: 128 kB\nMemAvailable: 512 kB\n")
    assert sdcard.disk_usage(storage="temporary") == (1048576, 524288, 524288)


@pytest.mark.parametrize("value,formatted", [(0, "0.0 B"), (1023, "1023.0 B"), (1024, "1.0 KiB"), (1536, "1.5 KiB"), (1024**3, "1.0 GiB")])
def test_human_sizes(value, formatted):
    assert sdcard.human_bytes(value) == formatted


def test_export_usage_is_fixed_while_files_scroll_and_updates_after_replacement(monkeypatch):
    sdcard.mount_memory({"files": {f"{index:02}.txt": "é" for index in range(20)}})
    app = _export_app("seed")
    _tap(app, "SD Card")
    app.render()
    first = {item["text"]: item["box"] for item in app.texts if item["text"].startswith(("Used:", "Free:", "Total:"))}
    assert set(first) == {"Used: 40.0 B / 64.0 MiB Free: 64.0 MiB"}
    fixed_bottom = max(box[3] for box in first.values())
    directory = next(item for item in app.texts if item["text"] == "/")
    assert fixed_bottom < directory["box"][1]
    app.scroll["sd"] = 10000
    app.render()
    assert app.scroll["sd"] > 0
    assert first == {item["text"]: item["box"] for item in app.texts if item["text"].startswith(("Used:", "Free:", "Total:"))}
    footer = next(hit["box"][1] for hit in app.hits if hit["label"] == "New File")
    assert all(fixed_bottom < hit["box"][1] < hit["box"][3] < footer for hit in app.hits if hit["action"].startswith("sd-write:"))
    sdcard.write_text("00.txt", "larger file")
    app.render()
    assert "Used: 49.0 B / 64.0 MiB Free: 64.0 MiB" in [item["text"] for item in app.texts]
    # Three long size values must still occupy one row within the page margins.
    monkeypatch.setattr("bigsigner.ui.app.disk_usage", lambda **kwargs: (1023.9 * 1024**4, 511.9 * 1024**4, 512 * 1024**4))
    app.render()
    usage = [item for item in app.texts if item["text"].startswith("Used:")]
    assert len(usage) == 1
    assert usage[0]["text"] == "Used: 511.9 TiB / 1023.9 TiB Free: 512.0 TiB"
    assert usage[0]["box"][2] <= WIDTH - 20
    assert usage[0]["box"][3] < directory["box"][1]


def test_storage_and_export_screens_save_screenshots():
    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_storage_and_export_screens_save_screenshots"))
    sdcard.mount_memory({"dirs": ["hello"], "files": {f"{index:02}-wallet.txt": "descriptor" * 129 for index in range(20)}})
    app = _export_app("seed")
    record.shot(app, "storage-choice")
    _tap(app, "SD Card")
    record.shot(app, "sd-export")
    _tap(app, "hello/")
    record.shot(app, "sd-export-folder")
    _tap(app, "..")
    app.scroll["sd"] = 10000
    record.shot(app, "sd-export-scrolled")
    app.back_one()
    _tap(app, "Temporary FS")
    record.shot(app, "temporary-export-empty")
    _tap(app, "New File")
    _tap(app, "Save")
    app._act("add-sd")
    _tap(app, "Temporary FS")
    record.shot(app, "temporary-load")
    for item in app.texts:
        left, top, right, bottom = item["box"]
        assert left >= 0 and right <= WIDTH and top >= 0 and bottom <= HEIGHT

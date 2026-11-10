"""SD card files for Load from File and Export to SD Card.

The browser page and the tests call mount_memory. An empty mounted card is
inserted. A text file is a string. A non-text file is stored as bytes, from a
``{"base64": "..."}`` value.

On the panel, when no memory card is mounted, the same helpers read and write
the FAT volume at ``/mnt/microsd`` (the path BigSigner OS mounts for
``mmcblk0p1``). ``BIGSIGNER_SDCARD_PATH`` overrides that root for tests.
"""

import base64
import os
from pathlib import Path


class SdError(Exception):
    pass


DEFAULT_DISK_ROOT = "/mnt/microsd"

_memory: dict | None = None
_memory_dirty = False


def mount_memory(card: dict) -> None:
    """Insert this card. dirs is a list of folder paths. files maps a path to its text."""
    global _memory, _memory_dirty
    if not isinstance(card, dict):
        raise SdError("The SD card data is not valid.")
    _memory = _normalize_memory(card)
    _memory_dirty = False


def unmount_memory() -> None:
    """Remove the memory card. The panel then uses the disk mount again, if any."""
    global _memory, _memory_dirty
    _memory = None
    _memory_dirty = False


def memory_snapshot() -> dict | None:
    """The mounted memory card, or None when no memory card is inserted."""
    if _memory is None:
        return None
    files = {path: _export_file(value) for path, value in _memory["files"].items()}
    return {"dirs": sorted(_memory["dirs"]), "files": files}


def consume_memory_change() -> dict | None:
    """The memory card after a write since the last call, or None when nothing was saved."""
    global _memory_dirty
    if _memory is None or not _memory_dirty:
        return None
    _memory_dirty = False
    return memory_snapshot()


def list_folder(relative: str) -> list[dict]:
    """Entries in one folder. Directories come first. Each item has name and kind."""
    if _memory is not None:
        return _list_memory(relative)
    return _list_disk(relative)


def read_text(relative: str, *, raw: bool = False) -> str:
    """The file's text. Surrounding space and newlines are removed unless raw is set."""
    if _memory is not None:
        return _read_memory(relative, raw=raw)
    data = _read_disk_bytes(relative)
    if b"\x00" in data:
        raise SdError("That file is not text.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SdError("That file is not text.") from exc
    return text if raw else text.strip()


def read_bytes(relative: str) -> bytes:
    """The file's bytes, including a non-text file. A file above 256000 bytes is refused."""
    if _memory is not None:
        return _file_bytes(relative)
    return _read_disk_bytes(relative)


def file_exists(relative: str) -> bool:
    """True when that path is a file on the card. A missing file is False."""
    if _memory is not None:
        path = _memory_path(relative)
        return bool(path) and path in _memory["files"]
    return _disk_path(relative).is_file()


def write_text(relative: str, text: str) -> None:
    """Replace one text file on the card, or create it. The path must stay on the card."""
    if _memory is not None:
        _write_memory(relative, text)
        return
    _write_disk(relative, text.encode("utf-8"))


def write_bytes(relative: str, data: bytes) -> None:
    """Replace one file with these bytes, or create it. The path must stay on the card."""
    if _memory is not None:
        _write_memory(relative, data)
        return
    _write_disk(relative, data)


def child_path(directory: str, name: str) -> str:
    if not directory:
        return name
    return f"{directory}/{name}"


def parent_path(directory: str) -> str:
    if not directory:
        return ""
    parent = Path(directory).parent
    if parent == Path("."):
        return ""
    return parent.as_posix()


def _normalize_memory(card: dict) -> dict:
    raw_dirs = card.get("dirs") or []
    raw_files = card.get("files") or {}
    if isinstance(raw_dirs, str) or not isinstance(raw_dirs, (list, tuple)):
        raise SdError("The SD card data is not valid.")
    if not isinstance(raw_files, dict):
        raise SdError("The SD card data is not valid.")
    dirs: set[str] = set()
    files: dict[str, str | bytes] = {}
    for item in raw_dirs:
        if not isinstance(item, str):
            continue
        rel = _safe_memory_path(item)
        if rel:
            _remember_dir(dirs, rel)
    for path, text in raw_files.items():
        if not isinstance(path, str):
            continue
        stored = _stored_file(text)
        if stored is None:
            continue
        rel = _safe_memory_path(path)
        if not rel or rel in dirs:
            continue
        parent = parent_path(rel)
        if parent:
            _remember_dir(dirs, parent)
        if rel in dirs:
            continue
        files[rel] = stored
    for path in list(files):
        if path in dirs:
            del files[path]
    return {"dirs": dirs, "files": files}


def _stored_file(value):
    """A text string, the bytes of a base64 file, or None when the value is unusable."""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value
    if isinstance(value, dict):
        encoded = value.get("base64")
        if isinstance(encoded, str):
            try:
                return base64.b64decode(encoded, validate=True)
            except Exception:
                return None
    return None


def _export_file(value):
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    return value


def _remember_dir(dirs: set[str], relative: str) -> None:
    while relative:
        dirs.add(relative)
        relative = parent_path(relative)


def _safe_memory_path(relative: str) -> str:
    try:
        return _memory_path(relative)
    except SdError:
        return ""


def _memory_path(relative: str) -> str:
    relative = (relative or "").strip().strip("/")
    if "\\" in relative or "\x00" in relative:
        raise SdError("That path is outside the SD card.")
    parts = Path(relative).parts if relative else ()
    if any(part in ("", ".", "..") for part in parts):
        raise SdError("That path is outside the SD card.")
    return "/".join(parts)


def _list_memory(relative: str) -> list[dict]:
    folder = _memory_path(relative)
    if folder in _memory["files"] or (folder and folder not in _memory["dirs"]):
        raise SdError("That folder is not on the SD card.")
    prefix = f"{folder}/" if folder else ""
    entries = []
    seen = set()
    for directory in _memory["dirs"]:
        name = _child_name(directory, prefix)
        if name and name not in seen:
            seen.add(name)
            entries.append({"name": name, "kind": "dir"})
    for path in _memory["files"]:
        name = _child_name(path, prefix)
        if name and name not in seen:
            seen.add(name)
            entries.append({"name": name, "kind": "file"})
    entries.sort(key=lambda item: (item["kind"] != "dir", item["name"].casefold()))
    return entries


def _child_name(path: str, prefix: str) -> str:
    if prefix:
        if not path.startswith(prefix):
            return ""
        rest = path[len(prefix) :]
    else:
        rest = path
    if not rest or "/" in rest:
        return ""
    return rest


def _file_bytes(relative: str) -> bytes:
    path = _memory_path(relative)
    if not path or path in _memory["dirs"] or path not in _memory["files"]:
        raise SdError("That is not a file.")
    stored = _memory["files"][path]
    data = stored if isinstance(stored, bytes) else stored.encode("utf-8")
    if len(data) > 256_000:
        raise SdError("That file is too large.")
    return data


def _read_memory(relative: str, raw: bool = False) -> str:
    data = _file_bytes(relative)
    if b"\x00" in data:
        raise SdError("That file is not text.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SdError("That file is not text.") from exc
    return text if raw else text.strip()


def _write_memory(relative: str, text: str | bytes) -> None:
    global _memory_dirty
    path = _memory_path(relative)
    if not path or path in _memory["dirs"]:
        raise SdError("That is a folder.")
    parent = parent_path(path)
    if parent and parent not in _memory["dirs"]:
        raise SdError("That folder is not on the SD card.")
    _memory["files"][path] = text
    _memory_dirty = True


def _disk_root() -> Path:
    """The mounted FAT volume, or an error when the card is not there."""
    raw = os.environ.get("BIGSIGNER_SDCARD_PATH", DEFAULT_DISK_ROOT).strip()
    root = Path(raw or DEFAULT_DISK_ROOT)
    if root.is_dir():
        return root
    raise SdError("No SD card is available.")


def _disk_path(relative: str) -> Path:
    """Absolute path under the disk root. Escaping the card is refused."""
    root = _disk_root().resolve()
    rel = _memory_path(relative)
    if not rel:
        return root
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SdError("That path is outside the SD card.") from exc
    return candidate


def _list_disk(relative: str) -> list[dict]:
    folder = _disk_path(relative)
    if not folder.is_dir():
        raise SdError("That folder is not on the SD card.")
    entries = []
    try:
        children = list(folder.iterdir())
    except OSError as exc:
        raise SdError("No SD card is available.") from exc
    for child in children:
        try:
            if child.is_dir():
                entries.append({"name": child.name, "kind": "dir"})
            elif child.is_file():
                entries.append({"name": child.name, "kind": "file"})
        except OSError:
            continue
    entries.sort(key=lambda item: (item["kind"] != "dir", item["name"].casefold()))
    return entries


def _read_disk_bytes(relative: str) -> bytes:
    path = _disk_path(relative)
    if not path.is_file():
        raise SdError("That is not a file.")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SdError("That is not a file.") from exc
    if size > 256_000:
        raise SdError("That file is too large.")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SdError("That is not a file.") from exc
    if len(data) > 256_000:
        raise SdError("That file is too large.")
    return data


def _write_disk(relative: str, data: bytes) -> None:
    path = _disk_path(relative)
    if path.is_dir():
        raise SdError("That is a folder.")
    parent = path.parent
    if not parent.is_dir():
        raise SdError("That folder is not on the SD card.")
    try:
        with open(path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SdError("Could not write that file.") from exc

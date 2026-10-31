"""Read files from the microSD card.

A process uses BIGSIGNER_SDCARD_PATH as that card, including the tests. A
missing or unusable path means no card is inserted.

The browser page calls mount_memory. That card is inserted even when it is
empty, and the path variable is not used.
"""

import os
from pathlib import Path


class SdError(Exception):
    pass


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
    """Return to the folder in BIGSIGNER_SDCARD_PATH, or to no card."""
    global _memory, _memory_dirty
    _memory = None
    _memory_dirty = False


def memory_snapshot() -> dict | None:
    """The mounted card, or None when the folder path is in use."""
    if _memory is None:
        return None
    return {"dirs": sorted(_memory["dirs"]), "files": dict(_memory["files"])}


def consume_memory_change() -> dict | None:
    """The card after a write since the last call, or None when nothing was saved."""
    global _memory_dirty
    if _memory is None or not _memory_dirty:
        return None
    _memory_dirty = False
    return memory_snapshot()


def card_root() -> Path | None:
    """The folder that stands in for the card, or None when no card is present."""
    raw = os.environ.get("BIGSIGNER_SDCARD_PATH", "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve()
    except OSError as exc:
        raise SdError("The SD card folder cannot be opened.") from exc
    if not resolved.is_dir():
        raise SdError("BIGSIGNER_SDCARD_PATH is not a folder.")
    return resolved


def list_folder(relative: str) -> list[dict]:
    """Entries in one folder. Directories come first. Each item has name and kind."""
    if _memory is not None:
        return _list_memory(relative)
    folder = _inside(relative)
    if not folder.is_dir():
        raise SdError("That folder is not on the SD card.")
    root = card_root()
    entries = []
    try:
        children = list(folder.iterdir())
    except OSError as exc:
        raise SdError("That folder cannot be opened.") from exc
    for child in children:
        if child.name in (".", ".."):
            continue
        try:
            target = child.resolve()
        except OSError:
            continue
        if root is None or not target.is_relative_to(root):
            continue
        entries.append({"name": child.name, "kind": "dir" if target.is_dir() else "file"})
    entries.sort(key=lambda item: (item["kind"] != "dir", item["name"].casefold()))
    return entries


def read_text(relative: str) -> str:
    """The file's text, with surrounding space and newlines removed."""
    if _memory is not None:
        return _read_memory(relative)
    path = _inside(relative)
    if not path.is_file():
        raise SdError("That is not a file.")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SdError("That file cannot be read.") from exc
    if size > 256_000:
        raise SdError("That file is too large.")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SdError("That file cannot be read.") from exc
    if b"\x00" in data:
        raise SdError("That file is not text.")
    return data.decode("utf-8", errors="replace").strip()


def file_exists(relative: str) -> bool:
    """True when that path is a file on the card. A missing file is False."""
    if _memory is not None:
        path = _memory_path(relative)
        return bool(path) and path in _memory["files"]
    return _inside(relative).is_file()


def write_text(relative: str, text: str) -> None:
    """Replace one text file on the card, or create it. The path must stay on the card."""
    if _memory is not None:
        _write_memory(relative, text)
        return
    path = _inside(relative)
    if path.is_dir():
        raise SdError("That is a folder.")
    if not path.parent.is_dir():
        raise SdError("That folder is not on the SD card.")
    body = text if text.endswith("\n") else text + "\n"
    try:
        path.write_text(body, encoding="utf-8")
    except OSError as exc:
        raise SdError("That file cannot be written.") from exc


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


def _inside(relative: str) -> Path:
    root = card_root()
    if root is None:
        raise SdError("No SD card is available.")
    relative = relative.strip("/")
    parts = Path(relative).parts if relative else ()
    if any(part in ("", ".", "..") for part in parts):
        raise SdError("That path is outside the SD card.")
    try:
        path = (root.joinpath(*parts)).resolve()
    except OSError as exc:
        raise SdError("That path is outside the SD card.") from exc
    if not path.is_relative_to(root):
        raise SdError("That path is outside the SD card.")
    return path


def _normalize_memory(card: dict) -> dict:
    raw_dirs = card.get("dirs") or []
    raw_files = card.get("files") or {}
    if isinstance(raw_dirs, str) or not isinstance(raw_dirs, (list, tuple)):
        raise SdError("The SD card data is not valid.")
    if not isinstance(raw_files, dict):
        raise SdError("The SD card data is not valid.")
    dirs: set[str] = set()
    files: dict[str, str] = {}
    for item in raw_dirs:
        if not isinstance(item, str):
            continue
        rel = _safe_memory_path(item)
        if rel:
            _remember_dir(dirs, rel)
    for path, text in raw_files.items():
        if not isinstance(path, str) or not isinstance(text, str):
            continue
        rel = _safe_memory_path(path)
        if not rel or rel in dirs:
            continue
        parent = parent_path(rel)
        if parent:
            _remember_dir(dirs, parent)
        if rel in dirs:
            continue
        files[rel] = text
    for path in list(files):
        if path in dirs:
            del files[path]
    return {"dirs": dirs, "files": files}


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


def _read_memory(relative: str) -> str:
    path = _memory_path(relative)
    if not path or path in _memory["dirs"] or path not in _memory["files"]:
        raise SdError("That is not a file.")
    data = _memory["files"][path].encode("utf-8")
    if len(data) > 256_000:
        raise SdError("That file is too large.")
    if b"\x00" in data:
        raise SdError("That file is not text.")
    return data.decode("utf-8").strip()


def _write_memory(relative: str, text: str) -> None:
    global _memory_dirty
    path = _memory_path(relative)
    if not path or path in _memory["dirs"]:
        raise SdError("That is a folder.")
    parent = parent_path(path)
    if parent and parent not in _memory["dirs"]:
        raise SdError("That folder is not on the SD card.")
    body = text if text.endswith("\n") else text + "\n"
    _memory["files"][path] = body
    _memory_dirty = True

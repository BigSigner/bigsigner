"""The SD card kept in memory.

The browser page and the tests call mount_memory. An empty mounted card is
inserted. Nothing is read from a folder on disk.
"""

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
    """Remove the card."""
    global _memory, _memory_dirty
    _memory = None
    _memory_dirty = False


def memory_snapshot() -> dict | None:
    """The mounted card, or None when no card is inserted."""
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


def _require_card() -> dict:
    if _memory is None:
        raise SdError("No SD card is available.")
    return _memory


def list_folder(relative: str) -> list[dict]:
    """Entries in one folder. Directories come first. Each item has name and kind."""
    _require_card()
    return _list_memory(relative)


def read_text(relative: str) -> str:
    """The file's text, with surrounding space and newlines removed."""
    _require_card()
    return _read_memory(relative)


def file_exists(relative: str) -> bool:
    """True when that path is a file on the card. A missing file is False."""
    _require_card()
    path = _memory_path(relative)
    return bool(path) and path in _memory["files"]


def write_text(relative: str, text: str) -> None:
    """Replace one text file on the card, or create it. The path must stay on the card."""
    _require_card()
    _write_memory(relative, text)


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

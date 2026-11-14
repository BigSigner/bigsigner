"""File access for SD Card and the RAM-only Temporary FS.

The browser page and the tests call mount_memory. An empty mounted card is
inserted. A text file is a string. A non-text file is stored as bytes, from a
``{"base64": "..."}`` value.

On the panel, when no memory card is mounted, the same helpers read and write
the FAT volume at ``/mnt/microsd`` (the path BigSigner OS mounts for
``mmcblk0p1``). ``BIGSIGNER_SDCARD_PATH`` overrides that root for tests.

Pass ``storage="temporary"`` for separate RAM storage. The panel creates
``/tmp/bigsigner`` on its RAM rootfs; desktop Linux can use ``/dev/shm``.
Other hosts and the browser keep temporary files in Python memory.
"""

import base64
import os
import sys
from pathlib import Path


class SdError(Exception):
    pass


DEFAULT_DISK_ROOT = "/mnt/microsd"
TEMPORARY_ROOT = "/tmp/bigsigner"
# Virtual cards and the browser's Temporary FS have a bounded, simulated capacity.
MEMORY_CAPACITY = 64 * 1024 * 1024
MEMORY_TEMPORARY = sys.platform != "linux"

_memory: dict | None = None
_memory_dirty = False
_temporary_memory = {"dirs": set(), "files": {}}


def _memory_card(storage: str) -> dict | None:
    if storage == "sd":
        return _memory
    if storage == "temporary":
        # The panel uses a real directory on its RAM filesystem. Other hosts
        # (including Pyodide) keep files in Python memory, never the host disk.
        return _temporary_memory if MEMORY_TEMPORARY else None
    raise SdError("Unknown storage.")


def disk_usage(*, storage: str = "sd") -> tuple[int, int, int]:
    """Total, used and available bytes on the selected filesystem."""
    card = _memory_card(storage)
    if card is not None:
        used = _memory_used(card)
        return MEMORY_CAPACITY, used, max(0, MEMORY_CAPACITY - used)
    root = _disk_root(storage)
    try:
        stats = os.statvfs(root)
    except OSError as exc:
        raise SdError("Could not read disk usage.") from exc
    total = stats.f_blocks * stats.f_frsize
    used = total - stats.f_bfree * stats.f_frsize
    if not total and storage == "temporary":
        # ramfs/rootfs have no block limit and report zero blocks. Their
        # available capacity is the RAM shared with the rest of the OS.
        try:
            memory = {}
            for line in Path("/proc/meminfo").read_text().splitlines():
                key, value = line.split(":", 1)
                memory[key] = int(value.split()[0]) * 1024
            total = memory["MemTotal"]
            free = memory["MemAvailable"] if "MemAvailable" in memory else memory["MemFree"]
            return total, total - free, free
        except (OSError, KeyError, ValueError) as exc:
            raise SdError("Could not read RAM usage.") from exc
    return total, used, stats.f_bavail * stats.f_frsize


def human_bytes(value: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024 or unit == "PiB":
            return f"{value:.1f} {unit}"
        value /= 1024


def _memory_used(card: dict) -> int:
    return sum(len(value if isinstance(value, bytes) else value.encode("utf-8")) for value in card["files"].values())


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


def list_folder(relative: str, *, storage: str = "sd") -> list[dict]:
    """Entries in one folder. Directories come first. Each item has name and kind."""
    card = _memory_card(storage)
    if card is not None:
        return _list_memory(relative, card)
    return _list_disk(relative, storage)


def read_text(relative: str, *, raw: bool = False, storage: str = "sd") -> str:
    """The file's text. Surrounding space and newlines are removed unless raw is set."""
    data = read_bytes(relative, storage=storage)
    if b"\x00" in data:
        raise SdError("That file is not text.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SdError("That file is not text.") from exc
    return text if raw else text.strip()


def read_bytes(relative: str, *, storage: str = "sd") -> bytes:
    """The file's bytes, including a non-text file. A file above 256000 bytes is refused."""
    card = _memory_card(storage)
    if card is not None:
        return _file_bytes(relative, card)
    return _read_disk_bytes(relative, storage)


def file_exists(relative: str, *, storage: str = "sd") -> bool:
    """True when that path is a file in the selected storage."""
    card = _memory_card(storage)
    if card is not None:
        path = _memory_path(relative)
        return bool(path) and path in card["files"]
    return _disk_path(relative, storage).is_file()


def write_text(relative: str, text: str, *, storage: str = "sd") -> None:
    """Replace or create a text file within the selected storage."""
    _write_file(relative, text, storage)


def write_bytes(relative: str, data: bytes, *, storage: str = "sd") -> None:
    """Replace or create a binary file within the selected storage."""
    _write_file(relative, data, storage)


def _write_file(relative: str, data: str | bytes, storage: str) -> None:
    global _memory_dirty
    card = _memory_card(storage)
    if card is not None:
        _write_memory(relative, data, card)
        if storage == "sd":
            _memory_dirty = True
        return
    _write_disk(relative, data.encode("utf-8") if isinstance(data, str) else data, storage)


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
        raise SdError("That path is outside the selected storage.")
    parts = Path(relative).parts if relative else ()
    if any(part in ("", ".", "..") for part in parts):
        raise SdError("That path is outside the selected storage.")
    return "/".join(parts)


def _list_memory(relative: str, card: dict) -> list[dict]:
    folder = _memory_path(relative)
    if folder in card["files"] or (folder and folder not in card["dirs"]):
        raise SdError("That folder is not available.")
    prefix = f"{folder}/" if folder else ""
    entries = []
    seen = set()
    for directory in card["dirs"]:
        name = _child_name(directory, prefix)
        if name and name not in seen:
            seen.add(name)
            entries.append({"name": name, "kind": "dir"})
    for path in card["files"]:
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


def _file_bytes(relative: str, card: dict) -> bytes:
    path = _memory_path(relative)
    if not path or path in card["dirs"] or path not in card["files"]:
        raise SdError("That is not a file.")
    stored = card["files"][path]
    data = stored if isinstance(stored, bytes) else stored.encode("utf-8")
    if len(data) > 256_000:
        raise SdError("That file is too large.")
    return data


def _write_memory(relative: str, text: str | bytes, card: dict) -> None:
    path = _memory_path(relative)
    if not path or path in card["dirs"]:
        raise SdError("That is a folder.")
    parent = parent_path(path)
    if parent and parent not in card["dirs"]:
        raise SdError("That folder is not available.")
    old = card["files"].get(path, b"")
    old_size = len(old if isinstance(old, bytes) else old.encode("utf-8"))
    size = len(text if isinstance(text, bytes) else text.encode("utf-8"))
    if _memory_used(card) - old_size + size > MEMORY_CAPACITY:
        raise SdError("There is not enough free space.")
    card["files"][path] = text


def _disk_root(storage: str = "sd") -> Path:
    """The mounted FAT volume, or an error when the card is not there."""
    if storage == "temporary":
        return _temporary_root()
    raw = os.environ.get("BIGSIGNER_SDCARD_PATH", "").strip()
    root = Path(raw or DEFAULT_DISK_ROOT)
    # A leftover mount directory is not an inserted card. The explicit path
    # override allows ordinary directories for tests and local development.
    if root.is_dir() and (raw or root.is_mount()):
        return root
    raise SdError("No SD card is available.")


def _temporary_root() -> Path:
    root = Path(TEMPORARY_ROOT)
    try:
        # Refuse persistent filesystems even on Linux development machines.
        # The panel's initramfs is rootfs/ramfs; /dev/shm is tmpfs on desktop Linux.
        mounts = _mounted_filesystems()
        for candidate in (root, Path("/dev/shm/bigsigner")):
            resolved = candidate.resolve()
            covering = [(mount, kind) for mount, kind in mounts if resolved == mount or mount in resolved.parents]
            if covering and max(covering, key=lambda item: len(item[0].parts))[1] in ("rootfs", "ramfs", "tmpfs"):
                candidate.mkdir(mode=0o700, parents=True, exist_ok=True)
                return candidate
    except OSError as exc:
        raise SdError("Could not open Temporary FS.") from exc
    raise SdError("No RAM filesystem is available.")


def _mounted_filesystems() -> list[tuple[Path, str]]:
    mounts = []
    for line in Path("/proc/self/mounts").read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3:
            mount = Path(fields[1].replace("\\040", " ").replace("\\134", "\\"))
            mounts.append((mount, fields[2]))
    return mounts


def _disk_path(relative: str, storage: str = "sd") -> Path:
    """Absolute path under the disk root. Escaping the card is refused."""
    root = _disk_root(storage).resolve()
    rel = _memory_path(relative)
    if not rel:
        return root
    candidate = (root / rel).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SdError("That path is outside the selected storage.") from exc
    return candidate


def _list_disk(relative: str, storage: str) -> list[dict]:
    folder = _disk_path(relative, storage)
    if not folder.is_dir():
        raise SdError("That folder is not available.")
    entries = []
    try:
        children = list(folder.iterdir())
    except OSError as exc:
        raise SdError("Could not open that folder.") from exc
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


def _read_disk_bytes(relative: str, storage: str) -> bytes:
    path = _disk_path(relative, storage)
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


def _write_disk(relative: str, data: bytes, storage: str) -> None:
    path = _disk_path(relative, storage)
    if path.is_dir():
        raise SdError("That is a folder.")
    parent = path.parent
    if not parent.is_dir():
        raise SdError("That folder is not available.")
    try:
        with open(path, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise SdError("Could not write that file.") from exc

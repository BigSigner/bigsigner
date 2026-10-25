"""Read files from the microSD card.

The emulator uses BIGSIGNER_SDCARD_PATH as that card. A missing or unusable
path means no card is inserted.
"""

import os
from pathlib import Path


class SdError(Exception):
    pass


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
    return _inside(relative).is_file()


def write_text(relative: str, text: str) -> None:
    """Replace one text file on the card, or create it. The path must stay on the card."""
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

"""Write the browser emulator's copy of the source tree.

    python -m bigsigner.bundle

The page in web/ reads web/bundle.json and does not open src/ itself.
That file is generated and is not committed.
"""

import base64
import json
import sys
from pathlib import Path

SKIP_NAMES = {".DS_Store"}
SKIP_PARTS = {"__pycache__"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def source_root() -> Path:
    return repo_root() / "src"


def bundle_path() -> Path:
    return repo_root() / "web" / "bundle.json"


def source_files(src: Path):
    """Files under src, in path order. Finder metadata and bytecode are left out."""
    paths = []
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(src)
        if path.name in SKIP_NAMES or path.suffix == ".pyc":
            continue
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        paths.append(path)
    paths.sort(key=lambda path: path.relative_to(src).as_posix())
    return paths


def bundle_files(src: Path) -> dict:
    """Map a path relative to src to its text, or to base64 when it is not text."""
    files = {}
    for path in source_files(src):
        relative = path.relative_to(src).as_posix()
        data = path.read_bytes()
        try:
            files[relative] = {"text": data.decode("utf-8")}
        except UnicodeDecodeError:
            files[relative] = {"base64": base64.b64encode(data).decode("ascii")}
    return files


def write_bundle(src: Path | None = None, dest: Path | None = None) -> Path:
    """Write the bundle and return its path."""
    src = source_root() if src is None else src
    dest = bundle_path() if dest is None else dest
    if not src.is_dir():
        raise SystemExit(f"Missing {src}.")
    document = {"files": bundle_files(src)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return dest


def main():
    if len(sys.argv) > 1:
        raise SystemExit("Usage: python -m bigsigner.bundle")
    dest = write_bundle()
    print(f"Wrote {dest} ({len(source_files(source_root()))} files).")


if __name__ == "__main__":
    main()

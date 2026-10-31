"""Write the browser emulator's copy of the source tree.

    python -m bigsigner.bundle

The page in web/ reads web/bundle.json and does not open src/ itself.
That file is generated and is not committed. The same command downloads the
pinned Pyodide runtime, Pillow, embit, and qrcode into web/external-assets.
Those files are not committed either. The page loads them from that folder.
"""

import base64
import hashlib
import json
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

SKIP_NAMES = {".DS_Store"}
SKIP_PARTS = {"__pycache__"}

# Pyodide 314.0.7. The pyodide folder is indexURL: the loader, the runtime,
# the standard library, and the package lock. Pillow's wheel is named by that
# lock, and the worker points packageBaseUrl at the pillow folder. embit and
# qrcode are not Pyodide packages; the worker unpacks them itself.
_PYODIDE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/"
EXTERNAL_ASSETS = (
    ("pyodide/pyodide.mjs", _PYODIDE + "pyodide.mjs", "6f1d60f7bf529beb300f0f47983c921d3982363640ba20af0e38efdddbc66109"),
    ("pyodide/pyodide.asm.mjs", _PYODIDE + "pyodide.asm.mjs", "f7cdc8ece80678ceb712f8e65ebe6d3a83203a180c399865f49612a051693635"),
    ("pyodide/pyodide.asm.wasm", _PYODIDE + "pyodide.asm.wasm", "cc36e3cab04fdfc9a63ff13eb52eae2b911bf46c025cc7b281f394bd3de1d5e6"),
    ("pyodide/python_stdlib.zip", _PYODIDE + "python_stdlib.zip", "fa1957e5777068fc4f7437f96d860ae2fbe9c19732ba06c84e004ec16dd7dd7a"),
    ("pyodide/pyodide-lock.json", _PYODIDE + "pyodide-lock.json", "5dc2fc119108bc148c7457dc86e7675b5c87e1cafd420b9c34c1eaef7b36c010"),
    (
        "pillow/pillow-12.2.0-cp314-cp314-pyemscripten_2026_0_wasm32.whl",
        _PYODIDE + "pillow-12.2.0-cp314-cp314-pyemscripten_2026_0_wasm32.whl",
        "e29838b7a756e4ee0f27a9cfa9a387ee0dfa2e9dd44be2dd595130b9f9d93ac3",
    ),
    (
        "embit/embit-0.8.0.tar.gz",
        "https://files.pythonhosted.org/packages/83/88/b054b00ade6d2a41749e15976cdcec4b7ec4656ac1cb917ce3de395528d1/embit-0.8.0.tar.gz",
        "8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770",
    ),
    (
        "qrcode/qrcode-8.0-py3-none-any.whl",
        "https://files.pythonhosted.org/packages/74/ab/df8d889fd01139db68ae9e5cb5c8f0ea016823559a6ecb427582d52b07dc/qrcode-8.0-py3-none-any.whl",
        "9fc05f03305ad27a709eb742cf3097fa19e6f6f93bb9e2f039c0979190f6f1b1",
    ),
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def source_root() -> Path:
    return repo_root() / "src"


def bundle_path() -> Path:
    return repo_root() / "web" / "bundle.json"


def external_assets_path() -> Path:
    return repo_root() / "web" / "external-assets"


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


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(url: str) -> bytes:
    print(f"Downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.read()
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not download {url}. {exc.reason}") from exc


def _asset_path(dest: Path, name: str) -> Path:
    relative = Path(name)
    if (
        not name
        or relative.is_absolute()
        or "\\" in name
        or ".." in relative.parts
        or any(part in ("", ".") for part in relative.parts)
    ):
        raise SystemExit(f"Bad external asset name {name}.")
    return dest.joinpath(*relative.parts)


def install_assets(dest: Path, assets, fetch=_download) -> None:
    """Save each pinned file. A file already on disk is kept when its hash matches."""
    dest.mkdir(parents=True, exist_ok=True)
    for name, url, expected in assets:
        target = _asset_path(dest, name)
        legacy = dest / Path(name).name
        if target.is_file() and _sha256(target.read_bytes()) == expected:
            if legacy != target and legacy.is_file():
                legacy.unlink()
            continue
        # An earlier bundle saved these files directly in external-assets.
        if legacy != target and legacy.is_file() and _sha256(legacy.read_bytes()) == expected:
            target.parent.mkdir(parents=True, exist_ok=True)
            legacy.replace(target)
            continue
        data = fetch(url)
        actual = _sha256(data)
        if actual != expected:
            raise SystemExit(f"SHA-256 for {url} was {actual}, expected {expected}.")
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".partial")
        temporary.write_bytes(data)
        temporary.replace(target)
        if legacy != target and legacy.is_file():
            legacy.unlink()


def install_external_assets(dest: Path | None = None) -> Path:
    """Download the pinned runtime into web/external-assets."""
    dest = external_assets_path() if dest is None else dest
    install_assets(dest, EXTERNAL_ASSETS)
    return dest


def write_bundle(src: Path | None = None, dest: Path | None = None) -> Path:
    """Write the bundle and return its path."""
    src = source_root() if src is None else src
    dest = bundle_path() if dest is None else dest
    if not src.is_dir():
        raise SystemExit(f"Missing {src}.")
    document = {"files": bundle_files(src)}
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    icon = src / "bigsigner" / "resources" / "icon.png"
    if icon.is_file():
        shutil.copyfile(icon, dest.parent / "icon.png")
    return dest


def main():
    if len(sys.argv) > 1:
        raise SystemExit("Usage: python -m bigsigner.bundle")
    dest = write_bundle()
    assets = install_external_assets()
    print(f"Wrote {dest} ({len(source_files(source_root()))} files).")
    print(f"Checked {assets} ({len(EXTERNAL_ASSETS)} external files).")


if __name__ == "__main__":
    main()

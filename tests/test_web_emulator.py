"""The static page runs the app in the browser."""

import base64
import json
from pathlib import Path

from bigsigner.bundle import bundle_files, source_files, source_root, write_bundle


def test_the_static_page_reads_the_bundle_and_checks_downloads():
    page = Path("web/index.html").read_text(encoding="utf-8")
    worker = Path("web/worker.js").read_text(encoding="utf-8")
    assert 'rel="icon" href="icon.png"' in page
    assert 'params.get("seed")' in page
    assert 'params.get("descriptor")' in page
    assert "BIGSIGNER_SDCARD_PATH" not in page
    assert "BIGSIGNER_SDCARD_PATH" not in worker
    assert "bigsigner-sdcard" in page
    assert "mount_memory" in worker
    assert "cardJson" in worker
    assert "bundle.json" in worker
    assert "manifest.json" not in worker
    assert "src/bigsigner" not in worker
    assert 'new URL("../"' not in page
    assert "crypto.subtle.digest" in worker
    assert "8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770" in worker
    assert "9fc05f03305ad27a709eb742cf3097fa19e6f6f93bb9e2f039c0979190f6f1b1" in worker
    assert "python -m bigsigner.bundle" in worker


def test_the_bundle_of_this_tree_includes_the_package_and_skips_metadata():
    paths = [path.relative_to(source_root()).as_posix() for path in source_files(source_root())]
    assert "bigsigner/ui/app.py" in paths
    assert "main.py" in paths
    assert all(".DS_Store" not in path and "__pycache__" not in path and not path.endswith(".pyc") for path in paths)


def test_the_bundle_stores_text_and_base64_and_skips_junk(tmp_path):
    src = tmp_path / "src"
    package = src / "bigsigner"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('value = "ok"\n', encoding="utf-8")
    (package / ".DS_Store").write_bytes(b"junk")
    cache = package / "__pycache__"
    cache.mkdir()
    (cache / "mod.pyc").write_bytes(b"\0\0")
    (src / "logo.bin").write_bytes(b"\xff\xfe")
    document = bundle_files(src)
    assert set(document) == {"bigsigner/__init__.py", "logo.bin"}
    assert document["bigsigner/__init__.py"]["text"] == 'value = "ok"\n'
    assert base64.b64decode(document["logo.bin"]["base64"]) == b"\xff\xfe"

    icon = package / "resources" / "icon.png"
    icon.parent.mkdir()
    icon.write_bytes(b"\x89PNG\r\n")
    dest = tmp_path / "web" / "bundle.json"
    written = write_bundle(src, dest)
    assert written == dest
    saved = json.loads(dest.read_text(encoding="utf-8"))["files"]
    assert saved["bigsigner/__init__.py"] == document["bigsigner/__init__.py"]
    assert saved["logo.bin"] == document["logo.bin"]
    assert (tmp_path / "web" / "icon.png").read_bytes() == b"\x89PNG\r\n"

"""The static page runs the app in the browser."""

import base64
import hashlib
import json
from pathlib import Path

import pytest

from bigsigner.bundle import EXTERNAL_ASSETS, bundle_files, install_assets, source_files, source_root, write_bundle


def test_the_static_page_reads_the_bundle_and_checks_downloads():
    page = Path("web/index.html").read_text(encoding="utf-8")
    worker = Path("web/worker.js").read_text(encoding="utf-8")
    assert 'rel="icon" href="icon.png"' in page
    assert "function downloadFile" in page
    assert 'id="sd-text"' in page
    assert 'placeholder="Folder/File name"' in page
    assert ">New Folder<" in page
    assert ">New File<" in page
    assert 'id="sd-folder"' not in page
    assert 'id="sd-filename"' not in page
    assert 'rename.textContent = "Rename"' in page
    assert "Downloading a binary file." in page
    assert "file.arrayBuffer" in page
    assert 'return "That file is not text."' not in page
    assert 'params.get("seed")' in page
    assert 'params.get("descriptor")' in page
    assert 'params.get("network")' in page
    assert 'id="hash-panel"' in page
    assert "Preloaded Parameters" in page
    assert 'id="about-panel" class="collapsed"' in page
    assert 'id="about-toggle"' in page
    assert 'aria-expanded="false"' in page
    assert "Isolated Chocolate Boar 4D" in page
    assert "https://bigsigner.com" in page
    assert 'id="sd-toggle"' in page
    assert 'id="hash-toggle"' in page
    assert 'root.textContent = "SD Card"' not in page
    assert 'setCardOpen("sd-toggle", card.dirs.length > 0 || Object.keys(card.files).length > 0)' in page
    assert 'setCardOpen("hash-toggle", Boolean(initial.seed.trim() || initial.descriptor.trim() || initial.network.trim()))' in page
    assert 'class="chevron"' in page
    assert 'method="dialog"' in page
    assert 'id="hash-seed"' in page
    assert 'id="hash-descriptor"' in page
    assert 'id="hash-network"' in page
    assert '<option value="mainnet">mainnet</option>' in page
    assert '<option value="testnet">testnet</option>' in page
    assert '<option value="regtest">regtest</option>' in page
    assert ">Reload<" in page
    assert 'id="hash-example"' in page
    assert ">example<" in page
    assert ">wallet descriptor<" in page
    assert 'id="hash-descriptor-example"' in page
    assert "wpkh([42c649e1/84h/0h/0h]xpub6BsXXeh3fxRHtmfpnbXcAWjfnXz92n3BKYT7tf9Xcay6weGXt44g3iVaZHdivvwdzVnf9exeVLVBwVTzgxxScv53dQuXvT6FyrVJy9v4TaD/<0;1>/*)" in page
    assert "example,example,example,example,example,example,example,example,example,example,example,sample" in page
    assert "initial_network" in worker
    assert "BIGSIGNER_SDCARD_PATH" not in page
    assert "BIGSIGNER_SDCARD_PATH" not in worker
    assert "BIGSIGNER_INITIAL_WALLET_DESCRIPTOR" not in page
    assert "BIGSIGNER_INITIAL_WALLET_DESCRIPTOR" not in worker
    assert "bigsigner-sdcard" in page
    assert "mount_memory" in worker
    assert "cardJson" in worker
    assert "bundle.json" in worker
    assert "manifest.json" not in worker
    assert "src/bigsigner" not in worker
    assert 'new URL("../"' not in page
    assert "crypto.subtle.digest" not in worker
    assert 'from "./external-assets/pyodide/pyodide.mjs"' in worker
    assert "external-assets/pillow/" in worker
    assert "external-assets/embit/embit-0.8.0.tar.gz" in worker
    assert "external-assets/qrcode/qrcode-8.0-py3-none-any.whl" in worker
    assert "cdn.jsdelivr.net" not in worker
    assert "files.pythonhosted.org" not in worker
    assert "python -m bigsigner.bundle" in worker
    assert '"delay": delay,' in worker
    assert 'typeof delay === "number"' in page
    assert "holdInput" in page
    assert "web/external-assets/" in Path(".gitignore").read_text(encoding="utf-8")
    by_name = {name: digest for name, _url, digest in EXTERNAL_ASSETS}
    assert by_name["embit/embit-0.8.0.tar.gz"] == "8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770"
    assert by_name["qrcode/qrcode-8.0-py3-none-any.whl"] == "9fc05f03305ad27a709eb742cf3097fa19e6f6f93bb9e2f039c0979190f6f1b1"
    assert list(by_name) == [
        "pyodide/pyodide.mjs",
        "pyodide/pyodide.asm.mjs",
        "pyodide/pyodide.asm.wasm",
        "pyodide/python_stdlib.zip",
        "pyodide/pyodide-lock.json",
        "pillow/pillow-12.2.0-cp314-cp314-pyemscripten_2026_0_wasm32.whl",
        "embit/embit-0.8.0.tar.gz",
        "qrcode/qrcode-8.0-py3-none-any.whl",
    ]


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


def test_an_external_asset_is_kept_when_its_hash_matches(tmp_path):
    body = b"already here"
    digest = hashlib.sha256(body).hexdigest()
    (tmp_path / "kept.bin").write_bytes(body)
    calls = []
    install_assets(tmp_path, (("kept.bin", "https://example.invalid/kept.bin", digest),), fetch=lambda url: calls.append(url))
    assert calls == []
    assert (tmp_path / "kept.bin").read_bytes() == body


def test_a_matching_file_moves_into_its_folder(tmp_path):
    body = b"wheel"
    digest = hashlib.sha256(body).hexdigest()
    (tmp_path / "lib.whl").write_bytes(body)
    install_assets(tmp_path, (("qrcode/lib.whl", "https://example.invalid/lib.whl", digest),), fetch=lambda url: b"no")
    assert (tmp_path / "qrcode" / "lib.whl").read_bytes() == body
    assert not (tmp_path / "lib.whl").exists()


def test_an_external_asset_path_cannot_leave_the_folder(tmp_path):
    with pytest.raises(SystemExit, match="Bad external asset"):
        install_assets(tmp_path, (("../x", "https://example.invalid/x", "ab"),), fetch=lambda url: b"x")


def test_an_external_asset_with_the_wrong_hash_is_refused(tmp_path):
    with pytest.raises(SystemExit, match="SHA-256"):
        install_assets(
            tmp_path,
            (("fresh.bin", "https://example.invalid/fresh.bin", "0" * 64),),
            fetch=lambda url: b"not the pinned bytes",
        )
    assert not (tmp_path / "fresh.bin").exists()

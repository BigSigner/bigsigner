"""The static page runs the app in the browser."""

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from embit import bip39

from bigsigner.bundle import EXTERNAL_ASSETS, bundle_files, install_assets, source_files, source_root, write_bundle
from bigsigner.seedqr import standard_digits
from test_domain import ABANDON


@pytest.mark.parametrize("payload,binary,expected_seed", [
    (base64.b64decode("aaaaaaaaaaaaaaaa"), True, None),
    (bytes(range(256)), True, None),
    (b"  hello\r\nworld! \n", False, None),
    (b"01234567890123456789012345", False, None),
    (b"UR:BYTES/1-3/\xff\x00", True, None),
    (b"\x00" * 16, True, ABANDON),
    (b"\xc2\xa9" * 8, True, bip39.mnemonic_from_bytes(b"\xc2\xa9" * 8)),
    (ABANDON.encode("ascii"), False, ABANDON),
    (standard_digits(ABANDON).encode("ascii"), False, ABANDON),
], ids=["reported-binary", "all-bytes", "text", "numeric", "sequence-binary",
        "compact-seed", "compact-valid-utf8", "mnemonic", "numeric-seed"])
def test_camera_qr_pixels_reach_file_and_key_flows_without_byte_changes(payload, binary, expected_seed, tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    import qrcode

    from bigsigner import sdcard
    from bigsigner.ui.app import App
    from test_filesystem import _browser
    from test_sdcard import _tap

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise browser QR decoding")
    decoder = Path("web/external-assets/jsqr/jsQR.js").resolve()
    if not decoder.is_file():
        pytest.skip("Run python -m bigsigner.bundle to install the pinned QR decoder")
    digest = next(digest for name, _url, digest in EXTERNAL_ASSETS if name == "jsqr/jsQR.js")
    assert hashlib.sha256(decoder.read_bytes()).hexdigest() == digest
    image = qrcode.make(payload, box_size=5, border=4).convert("RGBA")
    pixels = tmp_path / "pixels.json"
    pixels.write_text(json.dumps({"width": image.width, "height": image.height,
                                  "rgba": base64.b64encode(image.tobytes()).decode("ascii")}))
    page = Path("web/index.html").read_text(encoding="utf-8")
    scanner = "async function watchQr(" + page.split("async function watchQr(", 1)[1].split("async function syncCamera(", 1)[0]
    script = r'''
const assert = require("node:assert/strict");
const jsQR = require(process.argv[2]);
const frame = JSON.parse(require("node:fs").readFileSync(process.argv[3], "utf8"));
let rgba = new Uint8ClampedArray(Buffer.from(frame.rgba, "base64"));
const video = {srcObject: {}, readyState: 4, videoWidth: frame.width, videoHeight: frame.height};
const context = {
  drawImage: (source, x, y, width, height) => {
    assert.equal(source, video);
    assert.equal(width, frame.width);
    assert.equal(height, frame.height);
  },
  getImageData: () => ({data: rgba, width: frame.width, height: frame.height}),
};
const document = {createElement: () => ({getContext: () => context})};
const status = {textContent: ""};
const showStatus = text => {status.textContent = text;};
let qrBusy = false, qrWarned = false, qrCanvas = null, lastQr = "", screenName = "scan";
const sent = [];
const sendTick = body => sent.push(body);
const enqueue = fn => fn();
''' + scanner + r'''
(async () => {
  await watchQr();
  assert.equal(sent.length, 1, status.textContent || "The QR code was not captured");
  await watchQr();
  assert.equal(sent.length, 1, "The same visible code should only be sent once");
  const saved = rgba;
  rgba = new Uint8ClampedArray(rgba.length).fill(255);
  await watchQr();
  assert.equal(lastQr, "");
  rgba = saved;
  await watchQr();
  assert.equal(sent.length, 2);
  assert.deepEqual(sent[0], sent[1]);
  assert.equal(status.textContent, "");
  console.log(JSON.stringify(sent[0]));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([node, "-", str(decoder), str(pixels)], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    message = json.loads(result.stdout)
    assert message["qr_encoding"] == "hex"
    assert bytes.fromhex(message["qr"]) == payload
    worker = Path("web/worker.js").read_text(encoding="utf-8")
    driver = worker.split("const DRIVER = `", 1)[1].rsplit("`;", 1)[0]
    monkeypatch.setattr(sys, "path", list(sys.path))
    namespace = {}
    exec(compile(driver, "web/worker.js:DRIVER", "exec"), namespace)
    app = _browser()
    _tap(app, "plus")
    _tap(app, "New File")
    _tap(app, "Scan QR Code")
    namespace["_tap"](app, message)
    if payload.startswith(b"UR:"):
        assert app.screen == "fs-qr-warning"
        _tap(app, "OK")
    if app.screen == "fs-base64":
        _tap(app, "Keep Original Data")
    assert app.screen == ("fs-binary" if binary else "fs-edit")
    _tap(app, "Save")
    name = "file.bin" if binary else "file.txt"
    assert app.filename == name
    _tap(app, "Save")
    assert sdcard.read_bytes(name) == payload
    # All scan flows receive the same raw bytes, including numeric QR segments.
    received = []
    namespace["_tap"](SimpleNamespace(scan_kind="key", accept_qr=received.append), message)
    assert received == [payload]
    key_scan = App()
    key_scan.screen = "scan"
    namespace["_tap"](key_scan, message)
    if expected_seed is not None:
        assert key_scan.screen == "seed-review"
        assert key_scan.seed_words == expected_seed.split()
        assert not key_scan.session.fingerprints
    else:
        assert key_scan.screen == "load-error"
        assert key_scan.load_error and "empty" not in key_scan.load_error
        if payload == base64.b64decode("aaaaaaaaaaaaaaaa"):
            assert key_scan.load_error == "That QR code is not a seed, key expression or wallet descriptor."


def test_browser_detector_supplies_text_when_jsqr_misses_the_code():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise browser QR decoding")
    page = Path("web/index.html").read_text(encoding="utf-8")
    scanner = "async function watchQr(" + page.split("async function watchQr(", 1)[1].split("async function syncCamera(", 1)[0]
    script = r'''
const assert = require("node:assert/strict");
let mode = "miss";
const jsQR = () => mode === "bytes" ? {binaryData: [97, 97, 97, 97, 10]} : null;
class BarcodeDetector {
  detect() { return Promise.resolve([{rawValue: this.raw}]); }
}
BarcodeDetector.prototype.raw = "aaaa\n";
const video = {srcObject: {}, readyState: 4, videoWidth: 32, videoHeight: 32};
const context = {
  drawImage() {},
  getImageData: () => ({data: new Uint8ClampedArray(32 * 32 * 4).fill(255), width: 32, height: 32}),
};
const document = {createElement: () => ({getContext: () => context})};
const status = {textContent: ""};
const showStatus = text => {status.textContent = text;};
let qrBusy = false, qrWarned = false, qrCanvas = null, qrDetector = null, lastQr = "", screenName = "scan";
const sent = [];
const sendTick = body => sent.push(body);
const enqueue = fn => fn();
''' + scanner + r'''
(async () => {
  await watchQr();
  assert.deepEqual(sent, [{kind: "tap", qr: "aaaa\n"}]);
  await watchQr();
  assert.equal(sent.length, 1, "The same visible text should only be sent once");
  lastQr = "";
  mode = "bytes";
  await watchQr();
  assert.equal(sent[1].qr_encoding, "hex");
  assert.equal(sent[1].qr, "616161610a");
  lastQr = "";
  mode = "miss";
  BarcodeDetector.prototype.raw = "";
  await watchQr();
  assert.equal(sent.length, 2, "An empty text result must not replace binary content");
  assert.equal(status.textContent, "");
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([node, "-"], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_an_old_worker_cannot_silently_turn_a_binary_qr_into_empty_text():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise worker compatibility")
    page = Path("web/index.html").read_text(encoding="utf-8")
    ready = "function workerReady(" + page.split("function workerReady(", 1)[1].split('if (location.protocol === "file:")', 1)[0]
    script = '''
const assert = require("node:assert/strict");
let terminated = false, loaded = false, status = "";
const worker = {terminate: () => {terminated = true;}};
const loadFrame = () => {loaded = true;};
const showStatus = text => {status = text;};
''' + ready + '''
workerReady({type: "ready"}); // Old workers only returned the event type.
assert.equal(terminated, true);
assert.equal(loaded, false);
assert.match(status, /out of date/);
workerReady({type: "ready", qr_bytes: true}); // Reject the earlier file-only transport too.
assert.equal(loaded, false);
terminated = false;
workerReady({type: "ready", qr_encoding: "hex"});
assert.equal(terminated, false);
assert.equal(loaded, true);
'''
    result = subprocess.run([node], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_device_file_deletes_and_renames_merge_with_browser_card_edits():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise browser card merging")
    page = Path("web/index.html").read_text(encoding="utf-8")
    merge = "function applyRemote(" + page.split("function applyRemote(", 1)[1].split("async function sendTick(", 1)[0]
    script = '''
const assert = require("node:assert/strict");
const normalizeCard = value => JSON.parse(JSON.stringify(value));
const saveCard = () => {};
const renderSd = () => {};
let dirty = true;
let card;
''' + merge + '''
const sent = {dirs: [], files: {"old.txt": "unchanged", "binary.bin": {base64: "AP8="}}};
card = normalizeCard(sent);
card.files["browser.txt"] = "a concurrent browser edit";
applyRemote(sent, {dirs: [], files: {"renamed.txt": "unchanged"}});
assert.equal(card.files["old.txt"], undefined);
assert.equal(card.files["binary.bin"], undefined);
assert.equal(card.files["renamed.txt"], "unchanged");
assert.equal(card.files["browser.txt"], "a concurrent browser edit");
card = {dirs: [], files: {"old.txt": "modified while the device was busy"}};
applyRemote(sent, {dirs: [], files: {}});
assert.equal(card.files["old.txt"], "modified while the device was busy");
'''
    result = subprocess.run([node], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_browser_drops_taps_queued_against_the_previous_frame():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the browser input queue")
    page = Path("web/index.html").read_text(encoding="utf-8")
    driver = "let worker = null;" + page.split("let worker = null;", 1)[1].split('if (location.protocol === "file:")', 1)[0]
    script = """
const assert = require("node:assert/strict");
let now = 0;
const performance = {now: () => now};
let started = true, dirty = false, holdInput = false;
let tapBlockedUntil = 0, tapFrame = 0, refreshTimer = 0;
let screenName = "keys";
const handlers = new Map();
const panel = {style: {}, addEventListener: (name, fn) => handlers.set(name, fn)};
const point = event => ({x: event.x, y: event.y});
const card = {};
const initial = {};
""" + driver + """
(async () => {
  const sent = [];
  let release;
  rpc = async body => {
    sent.push(body);
    if (sent.length === 1) await new Promise(resolve => { release = resolve; });
    return {tap_guard: body.phase === "up", delay: null, png: ""};
  };
  paintPanel = async () => { now += 1000; }; // Slow image decoding/presentation.
  const event = {x: 240, y: 400, preventDefault() {}};
  post({kind: "tap", phase: "up"});
  await Promise.resolve(); // The first operation is running.
  handlers.get("pointerdown")(event);
  handlers.get("pointerup")(event);
  assert.equal(press, null);
  release();
  await chain;
  assert.equal(sent.length, 1); // The two queued phases cannot reach Python.
  assert.equal(tapBlockedUntil, 1250); // Starts after presentation.
  now = 1249;
  handlers.get("pointerdown")(event);
  assert.equal(press, null);
  now = 1251;
  handlers.get("pointerup")(event); // Lift after a rejected down is harmless.
  await chain;
  assert.equal(sent.length, 1);
  handlers.get("pointerdown")(event);
  await chain;
  handlers.get("pointerup")(event);
  await chain;
  assert.deepEqual(sent.map(body => body.phase), ["up", "down", "up"]);
  assert.equal(tapInputBlocked(), true);
  now = tapBlockedUntil + 1;
  const previousFrame = tapFrame;
  const previousTime = now;
  await showFrame({tap_guard: false, delay: 0, png: null, interactive: true});
  clearTimeout(refreshTimer);
  assert.equal(tapInputBlocked(), false); // Stop and Back remain available.
  assert.equal(tapFrame, previousFrame);
  assert.equal(now, previousTime); // An unchanged search step skips PNG decoding.
  handlers.get("pointerdown")(event);
  await chain;
  assert.equal(sent.at(-1).phase, "down");
  await showFrame({tap_guard: false, delay: 0, png: null, interactive: false});
  clearTimeout(refreshTimer);
  assert.equal(tapInputBlocked(), true); // PSBT loading retains its input block.
})().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


def test_emulator_frame_reports_the_viewfinder(monkeypatch):
    import sys

    from bigsigner.ui.app import App

    worker = Path("web/worker.js").read_text(encoding="utf-8")
    driver = worker.split("const DRIVER = `", 1)[1].rsplit("`;", 1)[0]
    monkeypatch.setattr(sys, "path", list(sys.path))
    namespace = {}
    exec(compile(driver, "web/worker.js:DRIVER", "exec"), namespace)
    app = App()
    namespace["app"] = app
    tick = namespace["tick"]
    app.screen = "keys"
    assert json.loads(tick('{"kind":"frame"}'))["preview"] is None
    app.screen = "scan"
    scan = json.loads(tick('{"kind":"frame"}'))
    assert scan["preview"] == list(app.camera_preview_box())
    app.screen = "camera"
    app.camera_purpose = "gpg"
    app.gpg.camera_for = "sign"
    signing = json.loads(tick('{"kind":"frame"}'))
    assert signing["preview"] == list(app.camera_preview_box())
    assert signing["preview"] != scan["preview"]


def test_worker_polls_search_once_per_request_and_accepts_stop(monkeypatch):
    import sys

    from test_address_search import _app

    app = _app()
    app._act("psbt-search-start")
    app.render()
    worker = Path("web/worker.js").read_text(encoding="utf-8")
    driver = worker.split("const DRIVER = `", 1)[1].rsplit("`;", 1)[0]
    monkeypatch.setattr(sys, "path", list(sys.path))
    namespace = {}
    exec(compile(driver, "web/worker.js:DRIVER", "exec"), namespace)
    namespace["app"] = app
    tick = namespace["tick"]
    job = app.psbt_search
    frame = json.loads(tick('{"kind":"frame"}'))
    assert len(job.creators) == 1
    assert frame["png"] is None and frame["interactive"] and frame["delay"] == 0
    frame = json.loads(tick('{"kind":"frame"}'))
    assert len(job.creators) == 2
    assert frame["png"] is None and not frame["tap_guard"]
    frame = json.loads(tick('{"kind":"tap","x":240,"y":750}'))
    assert job.done and not app.psbt_search_active()
    assert frame["png"] is not None and frame["delay"] is None
    assert not frame["interactive"]


def test_textual_base64_files_open_in_the_editor():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to exercise the SD card sidebar")
    page = Path("web/index.html").read_text(encoding="utf-8")
    helpers = "function isBinaryFile(" + page.split("function isBinaryFile(", 1)[1].split("function bytesToBase64(", 1)[0]
    opener = page.split("function openFile(", 1)[1].split("function saveEditorSoon(", 1)[0]
    script = r'''
const assert = require("node:assert/strict");
''' + helpers + "function openFile(" + opener + r'''
const manifest = [
  "f16b96ae65f74e75279c558d35fb4e325df51195cc3f6e19fa00bc2bc3a2af8c *binary2950.bin",
  "e3630883bf967f2689fbaf4ade9dc4d2a23e32d718c34b69815f13513fd0c628 *binary50k.bin",
  "",
].join("\n");
const encoded = Buffer.from(manifest, "ascii").toString("base64");
assert.equal(storedText({base64: encoded}), manifest);
assert.equal(storedText({base64: Buffer.from([0, 255]).toString("base64")}), null);
let notices = [];
let downloads = [];
let noted = 0;
const setSdError = () => {};
const setSdNotice = text => { notices.push(text); };
const downloadFile = path => { downloads.push(path); };
const renderSd = () => {};
const noteCard = () => { noted += 1; };
let editingPath = "";
const editor = {hidden: true};
const editorName = {textContent: ""};
const editorText = {value: "", focus() {}};
const card = {files: {
  SHA256SUMS: {base64: encoded},
  "wallet.psbt": {base64: Buffer.from([0xff]).toString("base64")},
}};
openFile("SHA256SUMS");
assert.equal(card.files.SHA256SUMS, manifest);
assert.equal(noted, 1);
assert.deepEqual(downloads, []);
assert.equal(editor.hidden, false);
assert.equal(editorText.value, manifest);
openFile("wallet.psbt");
assert.deepEqual(downloads, ["wallet.psbt"]);
assert.deepEqual(notices, ["Downloading a binary file."]);
'''
    result = subprocess.run([node], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr


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
    assert 'if (next === path) {\n    setSdError("");\n    renderSd();' in page
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
    assert ">Save and Reload<" in page
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
    assert 'import("./openpgp-bridge.js")' in worker
    assert "tick.callPromising(" in worker
    assert "external-assets/pillow/" in worker
    assert "external-assets/embit/embit-0.8.0.tar.gz" in worker
    assert "external-assets/qrcode/qrcode-8.0-py3-none-any.whl" in worker
    assert "cdn.jsdelivr.net" not in worker
    assert "files.pythonhosted.org" not in worker
    assert "python -m bigsigner.bundle" in worker
    assert '"delay": delay,' in worker
    assert 'typeof delay === "number"' in page
    assert "holdInput" in page
    assert "app.defer_psbt_progress = True" in worker
    assert "flush_display" not in worker
    assert "showPaint" not in page
    assert 'msg.type === "paint"' not in page
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
        "jsqr/jsQR.js",
        "openpgp/openpgp.min.mjs",
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

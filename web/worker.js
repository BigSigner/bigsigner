/* BigSigner in the page. Pyodide runs the same App the panel runs. */

import { loadPyodide } from "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.mjs";

const PYODIDE = "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/";

let tick = null;
const jobs = [];
let running = false;

const EMBIT_URL = "https://files.pythonhosted.org/packages/83/88/b054b00ade6d2a41749e15976cdcec4b7ec4656ac1cb917ce3de395528d1/embit-0.8.0.tar.gz";
const EMBIT_SHA256 = "8bf4b10073c67400370ce523fb16f035fe759f6fdd987c579bdcc268d75ed770";
const QRCODE_URL = "https://files.pythonhosted.org/packages/74/ab/df8d889fd01139db68ae9e5cb5c8f0ea016823559a6ecb427582d52b07dc/qrcode-8.0-py3-none-any.whl";
const QRCODE_SHA256 = "9fc05f03305ad27a709eb742cf3097fa19e6f6f93bb9e2f039c0979190f6f1b1";

self.onmessage = (event) => {
  const msg = event.data;
  if (msg.type === "init") {
    boot().catch((err) => {
      self.postMessage({type: "fatal", message: String((err && err.message) || err)});
    });
    return;
  }
  if (msg.type === "tick") {
    jobs.push(msg);
    drain();
  }
};

function progress(text) {
  self.postMessage({type: "progress", text});
}

async function fetchChecked(url, expected) {
  const response = await fetch(url);
  if (!response.ok) throw new Error("Could not download " + url);
  const bytes = new Uint8Array(await response.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const actual = [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  if (actual !== expected) {
    throw new Error("SHA-256 for " + url + " was " + actual + ", expected " + expected + ".");
  }
  return bytes;
}

async function boot() {
  progress("Loading Python…");
  const pyodide = await loadPyodide({
    indexURL: PYODIDE,
    stderr: (text) => self.postMessage({type: "stderr", text}),
  });
  progress("Loading Pillow…");
  await pyodide.loadPackage("pillow");
  progress("Loading the Bitcoin library…");
  // embit 0.8.0 publishes a source archive, not a wheel. The archive is pure
  // Python plus desktop builds of libsecp256k1, which this page does not load.
  pyodide.FS.writeFile("/embit-0.8.0.tar.gz", await fetchChecked(EMBIT_URL, EMBIT_SHA256));
  pyodide.runPython(`
import os, sys, tarfile
os.makedirs("/tmp/embit-src", exist_ok=True)
tarfile.open("/embit-0.8.0.tar.gz").extractall("/tmp/embit-src", filter="data")
sys.path.insert(0, "/tmp/embit-src/embit-0.8.0/src")
`);
  progress("Loading QR codes…");
  pyodide.FS.writeFile("/qrcode-8.0-py3-none-any.whl", await fetchChecked(QRCODE_URL, QRCODE_SHA256));
  pyodide.runPython(`
import sys, zipfile
zipfile.ZipFile("/qrcode-8.0-py3-none-any.whl").extractall("/tmp/qrcode")
sys.path.insert(0, "/tmp/qrcode")
`);
  progress("Loading BigSigner…");
  const response = await fetch(new URL("bundle.json", self.location.href), {cache: "no-cache"});
  if (!response.ok) throw new Error("The emulator bundle is missing. Run python -m bigsigner.bundle.");
  const bundle = await response.json();
  const files = bundle.files || {};
  for (const [path, entry] of Object.entries(files)) {
    if (!path || path.startsWith("/") || path.includes("\\") || path.split("/").includes("..")) {
      throw new Error("The emulator bundle has a bad path.");
    }
    const dest = "/repo/src/" + path;
    mkdirP(pyodide.FS, dest.slice(0, dest.lastIndexOf("/")));
    if (typeof entry.text === "string") pyodide.FS.writeFile(dest, entry.text);
    else pyodide.FS.writeFile(dest, bytesFromBase64(entry.base64 || ""));
  }
  pyodide.runPython(DRIVER);
  tick = pyodide.globals.get("tick");
  progress("Starting…");
  self.postMessage({type: "ready"});
}

function mkdirP(fs, dir) {
  const parts = dir.split("/").filter(Boolean);
  let current = "";
  for (const part of parts) {
    current += "/" + part;
    try {
      fs.mkdir(current);
    } catch (err) {
      /* The folder is already there. */
    }
  }
}

function bytesFromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function drain() {
  if (running) return;
  const msg = jobs.shift();
  if (!msg) return;
  running = true;
  let result = null;
  let error = null;
  try {
    let raw = tick(JSON.stringify(msg.body));
    if (raw && typeof raw !== "string") raw = String(raw);
    result = JSON.parse(raw);
  } catch (err) {
    error = String((err && err.message) || err);
  }
  if (error) self.postMessage({type: "tick-error", id: msg.id, message: error});
  else self.postMessage({type: "tick", id: msg.id, result});
  running = false;
  drain();
}

const DRIVER = `
import base64, io, json, os, sys

sys.path.insert(0, "/repo/src")

from bigsigner.sdcard import consume_memory_change, mount_memory

app = None

def _install_pbkdf2():
    import hashlib, hmac
    if hasattr(hashlib, "pbkdf2_hmac"):
        return
    def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
        if isinstance(password, str):
            password = password.encode("utf-8")
        if isinstance(salt, str):
            salt = salt.encode("utf-8")
        digest_size = hashlib.new(hash_name).digest_size
        if dklen is None:
            dklen = digest_size
        blocks = (dklen + digest_size - 1) // digest_size
        out = b""
        for index in range(1, blocks + 1):
            block = hmac.new(password, salt + index.to_bytes(4, "big"), hash_name).digest()
            mixed = block
            for _ in range(1, iterations):
                block = hmac.new(password, block, hash_name).digest()
                mixed = bytes(left ^ right for left, right in zip(mixed, block))
            out += mixed
        return out[:dklen]
    hashlib.pbkdf2_hmac = pbkdf2_hmac

def tick(raw):
    global app
    payload = json.loads(raw)
    card_json = payload.get("cardJson")
    if isinstance(card_json, str):
        mount_memory(json.loads(card_json))
    kind = payload.get("kind")
    if kind == "start" and app is None:
        os.environ["BIGSIGNER_INITIAL_SEED"] = str(payload.get("seed") or "").strip()
        os.environ["BIGSIGNER_INITIAL_WALLET_DESCRIPTOR"] = str(payload.get("descriptor") or "").strip()
        _install_pbkdf2()
        # No libsecp256k1 in the browser. A failed import selects embit's pure Python curve.
        sys.modules["embit.util.ctypes_secp256k1"] = None
        from bigsigner.ui.app import App
        app = App()
    elif kind == "tap":
        if app is None:
            raise RuntimeError("The emulator has not started.")
        _tap(app, payload)
    elif kind not in ("start", "frame"):
        raise RuntimeError("Unknown emulator request.")
    if app is None:
        raise RuntimeError("The emulator has not started.")
    buffer = io.BytesIO()
    app.render().save(buffer, format="PNG")
    delay = app.notice_delay()
    changed = consume_memory_change()
    return json.dumps({
        "screen": app.screen,
        "delay": delay or 0,
        "png": base64.b64encode(buffer.getvalue()).decode("ascii"),
        "card": changed,
    })

def _tap(app, payload):
    if payload.get("qr_unsupported"):
        app.note_qr_unsupported()
        return
    if isinstance(payload.get("qr"), str):
        app.accept_qr(payload["qr"])
        return
    x = int(payload.get("x") or 0)
    y = int(payload.get("y") or 0)
    phase = payload.get("phase")
    camera = _camera(payload.get("camera"))
    if phase == "down":
        app.pointer_down(x, y)
    elif phase == "move":
        app.pointer_move(x, y)
    elif phase == "up":
        app.pointer_up(x, y, camera=camera)
    else:
        app.tap(x, y, camera=camera)

def _camera(raw):
    if not isinstance(raw, dict):
        return None
    frames = []
    for item in (raw.get("frames") or [])[:8]:
        decoded = _decode_frame(item)
        if decoded:
            frames.append(decoded)
    return {"frames": frames, "final": _decode_frame(raw.get("final")) or b""}

def _decode_frame(item):
    if not isinstance(item, str) or len(item) > 300_000:
        return b""
    try:
        return base64.b64decode(item, validate=True)
    except Exception:
        return b""
`;

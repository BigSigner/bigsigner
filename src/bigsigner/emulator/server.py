"""Browser window that shows the same picture the panel shows."""

import base64
import io
import json
import os
import sys
import termios
import threading
import tty
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ..ui.app import App

INDEX = """<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BigSigner</title>
<style>
  body { margin: 0; background: #111; display: grid; place-items: center; min-height: 100vh; }
  #stage { display: grid; justify-items: center; gap: 12px; padding: 16px; }
  video { width: 51.84mm; height: 180px; object-fit: cover; background: #000; display: none; }
  img { width: 51.84mm; height: auto; aspect-ratio: 480 / 800; touch-action: none; background: white; }
  #size { display: flex; gap: 8px; align-items: center; }
  #size button { background: transparent; color: #ddd; border: 1px solid #555; border-radius: 8px; font: 14px/1 sans-serif; padding: 8px 12px; cursor: pointer; }
  #size-note { margin: 0; max-width: 52mm; color: #9a9a9a; font: 13px/1.4 sans-serif; text-align: center; }
</style>
<div id="stage">
  <video id="camera" playsinline autoplay muted></video>
  <img id="panel" alt="BigSigner">
  <div id="size">
    <button type="button" id="smaller" title="Smaller">−</button>
    <button type="button" id="size-label" title="Reset to the Waveshare picture size"></button>
    <button type="button" id="larger" title="Larger">+</button>
  </div>
  <p id="size-note">The 4 inch Waveshare picture is 51.8 mm wide. Match a ruler, then leave it.</p>
</div>
<script>
const panel = document.getElementById("panel");
const video = document.getElementById("camera");
const PANEL_WIDTH_MM = 51.84;
const SIZE_KEY = "bigsigner-panel-scale";
function panelScale() {
  const saved = Number(localStorage.getItem(SIZE_KEY));
  return Number.isFinite(saved) && saved >= 0.6 && saved <= 1.8 ? saved : 1;
}
function applyPanelSize(scale) {
  const width = (PANEL_WIDTH_MM * scale) + "mm";
  panel.style.width = width;
  video.style.width = width;
  const label = document.getElementById("size-label");
  label.textContent = scale === 1 ? "51.8 × 86.4 mm" : Math.round(scale * 100) + "%";
}
function setPanelScale(scale) {
  const next = Math.round(Math.min(1.8, Math.max(0.6, scale)) * 100) / 100;
  localStorage.setItem(SIZE_KEY, String(next));
  applyPanelSize(next);
}
applyPanelSize(panelScale());
document.getElementById("smaller").addEventListener("click", () => setPanelScale(panelScale() - 0.02));
document.getElementById("larger").addEventListener("click", () => setPanelScale(panelScale() + 0.02));
document.getElementById("size-label").addEventListener("click", () => setPanelScale(1));
let refreshTimer = 0;
let frameUrl = "";
let screenName = "";
let cameraFrames = [];
let sampler = 0;
let lastQr = "";
let qrBusy = false;
let qrWarned = false;
let qrDetector = null;
function point(event) {
  const rect = panel.getBoundingClientRect();
  const source = event.touches ? event.touches[0] : event;
  return {
    x: Math.round((source.clientX - rect.left) * 480 / rect.width),
    y: Math.round((source.clientY - rect.top) * 800 / rect.height)
  };
}
function grab() {
  if (!video.videoWidth) return "";
  const canvas = document.createElement("canvas");
  canvas.width = 160;
  canvas.height = 120;
  canvas.getContext("2d").drawImage(video, 0, 0, 160, 120);
  return canvas.toDataURL("image/jpeg", 0.5).split(",")[1];
}
function sampleCamera() {
  const frame = grab();
  if (!frame) return;
  cameraFrames.push(frame);
  if (cameraFrames.length > 8) cameraFrames.shift();
}
function usesCamera(name) {
  return name === "camera" || name === "scan";
}
function stopCamera() {
  clearInterval(sampler);
  sampler = 0;
  cameraFrames = [];
  lastQr = "";
  const stream = video.srcObject;
  if (stream) stream.getTracks().forEach((track) => track.stop());
  video.srcObject = null;
  video.style.display = "none";
}
async function watchQr() {
  if (qrBusy || screenName !== "scan" || !video.srcObject) return;
  qrBusy = true;
  try {
    if (!("BarcodeDetector" in window)) {
      if (!qrWarned) {
        qrWarned = true;
        await fetch("/tap", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({qr_unsupported: true})});
        await loadFrame();
      }
      return;
    }
    if (!video.videoWidth) return;
    if (!qrDetector) qrDetector = new BarcodeDetector({formats: ["qr_code"]});
    const codes = await qrDetector.detect(video);
    const text = codes.length ? (codes[0].rawValue || "") : "";
    if (!text) {
      lastQr = "";
      return;
    }
    if (text === lastQr) return;
    lastQr = text;
    await fetch("/tap", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({qr: text})});
    await loadFrame();
  } catch (err) {
  } finally {
    qrBusy = false;
  }
}
async function syncCamera(name) {
  if (!usesCamera(name)) {
    if (usesCamera(screenName)) stopCamera();
    screenName = name;
    return;
  }
  screenName = name;
  video.style.display = "block";
  if (!video.srcObject) {
    let stream = null;
    for (const constraints of [{video: {facingMode: "environment"}, audio: false}, {video: true, audio: false}]) {
      try {
        stream = await navigator.mediaDevices.getUserMedia(constraints);
        break;
      } catch (err) {}
    }
    if (!stream) {
      video.style.display = "none";
      return;
    }
    video.srcObject = stream;
    await video.play();
  }
  if (!sampler) sampler = setInterval(() => {
    if (screenName === "camera") sampleCamera();
    if (screenName === "scan") watchQr();
  }, 400);
}
async function loadFrame() {
  clearTimeout(refreshTimer);
  const response = await fetch("/frame.png?" + Date.now(), {cache: "no-store"});
  const blob = await response.blob();
  const next = URL.createObjectURL(blob);
  panel.src = next;
  if (frameUrl) URL.revokeObjectURL(frameUrl);
  frameUrl = next;
  syncCamera(response.headers.get("X-Screen") || "");
  const refreshMs = Number(response.headers.get("X-Notice-Ms") || 0);
  if (refreshMs > 0) refreshTimer = setTimeout(loadFrame, refreshMs + 80);
}
let press = null;
let chain = Promise.resolve();
function post(body) {
  chain = chain.then(() => fetch("/tap", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body)
  })).then(() => loadFrame()).catch(() => {});
}
panel.addEventListener("pointerdown", (event) => {
  event.preventDefault();
  if (panel.setPointerCapture) panel.setPointerCapture(event.pointerId);
  const p = point(event);
  press = {x: p.x, y: p.y, moved: false};
  post({phase: "down", x: p.x, y: p.y});
});
panel.addEventListener("pointermove", (event) => {
  if (!press) return;
  const p = point(event);
  if (Math.abs(p.x - press.x) < 8 && Math.abs(p.y - press.y) < 8) return;
  press = {x: p.x, y: p.y, moved: true};
  post({phase: "move", x: p.x, y: p.y});
});
panel.addEventListener("pointerup", (event) => {
  if (!press) return;
  const moved = press.moved;
  press = null;
  const p = point(event);
  const body = {phase: "up", x: p.x, y: p.y};
  if (!moved && screenName === "camera" && video.srcObject) {
    const finalFrame = grab();
    if (finalFrame) body.camera = {frames: cameraFrames.slice(), final: finalFrame};
  }
  post(body);
});
panel.addEventListener("pointercancel", () => { press = null; });
loadFrame();
</script>
"""


class EmulatorServer(ThreadingHTTPServer):
    allow_reuse_address = True


def serve(port: int = 8765):
    """Serve the emulator. In a terminal, the r key starts a fresh process."""
    if not sys.stdin.isatty():
        _serve_once(port)
        return
    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    tty.setcbreak(fd)
    print("Press r to restart with empty memory and reload the code. Ctrl+C to stop.", flush=True)
    try:
        while True:
            server = _serve_once(port, background=True)
            try:
                restart = _wait_for_restart()
            except KeyboardInterrupt:
                _stop_server(server)
                print(flush=True)
                return
            _stop_server(server)
            if not restart:
                return
            # Restore the terminal before the new process saves its own settings.
            termios.tcsetattr(fd, termios.TCSADRAIN, previous)
            print("Restarting.", flush=True)
            _reexec(port)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)


def _reexec(port: int):
    """Replace this process so the next session imports the code from disk."""
    os.environ["BIGSIGNER_EMULATOR"] = "1"
    os.environ["BIGSIGNER_PORT"] = str(port)
    os.execv(sys.executable, [sys.executable, "-m", "bigsigner"])


def _wait_for_restart():
    while True:
        char = sys.stdin.read(1)
        if char == "" or char == "\x04":
            return False
        if char == "r":
            return True


def _serve_once(port: int, background: bool = False):
    app = App()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/frame.png"):
                buffer = io.BytesIO()
                app.render().save(buffer, format="PNG")
                body = buffer.getvalue()
                delay = app.notice_delay()
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Screen", app.screen)
                if delay:
                    self.send_header("X-Notice-Ms", str(int(delay * 1000)))
                self.end_headers()
                self.wfile.write(body)
                return
            encoded = INDEX.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            if payload.get("qr_unsupported"):
                app.note_qr_unsupported()
            elif isinstance(payload.get("qr"), str):
                app.accept_qr(payload["qr"])
            else:
                x = int(payload.get("x", 0))
                y = int(payload.get("y", 0))
                phase = payload.get("phase")
                if phase == "down":
                    app.pointer_down(x, y)
                elif phase == "move":
                    app.pointer_move(x, y)
                elif phase == "up":
                    app.pointer_up(x, y, camera=_camera_payload(payload.get("camera")))
                else:
                    app.tap(x, y, camera=_camera_payload(payload.get("camera")))
            self.send_response(204)
            self.end_headers()

        def log_message(self, fmt, *args):
            return

    server = EmulatorServer(("127.0.0.1", port), Handler)
    print(f"BigSigner emulator at http://127.0.0.1:{port}", flush=True)
    if not background:
        server.serve_forever()
        return server
    thread = threading.Thread(target=server.serve_forever, name="bigsigner-emulator", daemon=True)
    thread.start()
    server.emulator_thread = thread
    return server


def _camera_payload(raw):
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


def _stop_server(server):
    server.shutdown()
    server.server_close()
    thread = getattr(server, "emulator_thread", None)
    if thread is not None:
        thread.join(timeout=2)

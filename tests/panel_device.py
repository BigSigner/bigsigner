#!/usr/bin/env python3
"""Drive the connected panel and check where each control landed.

    .venv/bin/python tests/panel_device.py

Syncs this tree to seedsigner.local, starts the panel with a tap pipe and a
layout dump, then taps through the Abandon test seed. Screenshots land in
artifacts/panel/device/. The descriptor QR is scrolled on purpose: those frame
times are the check that a finger can move a screen which already holds a QR.

pytest skips this file unless BIGSIGNER_PANEL=1, because it restarts the device.
"""

import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from PIL import Image

from bigsigner.ui.canvas import BLUE, HEADER, HEIGHT, NAVY, WIDTH

# The panel logs a frame of 500ms or more as slow. Scrolling an already-built
# QR is a crop of that picture, so it stays under the same line.
SCROLL_FRAME_MS = 500
ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
ROOT = Path(__file__).resolve().parents[1]
OS_ROOT = ROOT.parent / "bigsigner-os"
SSH = OS_ROOT / "docs" / "scripts" / "ssh-seedsigner.sh"
RSYNC = OS_ROOT / "docs" / "scripts" / "rsync-to-seedsigner.sh"
FOLDER = ROOT / "artifacts" / "panel" / "device"


def test_panel_on_the_device():
    import pytest

    if os.environ.get("BIGSIGNER_PANEL") != "1":
        pytest.skip("Set BIGSIGNER_PANEL=1 to drive seedsigner.local")
    run()


class Panel:
    def __init__(self):
        self.history = []
        self.latest = None
        self.started = False
        self.step = 0
        self.scroll_frames = []
        self.prepare_ms = None
        self.address_ms = None
        self.folder = FOLDER

    def ssh(self, command: str, timeout: int = 60, binary: bool = False):
        if not SSH.is_file():
            raise RuntimeError(f"Missing {SSH}")
        proc = subprocess.run(
            [str(SSH), command],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")
            out = "" if binary else proc.stdout.decode("utf-8", "replace")
            raise RuntimeError(f"ssh failed ({proc.returncode}): {err}\n{out}")
        if binary:
            return proc.stdout
        return proc.stdout.decode("utf-8", "replace")

    def install(self):
        if not RSYNC.is_file():
            raise RuntimeError(f"Missing {RSYNC}")
        print("Syncing this tree to seedsigner.local", flush=True)
        self.ssh("true", timeout=30)
        known = Path.home() / ".ssh" / "seedsigner_known_hosts"
        env = os.environ.copy()
        env["RSYNC_RSH"] = (
            "ssh -o ControlPath=/tmp/seedsigner-ssh.sock -o ControlMaster=no "
            f"-o UserKnownHostsFile={known} -o LogLevel=ERROR"
        )
        proc = subprocess.run([str(RSYNC), str(ROOT)], env=env, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f"rsync failed ({proc.returncode})")

    def start(self):
        """Stop the normal app and start this tree with the tap pipe."""
        self.started = True
        self.folder.mkdir(parents=True, exist_ok=True)
        for old in self.folder.glob("*.png"):
            old.unlink()
        print("Starting the panel", flush=True)
        self.ssh(
            f"""
set -eu
seedsigner stop || true
if [ -f /tmp/bigsigner-panel.pid ]; then
    kill "$(cat /tmp/bigsigner-panel.pid)" 2>/dev/null || true
    rm -f /tmp/bigsigner-panel.pid
fi
sleep 1
rm -f /tmp/bigsigner-tap /tmp/bigsigner-ui.jsonl
mkfifo /tmp/bigsigner-tap
cd /mnt/data/seedsigner/src
export BIGSIGNER_TAP=/tmp/bigsigner-tap
export BIGSIGNER_UI=/tmp/bigsigner-ui.jsonl
export BIGSIGNER_INITIAL_SEED='{ABANDON}'
nohup python3 main.py >/tmp/bigsigner-panel.log 2>&1 &
echo $! >/tmp/bigsigner-panel.pid
""",
            timeout=40,
        )
        deadline = time.time() + 90
        while time.time() < deadline:
            self._absorb(self.ssh("cat /tmp/bigsigner-ui.jsonl 2>/dev/null || true", timeout=20))
            if self.history:
                self.latest = self.history[-1]
                print(f"First frame {self.latest['frame']} {self.latest['screen']} {self.latest['ms']} ms", flush=True)
                return
            time.sleep(0.4)
        raise RuntimeError("The panel did not paint.\n" + self.log())

    def restore(self):
        """Stop the probed process and bring the normal app back."""
        print("Restoring the normal panel", flush=True)
        self.ssh(
            """
if [ -f /tmp/bigsigner-panel.pid ]; then
    kill "$(cat /tmp/bigsigner-panel.pid)" 2>/dev/null || true
    rm -f /tmp/bigsigner-panel.pid
fi
sleep 1
rm -f /tmp/bigsigner-tap
seedsigner start || true
""",
            timeout=40,
        )
        self.started = False

    def log(self) -> str:
        try:
            return self.ssh(
                "echo '--- log ---'; tail -n 30 /tmp/bigsigner-panel.log 2>/dev/null || true; "
                "echo '--- dmesg ---'; dmesg | grep bigsigner | tail -n 15",
                timeout=20,
            )
        except Exception as exc:
            return str(exc)

    def pull(self):
        self._absorb(self.ssh("cat /tmp/bigsigner-ui.jsonl 2>/dev/null || true", timeout=20))
        if not self.history:
            raise RuntimeError("The layout dump is empty.\n" + self.log())
        self.latest = self.history[-1]
        return self.latest

    def _absorb(self, text: str):
        frames = []
        for line in text.splitlines():
            try:
                frames.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        if frames:
            self.history = frames

    def wait(self, pred, timeout: float, what: str):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                self.pull()
            except RuntimeError:
                time.sleep(0.3)
                continue
            if pred(self.latest):
                return self.latest
            time.sleep(0.25)
        raise AssertionError(f"Timed out waiting for {what}. Last: {_brief(self.latest)}\n{self.log()}")

    def tap(self, name: str, timeout: float = 25):
        self.pull()
        hit = require_hit(self.latest, name)
        point = point_in(hit["box"])
        if point is None:
            raise AssertionError(f"{name} is off the screen at {hit['box']}")
        before = self.latest["frame"]
        x, y = point
        print(f"Tap {name} at {x},{y}", flush=True)
        self.ssh(f"printf '%s\\n' '{x} {y}' > /tmp/bigsigner-tap", timeout=20)
        return self.wait(lambda snap: snap["frame"] > before, timeout, f"a frame after tapping {name}")

    def burst(self, lines: list[str]):
        """One write. A pause longer than the touch gap would end the drag."""
        payload = "\n".join(lines) + "\n"
        self.ssh("printf '%s' " + shlex.quote(payload) + " > /tmp/bigsigner-tap", timeout=20)

    def shot(self, name: str) -> Image.Image:
        stride = int(self.ssh("cat /sys/class/graphics/fb0/stride", timeout=20).strip())
        width, height = (
            int(part) for part in self.ssh("cat /sys/class/graphics/fb0/virtual_size", timeout=20).strip().split(",")
        )
        raw = self.ssh("cat /dev/fb0", timeout=30, binary=True)
        image = _framebuffer(raw, stride, width, height)
        self.step += 1
        path = self.folder / f"{self.step:02d}-{name}.png"
        image.save(path)
        print(f"Saved {path.relative_to(ROOT)}", flush=True)
        return image

    def write_report(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        text = self.report()
        (self.folder / "report.txt").write_text(text, encoding="utf-8")
        print(text, flush=True)

    def report(self) -> str:
        lines = ["Panel frames", ""]
        slowest = {}
        for frame in self.history:
            screen = frame["screen"]
            if screen not in slowest or frame["ms"] > slowest[screen]["ms"]:
                slowest[screen] = frame
        for screen, frame in slowest.items():
            lines.append(f"{screen:16} slowest frame {frame['frame']:4}  {frame['ms']:5} ms")
        if self.address_ms is not None:
            lines.append(f"address list painted in {self.address_ms} ms")
        if self.prepare_ms is not None:
            lines.append(f"descriptor QR prepare max {self.prepare_ms} ms")
        if self.scroll_frames:
            shown = ", ".join(f"{frame['ms']} ms" for frame in self.scroll_frames)
            lines.append(f"descriptor QR scroll frames: {shown}")
            lines.append(
                f"descriptor QR scroll max {max(frame['ms'] for frame in self.scroll_frames)} ms, "
                f"limit {SCROLL_FRAME_MS} ms"
            )
        return "\n".join(lines) + "\n"


def run():
    panel = Panel()
    try:
        panel.install()
        panel.start()
        check_remove_sd(panel)
        check_menu_and_keys(panel)
        check_seed_key(panel)
        check_derive(panel)
        check_wallet_and_addresses(panel)
        check_descriptor_scroll(panel)
    except Exception:
        if panel.started:
            try:
                panel.shot("failure")
            except Exception as exc:
                print(f"Could not save the failure frame: {exc}", flush=True)
            print(panel.log(), flush=True)
        raise
    finally:
        try:
            panel.write_report()
        finally:
            if panel.started:
                panel.restore()


def check_remove_sd(panel: Panel):
    print("Remove SD Card", flush=True)
    snap = panel.wait(lambda item: item["screen"] == "warning", 30, "Remove SD Card")
    title = require_text(snap, "Remove SD Card")
    button = require_hit(snap, "Continue")
    body = next(item for item in snap["texts"] if "SD card" in item["text"])
    assert title["box"][3] <= HEADER, title
    assert body["box"][1] >= title["box"][3]
    assert body["box"][3] <= button["box"][1]
    assert button["box"][1] > 640
    image = panel.shot("remove-sd")
    _assert_closer(image.getpixel((12, 20)), NAVY, (255, 255, 255), "title bar")
    panel.tap("Continue")
    panel.wait(lambda item: item["menu"], 20, "the menu")


def check_menu_and_keys(panel: Panel):
    print("Menu", flush=True)
    snap = panel.pull()
    keys = require_hit(snap, "Bitcoin Keys")
    wallets = require_hit(snap, "Bitcoin Wallets")
    about = require_hit(snap, "About")
    close = require_hit(snap, "close")
    assert keys["box"][3] <= wallets["box"][1] <= wallets["box"][3] <= about["box"][1]
    assert keys["box"][2] <= 320
    assert close["box"][0] >= 320
    panel.shot("menu")
    panel.tap("close")
    snap = panel.wait(lambda item: not item["menu"] and _hit_prefix(item, "open-fp-"), 20, "Bitcoin Keys")
    card = _hit_prefix(snap, "open-fp-")
    assert card["box"][1] >= HEADER
    assert card["box"][0] >= 20
    fingerprint = require_text(snap, "73c5da0a")
    assert fingerprint["box"][1] > HEADER
    panel.shot("keys")
    panel.tap(card["label"])
    panel.wait(lambda item: item["screen"] == "key", 20, "the seed key")


def check_seed_key(panel: Panel):
    print("Seed Key", flush=True)
    snap = panel.pull()
    show = require_hit(snap, "Show Seed")
    export = require_hit(snap, "Export Seed to SD Card")
    derive = require_hit(snap, "Derive an Extended Public Key")
    assert show["box"][3] <= export["box"][1]
    assert export["box"][3] <= derive["box"][1]
    assert require_text(snap, "Seed Key")["box"][3] <= HEADER
    panel.shot("seed-key")
    panel.tap("Derive an Extended Public Key")
    panel.wait(lambda item: item["screen"] == "derive-type", 20, "the derive menu")


def check_derive(panel: Panel):
    print("Derive Key", flush=True)
    snap = panel.pull()
    native = require_hit(snap, "Native-Segwit SingleSig Key")
    multi = require_hit(snap, "Native-Segwit MultiSig Key")
    taproot = require_hit(snap, "Taproot SingleSig Key")
    assert native["box"][3] <= multi["box"][1]
    assert multi["box"][3] <= taproot["box"][1]
    panel.shot("derive-type")
    panel.tap("Native-Segwit SingleSig Key")
    snap = panel.wait(lambda item: item["screen"] == "derive", 30, "Derive Key")
    minus = require_text(snap, "-")
    plus = require_text(snap, "+")
    account = require_hit(snap, "Account")
    assert minus["box"][2] <= account["box"][0] <= account["box"][2] <= plus["box"][0]
    assert not any(hit["label"] == "-" for hit in snap["hits"])
    panel.shot("derive")
    panel.tap("Create a Native-Segwit SingleSig Wallet")
    panel.wait(lambda item: item["screen"] == "wallet", 30, "the new wallet")


def check_wallet_and_addresses(panel: Panel):
    print("Wallet and Addresses", flush=True)
    snap = panel.pull()
    addresses = require_hit(snap, "Addresses")
    descriptor = require_hit(snap, "Show Descriptor")
    assert addresses["box"][3] <= descriptor["box"][1]
    minus = require_text(snap, "-")
    plus = require_text(snap, "+")
    account = require_hit(snap, "Account")
    assert minus["box"][2] <= account["box"][0] <= account["box"][2] <= plus["box"][0]
    panel.shot("wallet")
    panel.tap("Addresses")
    snap = panel.wait(lambda item: _hit_startswith(item, "0. ") is not None, 45, "an address row")
    panel.address_ms = snap["ms"]
    print(f"Address list painted in {snap['ms']} ms", flush=True)
    receive = require_hit(snap, "Receive")
    change = require_hit(snap, "Change")
    row = _hit_startswith(snap, "0. ")
    assert receive["box"][2] <= change["box"][0]
    assert receive["box"][1] >= HEADER
    assert row["box"][1] >= receive["box"][3]
    assert row["label"].startswith("0. bc1")
    image = panel.shot("addresses")
    _assert_closer(image.getpixel(_fill_at(receive["box"])), BLUE, NAVY, "Receive")
    _assert_closer(image.getpixel(_fill_at(change["box"])), NAVY, BLUE, "Change")
    panel.tap("back")
    panel.wait(lambda item: item["screen"] == "wallet", 20, "the wallet")


def check_descriptor_scroll(panel: Panel):
    print("Descriptor QR", flush=True)
    opened = panel.latest["frame"]
    panel.tap("Show Descriptor")
    ready = panel.wait(
        lambda item: any(text["text"].startswith("wpkh") for text in item["qr_texts"]),
        45,
        "the descriptor under the QR",
    )
    prepare = [frame for frame in panel.history if opened < frame["frame"] <= ready["frame"]]
    panel.prepare_ms = max(frame["ms"] for frame in prepare)
    print(f"Descriptor QR prepare max {panel.prepare_ms} ms", flush=True)
    title = require_text(ready, "Descriptor")
    bright = require_text(ready, "Brightness")
    line = next(text for text in ready["qr_texts"] if text["text"].startswith("wpkh"))
    assert title["box"][3] <= HEADER
    assert title["box"][0] > 70
    assert bright["box"][1] > 600
    assert ready["qr_box"][1] < line["box"][1]
    minus = require_text(ready, "-")
    plus = require_text(ready, "+")
    assert minus["box"][0] < bright["box"][0] < plus["box"][0]
    image = panel.shot("descriptor")
    _assert_qr(image, ready["qr_box"])
    panel_box = ready["qr_panel"]
    if panel_box is None:
        raise AssertionError("The descriptor QR is not a scroll panel")
    before_line = line["box"][1]
    before_qr = ready["qr_box"][1]
    before_scroll = ready["qr_scroll"]
    # Each drag is its own down, move, and up. One burst would be painted once:
    # the moves land before the next paint is due, and only the release is drawn.
    frames = []
    for index in range(3):
        frames.extend(_drag_qr(panel, panel_box))
        print(f"QR scroll {index + 1}: {frames[-1]['ms']} ms", flush=True)
    panel.scroll_frames = frames
    shown = ", ".join(f"{frame['ms']} ms" for frame in frames)
    print(f"QR scroll frames: {shown}", flush=True)
    assert len(frames) >= 3, f"expected a paint for each drag, got {shown}"
    slow = [frame for frame in frames if frame["ms"] > SCROLL_FRAME_MS]
    assert not slow, f"QR scroll frame slower than {SCROLL_FRAME_MS} ms: {shown}"
    after = panel.latest
    assert after["qr_scroll"] >= before_scroll + 80
    after_line = _qr_line_top(after, "wpkh")
    if after_line is None:
        assert before_line > HEADER
    else:
        assert after_line < before_line - 40
    assert after["qr_box"][1] < before_qr - 40
    panel.shot("descriptor-scrolled")


def _drag_qr(panel: Panel, box) -> list[dict]:
    """Move the QR up by 80 pixels and return the paints that showed it."""
    x = (box[0] + box[2]) // 2
    y0 = box[1] + (box[3] - box[1]) * 2 // 3
    y1 = y0 - 80
    before = panel.latest["frame"]
    before_scroll = panel.latest["qr_scroll"]
    panel.burst([f"down {x} {y0}", f"move {x} {y1}", f"up {x} {y1}"])
    after = panel.wait(
        lambda snap: snap["frame"] > before and snap["qr_scroll"] > before_scroll,
        20,
        "the descriptor to scroll",
    )
    return [frame for frame in panel.history if before < frame["frame"] <= after["frame"]]


def require_hit(snap, name):
    found = [
        hit for hit in snap["hits"]
        if hit["label"] == name or hit["action"] == name
    ]
    visible = [hit for hit in found if point_in(hit["box"])]
    if visible:
        return visible[0]
    if found:
        return found[0]
    labels = [hit["label"] for hit in snap["hits"]]
    raise AssertionError(f"No {name!r} on {snap['screen']}. Hits: {labels}")


def require_text(snap, name):
    found = [item for item in snap["texts"] if item["text"] == name]
    if not found:
        shown = [item["text"] for item in snap["texts"]]
        raise AssertionError(f"No text {name!r} on {snap['screen']}. Texts: {shown}")
    return found[0]


def _hit_prefix(snap, prefix: str):
    return next((hit for hit in snap["hits"] if hit["action"].startswith(prefix)), None)


def _hit_startswith(snap, prefix: str):
    return next((hit for hit in snap["hits"] if hit["label"].startswith(prefix)), None)


def _qr_line_top(snap, prefix: str):
    for item in snap["qr_texts"]:
        if item["text"].startswith(prefix):
            return item["box"][1]
    return None


def point_in(box):
    left, top, right, bottom = (int(value) for value in box)
    y0 = max(top, 2)
    y1 = min(bottom - 1, HEIGHT - 2)
    x0 = max(left, 2)
    x1 = min(right - 1, WIDTH - 2)
    if y1 - y0 < 8 or x1 - x0 < 8:
        return None
    return (x0 + x1) // 2, (y0 + y1) // 2


def _fill_at(box):
    left, top, _right, bottom = (int(value) for value in box)
    return left + 16, (top + bottom) // 2


def _assert_closer(pixel, this, other, what: str):
    if _dist(pixel, this) >= _dist(pixel, other):
        raise AssertionError(f"{what} pixel {pixel} is not closer to {this} than {other}")


def _dist(pixel, color) -> int:
    return sum((int(pixel[index]) - color[index]) ** 2 for index in range(3))


def _assert_qr(image: Image.Image, box):
    left = max(0, int(box[0]))
    top = max(HEADER, int(box[1]))
    right = min(image.width, int(box[2]))
    bottom = min(image.height, int(box[3]))
    crop = image.crop((left, top, right, bottom))
    dark = light = 0
    for pixel in crop.getdata():
        shade = int(pixel[0]) + int(pixel[1]) + int(pixel[2])
        if shade < 120:
            dark += 1
        elif shade > 600:
            light += 1
    if dark < 30 or light < 30:
        raise AssertionError(f"QR region has {dark} dark pixels and {light} light pixels")


def _framebuffer(raw: bytes, stride: int, width: int, height: int) -> Image.Image:
    need = height * stride
    if len(raw) < need:
        raise RuntimeError(f"Framebuffer is {len(raw)} bytes, expected at least {need}")
    if stride == width * 2:
        blob = raw[: width * height * 2]
    else:
        rows = []
        for y in range(height):
            start = y * stride
            rows.append(raw[start : start + width * 2])
        blob = b"".join(rows)
    return Image.frombytes("RGB", (width, height), blob, "raw", "BGR;16")


def _brief(snap) -> str:
    if not snap:
        return "no frame"
    labels = [hit["label"] for hit in snap["hits"][:8]]
    return f"frame {snap['frame']} {snap['screen']} menu={snap['menu']} {labels}"


def main():
    run()


if __name__ == "__main__":
    main()

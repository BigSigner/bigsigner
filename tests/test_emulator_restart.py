import io
import os
import pty
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
PORT = 8778
NAVY = (18, 36, 58)


def frame_pixel(x, y):
    data = urllib.request.urlopen(f"http://127.0.0.1:{PORT}/frame.png", timeout=3).read()
    return Image.open(io.BytesIO(data)).getpixel((x, y))[:3]


def wait_pixel(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = frame_pixel(240, 400)
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
            continue
        if predicate(last):
            return last
        time.sleep(0.05)
    raise AssertionError(last)


def test_the_emulator_page_uses_the_waveshare_picture_size():
    from bigsigner.emulator.server import INDEX

    assert "51.84" in INDEX
    assert "86.4" in INDEX
    assert "480px" not in INDEX


def test_typing_r_restarts_the_emulator_with_empty_memory():
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        [sys.executable, "-c", "from bigsigner.emulator.server import serve; serve(8778)"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )
    os.close(slave)

    def drain():
        while True:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                return
            if not chunk:
                return

    threading.Thread(target=drain, daemon=True).start()
    try:
        wait_pixel(lambda color: color == NAVY)
        request = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/tap",
            data=b'{"x":240,"y":400}',
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=3).read()
        wait_pixel(lambda color: color != NAVY)
        os.write(master, b"r")
        wait_pixel(lambda color: color == NAVY, timeout=10)
    finally:
        proc.kill()
        proc.wait(timeout=3)
        os.close(master)

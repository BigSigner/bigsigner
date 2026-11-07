#!/usr/bin/env python3
"""Load the 100-in / 100-out PSBT on the live panel and scroll it.

Stops nothing by itself. On the device, stop the normal service first, then run
this. It shows progress, Transaction Signing, and a short auto-scroll back to
the top, then starts the normal app again so the panel stays tappable. Pass
``--stay`` to keep this process on Transaction Signing instead (Ctrl-C to quit,
then ``seedsigner start``).

This script is a stand-in for the panel process. When it exits without starting
the normal app, nothing is drawing or reading touch. That is unrelated to the
desktop ``.venv``; see ``tests/vectors/README.md``.

Do not sign with a real seed; this uses the Abandon test mnemonic only.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import time
from pathlib import Path

from embit import bip32, bip39
from embit.descriptor.checksum import checksum

from bigsigner.hardware.camera import LiveCamera
from bigsigner.hardware.display import framebuffer_info, pack_image, silence_console
from bigsigner.hardware.panel import _drag_interval, _kmsg
from bigsigner.hardware.touch import ABS_X, ABS_Y, axis_range, find_touch, read_points
from bigsigner.rpc import apply_line, open_rpc_pipe
from bigsigner.ui.app import App

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)
VECTOR = (
    Path(__file__).resolve().parent / "vectors" / "native_segwit_100_in_100_out.psbt"
)


def make_app(psbt_path: Path) -> App:
    app = App()
    app.session.add_mnemonic(ABANDON.split())
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(ABANDON))
    public = root.derive("m/84h/0h/0h").to_public()
    key = f"[{root.my_fingerprint.hex()}/84h/0h/0h]{public.to_string()}/<0;1>/*"
    app.session.add_text(f"wpkh({key})#{checksum('wpkh(' + key + ')')}")
    app.wallet_index = 0
    app.screen = "load-psbt"
    app.back = ["wallet"]
    app._auto_psbt = psbt_path.read_bytes()
    return app


def _start_normal_app() -> None:
    """Hand the panel back to the service that owns touch after boot."""
    _kmsg("starting seedsigner")
    subprocess.run(["seedsigner", "start"], check=False)


def run(psbt_path: Path | None = None, *, stay: bool = False) -> None:
    path = VECTOR if psbt_path is None else psbt_path
    if not path.is_file():
        raise SystemExit(f"missing PSBT: {path}")
    app = make_app(path)
    camera = LiveCamera()
    fb = os.open("/dev/fb0", os.O_RDWR)
    width, height, stride, bpp, channels = framebuffer_info(fb)
    touch_path = find_touch()
    touch = os.open(touch_path, os.O_RDONLY | os.O_NONBLOCK) if touch_path else None
    ranges = (axis_range(touch, ABS_X), axis_range(touch, ABS_Y)) if touch else None
    rpc = open_rpc_pipe()
    rpc_fd = None if rpc is None else rpc[0]
    _kmsg(f"hundred psbt demo, touch {touch_path or 'missing'}")
    silence_console()
    frames = 0
    painted_at = 0.0
    pending = False
    hand_back = not stay

    def _write(image):
        band = app.dirty if image.size == (width, height) else None
        if band:
            top, bottom = band
            top = max(0, min(height, top))
            bottom = max(top, min(height, bottom))
            payload = pack_image(image.crop((0, top, width, bottom)), stride, bpp, channels)
            os.lseek(fb, top * stride, os.SEEK_SET)
            os.write(fb, payload)
            return
        if (width, height) != image.size:
            image = image.resize((width, height))
        os.lseek(fb, 0, os.SEEK_SET)
        os.write(fb, pack_image(image, stride, bpp, channels))

    def blit():
        nonlocal frames, painted_at, pending
        pending = False
        started = time.monotonic()
        painted_at = started
        _write(app.render())
        elapsed = int((time.monotonic() - started) * 1000)
        frames += 1
        if frames == 1 or elapsed >= 500:
            _kmsg(f"frame {frames} {elapsed} ms {app.screen}")
        return elapsed

    app.flush_display = blit

    def wait():
        delays = []
        if pending:
            delays.append(_drag_interval(app))
        if app.finger_down():
            delays.append(0.05)
        notice = app.notice_delay()
        if notice is not None:
            delays.append(notice)
        if not delays:
            return None
        return min(delays)

    try:
        blit()
        _kmsg(f"accepting {path.name}")
        app._accept_psbt_text(app._auto_psbt, "file")
        app.psbt_outputs_open = True
        app.psbt_inputs_open = True
        app._psbt_sheet = None
        _kmsg(f"ready screen={app.screen}")
        blit()
        limit = app.scroll_max.get("psbt-yaml", 0)
        for offset in (min(1200, limit), min(4000, limit), min(1200, limit), 0):
            app.scroll["psbt-yaml"] = offset
            app._press = None
            blit()
            time.sleep(0.35)
        app.scroll["psbt-yaml"] = 0
        blit()
        Path("/tmp/bigsigner-hundred-ready").write_text(
            f"screen={app.screen}\n"
            f"inputs={len(app.psbt_view['inputs'])}\n"
            f"outputs={len(app.psbt_view['outputs'])}\n"
            f"scroll={app.scroll.get('psbt-yaml', 0)}\n",
            encoding="ascii",
        )
        if not stay:
            _kmsg("auto-scroll done; handing panel back")
            return
        _kmsg("auto-scroll done; at top; --stay")
        hand_back = False
        if touch is None and rpc_fd is None:
            return
        x_range = ranges[0] if ranges else (0, width - 1)
        y_range = ranges[1] if ranges else (0, height - 1)
        for point in read_points(touch, width, height, x_range, y_range, wait=wait, rpc=rpc_fd):
            if point is None:
                app.pointer_idle()
                blit()
                continue
            if point[0] == "rpc":
                try:
                    _kmsg(apply_line(app, point[1]))
                except Exception as exc:
                    _kmsg(f"command refused: {exc}")
                blit()
                continue
            if point[0] == "rpc-error":
                _kmsg(point[1])
                continue
            phase, x, y = point
            if phase == "down":
                app.pointer_down(x, y)
            elif phase in ("move", "hold"):
                if app.pointer_move(x, y):
                    if time.monotonic() - painted_at >= _drag_interval(app):
                        blit()
                    else:
                        pending = True
            elif phase == "up":
                app.pointer_up(x, y)
                blit()
    finally:
        camera.close()
        if touch is not None:
            os.close(touch)
        os.close(fb)
        if rpc is not None:
            os.close(rpc[0])
        if hand_back:
            _start_normal_app()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--stay",
        action="store_true",
        help="keep Transaction Signing interactive instead of starting the normal app",
    )
    parser.add_argument(
        "psbt",
        nargs="?",
        type=Path,
        default=None,
        help="PSBT path (default: tests/vectors/native_segwit_100_in_100_out.psbt)",
    )
    args = parser.parse_args(argv)
    run(args.psbt, stay=args.stay)


if __name__ == "__main__":
    main()

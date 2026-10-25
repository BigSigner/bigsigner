"""Show the signer on the HDMI framebuffer and read touch events."""

import os
import time

from ..ui.app import App
from .camera import LiveCamera, jpeg_bytes, paste_preview, read_qr
from .display import framebuffer_info, pack_image, silence_console
from .touch import ABS_X, ABS_Y, axis_range, find_touch, read_points


def _kmsg(message: str):
    """One line in the kernel log, readable with dmesg over SSH."""
    try:
        with open("/dev/kmsg", "w", encoding="ascii", errors="replace") as handle:
            handle.write(f"bigsigner: {message}\n")
    except OSError:
        pass


def run_panel():
    app = App()
    camera = LiveCamera()
    fb = os.open("/dev/fb0", os.O_RDWR)
    width, height, stride, bpp, channels = framebuffer_info(fb)
    touch_path = find_touch()
    touch = os.open(touch_path, os.O_RDONLY | os.O_NONBLOCK) if touch_path else None
    ranges = (axis_range(touch, ABS_X), axis_range(touch, ABS_Y)) if touch else None
    _kmsg(f"framebuffer {width}x{height} {bpp}bpp, touch {touch_path or 'missing'}")
    silence_console()

    frames = 0

    def blit():
        nonlocal frames
        started = time.monotonic()
        image = _with_camera(app, camera)
        band = app.dirty if image.size == (width, height) else None
        if band:
            top, bottom = band
            top = max(0, min(height, top))
            bottom = max(top, min(height, bottom))
            payload = pack_image(image.crop((0, top, width, bottom)), stride, bpp, channels)
            os.lseek(fb, top * stride, os.SEEK_SET)
            os.write(fb, payload)
        else:
            if (width, height) != image.size:
                image = image.resize((width, height))
            os.lseek(fb, 0, os.SEEK_SET)
            os.write(fb, pack_image(image, stride, bpp, channels))
        elapsed = int((time.monotonic() - started) * 1000)
        frames += 1
        if frames == 1 or elapsed >= 500:
            _kmsg(f"frame {frames} {elapsed} ms")

    def wait():
        # Keep painting while the viewfinder is open. Otherwise wait for a notice to expire.
        if app.camera_preview_box() is not None:
            return 0.1
        return app.notice_delay()

    try:
        blit()
        if touch is None:
            return
        logged_touch = False
        for point in read_points(touch, width, height, ranges[0], ranges[1], wait=wait):
            if point is None:
                blit()
                continue
            phase, x, y = point
            if not logged_touch:
                logged_touch = True
                _kmsg(f"touch {phase} {x},{y}")
            if phase == "down":
                app.pointer_down(x, y)
            elif phase == "move":
                if app.pointer_move(x, y):
                    blit()
            elif phase == "up":
                app.pointer_up(x, y)
                blit()
    finally:
        camera.close()


def _with_camera(app: App, camera: LiveCamera):
    """Draw the screen, then cover its viewfinder with the live picture."""
    image = app.render()
    box = app.camera_preview_box()
    if box is None:
        camera.close()
        camera.failed = False
        camera.reported = False
        camera.last_qr = None
        return image
    shot = camera.frame()
    if shot is None:
        if camera.failed and not camera.reported:
            camera.reported = True
            app.set_notice("The camera is not available.")
            image = app.render()
        return image
    if app.screen == "camera":
        app.remember_camera_frame(jpeg_bytes(shot))
    elif app.screen == "scan":
        text = read_qr(shot)
        if text and text != camera.last_qr:
            camera.last_qr = text
            app.accept_qr(text)
            image = app.render()
            box = app.camera_preview_box()
        elif not text:
            camera.last_qr = None
    if box is not None:
        paste_preview(image, shot, box)
    return image

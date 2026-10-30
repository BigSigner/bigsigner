"""Show the signer on the HDMI framebuffer and read touch events."""

import os
import time

from ..ui.app import App
from .camera import LiveCamera, jpeg_bytes, paste_preview, read_qr
from .display import framebuffer_info, pack_image, silence_console
from .touch import ABS_X, ABS_Y, axis_range, find_touch, read_points

# Seconds between frames while a finger drags a list.
DRAG_INTERVAL = 0.15


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
    tap_path = os.environ.get("BIGSIGNER_TAP", "").strip()
    inject = os.open(tap_path, os.O_RDWR | os.O_NONBLOCK) if tap_path and os.path.exists(tap_path) else None
    _kmsg(f"framebuffer {width}x{height} {bpp}bpp, touch {touch_path or 'missing'}")
    silence_console()

    frames = 0
    painted_at = 0.0
    # A drag moves faster than this board can paint. Painting every move queues
    # stale frames behind the finger. Paint at most this often while dragging,
    # then once more when the finger pauses or lifts.
    pending = False

    def blit():
        nonlocal frames, painted_at, pending
        pending = False
        started = time.monotonic()
        painted_at = started
        if app.qr_strip_due():
            # The chevrons, or the loading line, are already on the panel.
            app.build_qr_strip()
            if not app.qr_hint_holding():
                _write(_with_camera(app, camera))
        else:
            preview = app.preview_qr_frame()
            if preview is not None:
                _write(preview)
            else:
                _write(_with_camera(app, camera))
        elapsed = int((time.monotonic() - started) * 1000)
        frames += 1
        if frames == 1 or elapsed >= 500:
            _kmsg(f"frame {frames} {elapsed} ms")
        return elapsed

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

    def wait():
        # Keep painting while the viewfinder shows a live picture. A camera that
        # could not open has nothing new to show, so wait for a touch instead.
        # A finger that is down is polled, so a long hold can become a scroll
        # and a pause in the reports can end a click.
        delays = []
        if pending:
            delays.append(DRAG_INTERVAL)
        if app.qr_strip_due():
            delays.append(0)
        if app.finger_down():
            delays.append(0.05)
        if app.camera_preview_box() is not None and not camera.failed:
            delays.append(0.1)
        notice = app.notice_delay()
        if notice is not None:
            delays.append(notice)
        if not delays:
            return None
        return min(delays)

    try:
        blit()
        if touch is None:
            return
        logged_touch = False
        for point in read_points(touch, width, height, ranges[0], ranges[1], wait=wait, inject=inject):
            if point is None:
                app.pointer_idle()
                blit()
                continue
            phase, x, y = point
            if not logged_touch:
                logged_touch = True
                _kmsg(f"touch {phase} {x},{y}")
            if phase == "down":
                app.pointer_down(x, y)
            elif phase in ("move", "hold"):
                if app.pointer_move(x, y):
                    if time.monotonic() - painted_at >= DRAG_INTERVAL:
                        blit()
                    else:
                        pending = True
            elif phase == "up":
                app.pointer_up(x, y)
                elapsed = blit()
                if inject is not None:
                    _kmsg(f"tap {x},{y} {elapsed} ms")
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
        app.camera_unavailable = False
        return image
    shot = camera.frame()
    if shot is None:
        if camera.failed and not app.camera_unavailable:
            app.camera_unavailable = True
            image = app.render()
        return image
    if app.camera_unavailable:
        app.camera_unavailable = False
        image = app.render()
        box = app.camera_preview_box()
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

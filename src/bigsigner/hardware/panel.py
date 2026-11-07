"""Show the signer on the HDMI framebuffer and read touch events."""

import os
import select
import time

from ..rpc import apply_line, open_rpc_pipe
from ..ui.app import App
from .camera import LiveCamera, jpeg_bytes, paste_preview, read_qr
from .display import framebuffer_info, pack_image, silence_console
from .touch import ABS_X, ABS_Y, axis_range, find_touch, read_points
from .ui_dump import append_snapshot

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
    rpc = open_rpc_pipe()
    rpc_fd = None if rpc is None else rpc[0]
    ui_path = os.environ.get("BIGSIGNER_UI", "").strip()
    dump_error = False
    _kmsg(f"framebuffer {width}x{height} {bpp}bpp, touch {touch_path or 'missing'}")
    if rpc_fd is not None:
        _kmsg(f"listening on {rpc[1]}")
    silence_console()

    frames = 0
    painted_at = 0.0
    # A drag moves faster than this board can paint. Painting every move queues
    # stale frames behind the finger. Paint at most this often while dragging,
    # then once more when the finger pauses or lifts.
    pending = False

    def flush_progress():
        """Push the progress screen while a PSBT check is still running."""
        nonlocal frames, painted_at
        started = time.monotonic()
        painted_at = started
        _write(app.render())
        elapsed = int((time.monotonic() - started) * 1000)
        frames += 1
        if frames == 1 or elapsed >= 500:
            _kmsg(f"frame {frames} {elapsed} ms")

    app.flush_display = flush_progress

    def blit():
        nonlocal frames, painted_at, pending, dump_error
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
        if ui_path and not dump_error:
            try:
                append_snapshot(ui_path, app, elapsed, frames)
            except Exception as exc:
                dump_error = True
                _kmsg(f"ui dump {exc}")
        # A touch already waiting was pressed while Loading was on the glass.
        if touch is not None and app.take_queued_touch_discard():
            ready, _, _ = select.select([touch], [], [], 0)
            if ready:
                app.arm_queued_touch_discard()
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
        # A finger that is down is polled, so a long hold can become a scroll.
        # The gesture ends when the lift event arrives.
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
        if touch is None and rpc_fd is None:
            return
        x_range = ranges[0] if ranges else (0, width - 1)
        y_range = ranges[1] if ranges else (0, height - 1)
        logged_touch = False
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

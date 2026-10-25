"""Show the signer on the HDMI framebuffer and read touch events."""

import os

from ..ui.app import App
from .camera import LiveCamera, jpeg_bytes, paste_preview, read_qr
from .display import framebuffer_info, pack_image
from .touch import ABS_X, ABS_Y, axis_range, find_touch, read_points


def run_panel():
    app = App()
    camera = LiveCamera()
    fb = os.open("/dev/fb0", os.O_RDWR)
    width, height, stride, bpp, channels = framebuffer_info(fb)
    touch_path = find_touch()
    touch = os.open(touch_path, os.O_RDONLY) if touch_path else None
    ranges = (axis_range(touch, ABS_X), axis_range(touch, ABS_Y)) if touch else None

    def blit():
        image = _with_camera(app, camera)
        if (width, height) != image.size:
            image = image.resize((width, height))
        os.lseek(fb, 0, os.SEEK_SET)
        os.write(fb, pack_image(image, stride, bpp, channels))

    def wait():
        # Keep painting while the viewfinder is open. Otherwise wait for a notice to expire.
        if app.camera_preview_box() is not None:
            return 0.1
        return app.notice_delay()

    try:
        blit()
        if touch is None:
            return
        for point in read_points(touch, width, height, ranges[0], ranges[1], wait=wait):
            if point is None:
                blit()
                continue
            phase, x, y = point
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

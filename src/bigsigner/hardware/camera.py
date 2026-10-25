"""Live camera frames for the Raspberry Pi panel.

picamera2 and pyzbar are provided by the device image. They are not imported
unless this machine is actually capturing. The emulator does not use this module.
"""

import io

from PIL import Image


VIEWFINDER = (12, 14, 18)


class LiveCamera:
    """One camera, opened only while a screen is showing its picture."""

    def __init__(self):
        self._camera = None
        self.failed = False
        self.reported = False
        self.last_qr = None

    def frame(self):
        """The latest picture, or None when the camera cannot be opened."""
        if self.failed:
            return None
        try:
            camera = self._open()
            if camera is None:
                return None
            request = camera.capture_request()
            try:
                image = _image_from_request(request)
            finally:
                request.release()
        except Exception:
            self.failed = True
            self.close()
            return None
        return image

    def close(self):
        camera = self._camera
        self._camera = None
        if camera is None:
            return
        try:
            camera.stop()
        except Exception:
            pass
        try:
            camera.close()
        except Exception:
            pass

    def _open(self):
        if self._camera is not None:
            return self._camera
        try:
            from picamera2 import Picamera2
        except ImportError:
            self.failed = True
            return None
        camera = Picamera2()
        config = camera.create_preview_configuration(
            main={"size": (640, 480), "format": "RGB888"},
            buffer_count=2,
        )
        camera.configure(config)
        camera.start()
        self._camera = camera
        return camera


def paste_preview(image: Image.Image, shot: Image.Image, box: tuple[int, int, int, int]):
    """Scale the picture to cover the viewfinder, keeping the center."""
    left, top, right, bottom = box
    width = right - left
    height = bottom - top
    if width <= 0 or height <= 0:
        return
    scale = max(width / shot.width, height / shot.height)
    resized = shot.resize((max(1, round(shot.width * scale)), max(1, round(shot.height * scale))))
    crop_x = max(0, (resized.width - width) // 2)
    crop_y = max(0, (resized.height - height) // 2)
    image.paste(resized.crop((crop_x, crop_y, crop_x + width, crop_y + height)), (left, top))


def read_qr(image: Image.Image) -> str | None:
    """The first QR text in the picture, or None when zbar is absent or finds nothing."""
    try:
        from pyzbar.pyzbar import decode
    except ImportError:
        return None
    try:
        codes = decode(image)
    except Exception:
        return None
    for code in codes:
        if code.type != "QRCODE" or not code.data:
            continue
        try:
            return code.data.decode("utf-8")
        except UnicodeDecodeError:
            return code.data.decode("latin-1")
    return None


def jpeg_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, format="JPEG", quality=70)
    return buffer.getvalue()


def _image_from_request(request) -> Image.Image:
    """A copied RGB picture. picamera2's RGB888 buffer is stored as BGR."""
    if hasattr(request, "make_image"):
        image = request.make_image("main")
        return image.copy() if image is not None else Image.fromarray(request.make_array("main")).copy()
    array = request.make_array("main")
    raw = Image.fromarray(array).copy()
    red, green, blue = raw.split()
    return Image.merge("RGB", (blue, green, red))

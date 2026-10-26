"""Live camera frames for the Raspberry Pi panel.

The device image provides one of two camera libraries. bigsigner-os ships the
legacy ``picamera``, which talks to the firmware over MMAL. A card built on the
libcamera stack has ``picamera2`` instead. Both are tried; neither is imported
unless this machine is actually capturing. pyzbar reads the codes. The emulator
does not use this module.
"""

import io

from PIL import Image


VIEWFINDER = (12, 14, 18)
CAPTURE_SIZE = (640, 480)


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
            image = camera.frame()
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
            camera.close()
        except Exception:
            pass

    def _open(self):
        if self._camera is not None:
            return self._camera
        for backend in (_Picamera2, _LegacyPicamera):
            camera = backend.open()
            if camera is not None:
                self._camera = camera
                return camera
        self.failed = True
        return None


class _Picamera2:
    """libcamera through picamera2."""

    def __init__(self, camera):
        self._camera = camera

    @classmethod
    def open(cls):
        try:
            from picamera2 import Picamera2
        except ImportError:
            return None
        camera = Picamera2()
        config = camera.create_preview_configuration(
            main={"size": CAPTURE_SIZE, "format": "RGB888"},
            buffer_count=2,
        )
        camera.configure(config)
        camera.start()
        return cls(camera)

    def frame(self) -> Image.Image:
        request = self._camera.capture_request()
        try:
            return _image_from_request(request)
        finally:
            request.release()

    def close(self):
        try:
            self._camera.stop()
        finally:
            self._camera.close()


class _LegacyPicamera:
    """The firmware camera through picamera 1.x, as on bigsigner-os.

    The video port gives a frame without the still-capture pause. The sensor
    needs a moment after start before its exposure settles.
    """

    def __init__(self, camera):
        self._camera = camera
        self._buffer = io.BytesIO()

    @classmethod
    def open(cls):
        try:
            from picamera import PiCamera
        except ImportError:
            return None
        camera = PiCamera(resolution=CAPTURE_SIZE, framerate=15)
        return cls(camera)

    def frame(self) -> Image.Image:
        buffer = self._buffer
        buffer.seek(0)
        buffer.truncate()
        self._camera.capture(buffer, format="rgb", use_video_port=True)
        width, height = CAPTURE_SIZE
        return Image.frombuffer("RGB", (width, height), buffer.getvalue(), "raw", "RGB", 0, 1).copy()

    def close(self):
        self._camera.close()


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

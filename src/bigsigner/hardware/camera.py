"""Live camera frames for the Raspberry Pi panel.

The device image provides one of two camera libraries. bigsigner-os ships the
legacy ``picamera``, which talks to the firmware over MMAL. A card built on the
libcamera stack has ``picamera2`` instead. Both are tried; neither is imported
unless this machine is actually capturing. pyzbar reads the codes. The emulator
does not use this module.
"""

import io
import threading

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

    Frames are captured on a background thread, the way SeedSigner's video
    stream does. A capture on the UI thread blocks the whole panel, and a
    sensor that pauses hits picamera's 60 second timeout before the page
    accepts a tap again. The screen keeps the newest picture and stays
    responsive while the next one is read.
    """

    def __init__(self, camera):
        self._camera = camera
        self._latest = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._closed = threading.Event()
        self._error = None
        self._thread = threading.Thread(target=self._run, name="bigsigner-camera", daemon=True)
        self._thread.start()

    @classmethod
    def open(cls):
        try:
            from picamera import PiCamera
        except ImportError:
            return None
        camera = PiCamera(resolution=CAPTURE_SIZE, framerate=15)
        # A stalled sensor must give up quickly. The default wait is 60 seconds.
        # The value is a class attribute; picamera rejects setting it on the camera.
        PiCamera.CAPTURE_TIMEOUT = 2
        return cls(camera)

    def _run(self):
        misses = 0
        try:
            while not self._stop.is_set():
                buffer = io.BytesIO()
                try:
                    self._camera.capture(buffer, format="rgb", use_video_port=True)
                except Exception as exc:
                    misses += 1
                    if misses < 3 and not self._stop.is_set():
                        continue
                    self._error = exc
                    return
                misses = 0
                width, height = CAPTURE_SIZE
                image = Image.frombuffer(
                    "RGB", (width, height), buffer.getvalue(), "raw", "RGB", 0, 1
                ).copy()
                with self._lock:
                    self._latest = image
        finally:
            try:
                self._camera.close()
            except Exception:
                pass
            self._closed.set()

    def frame(self) -> Image.Image | None:
        if self._error is not None:
            raise self._error
        with self._lock:
            return self._latest

    def close(self):
        self._stop.set()
        self._closed.wait(timeout=4)


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

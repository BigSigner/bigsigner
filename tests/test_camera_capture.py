"""Camera backend failures must reach the panel without stranding its preview."""

import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from PIL import Image

from bigsigner.hardware.camera import CAPTURE_SIZE, LiveCamera, _LegacyPicamera, _Picamera2


def test_a_modern_backend_startup_failure_falls_back_to_legacy(monkeypatch):
    shot = Image.new("RGB", (4, 4))
    legacy = SimpleNamespace(frame=Mock(return_value=shot), close=Mock())
    monkeypatch.setattr(_Picamera2, "open", Mock(side_effect=RuntimeError("no libcamera sensor")))
    monkeypatch.setattr(_LegacyPicamera, "open", Mock(return_value=legacy))
    camera = LiveCamera()
    try:
        assert camera.frame() is shot
        assert not camera.failed
    finally:
        camera.close()
    legacy.close.assert_called_once()


def test_a_failed_modern_backend_releases_resources(monkeypatch):
    raw = SimpleNamespace(
        create_preview_configuration=Mock(return_value={}),
        configure=Mock(side_effect=RuntimeError("configuration failed")), close=Mock(),
    )
    monkeypatch.setitem(sys.modules, "picamera2", SimpleNamespace(Picamera2=lambda: raw))
    with pytest.raises(RuntimeError, match="configuration failed"):
        _Picamera2.open()
    raw.close.assert_called_once()


def test_bad_rgb_frames_are_reported_instead_of_silently_killing_the_worker():
    raw = SimpleNamespace(capture=Mock(side_effect=lambda buffer, **_kwargs: buffer.write(b"short")), close=Mock())
    worker = _LegacyPicamera(raw)
    try:
        assert worker._closed.wait(2)
        assert raw.capture.call_count == 3
        with pytest.raises(ValueError):
            worker.frame()
        camera = LiveCamera()
        camera._camera = worker
        assert camera.frame() is None
        assert camera.failed
    finally:
        worker.close()
    raw.close.assert_called_once()


def test_legacy_capture_recovers_from_a_transient_error():
    published = threading.Event()
    release = threading.Event()
    width, height = CAPTURE_SIZE
    rgb = bytes((10, 20, 30)) * (width * height)

    def capture(buffer, **_kwargs):
        if raw.capture.call_count == 1:
            raise TimeoutError("first capture failed")
        if raw.capture.call_count > 2:
            published.set()  # Previous frame was published before this call.
            release.wait(2)
        buffer.write(rgb)

    raw = SimpleNamespace(capture=Mock(side_effect=capture), close=Mock())
    worker = _LegacyPicamera(raw)
    try:
        assert published.wait(2)
        shot = worker.frame()
        assert shot.size == CAPTURE_SIZE
        assert shot.getpixel((0, 0)) == (10, 20, 30)
    finally:
        worker._stop.set()
        release.set()
        worker.close()
    assert worker._closed.is_set()
    raw.close.assert_called_once()

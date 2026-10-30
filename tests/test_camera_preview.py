from PIL import Image

from bigsigner.hardware.camera import paste_preview, read_qr
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEADER, HEIGHT, WIDTH


def test_the_scan_and_camera_screens_reserve_a_viewfinder():
    app = App()
    app.screen = "keys"
    assert app.camera_preview_box() is None

    app.screen = "scan"
    box = app.camera_preview_box()
    image = app.render()
    assert box == (0, HEADER, WIDTH, HEIGHT - 108)
    assert image.getpixel((box[0] + 8, box[1] + 8))[:3] == (12, 14, 18)
    assert image.getpixel((WIDTH // 2, HEIGHT - 20))[:3] != (12, 14, 18)

    app.screen = "camera"
    camera_box = app.camera_preview_box()
    camera = app.render()
    assert camera_box[1] > HEADER
    assert camera_box[3] < HEIGHT - 110
    assert camera.getpixel((camera_box[0] + 8, camera_box[1] + 8))[:3] == (12, 14, 18)


def test_a_camera_frame_covers_the_viewfinder_and_leaves_the_header():
    image = Image.new("RGB", (WIDTH, HEIGHT), (255, 255, 255))
    shot = Image.new("RGB", (30, 80), (0, 180, 40))
    box = (0, HEADER, WIDTH, HEIGHT - 88)
    paste_preview(image, shot, box)
    assert image.getpixel((WIDTH // 2, (box[1] + box[3]) // 2)) == (0, 180, 40)
    assert image.getpixel((WIDTH // 2, 20)) == (255, 255, 255)
    assert image.getpixel((WIDTH // 2, HEIGHT - 20)) == (255, 255, 255)


def test_a_missing_camera_replaces_the_scan_instruction():
    app = App()
    app.screen = "scan"
    assert app.scan_prompt() == "Point the camera at one QR code."
    app.camera_unavailable = True
    assert app.scan_prompt() == "The camera is not available."
    assert app.notice == ""
    image = app.render()
    assert image.getpixel((WIDTH // 2, HEIGHT - 20))[:3] != (12, 14, 18)

    app.scan_kind = "descriptor"
    app.camera_unavailable = False
    assert app.scan_prompt() == "Point the camera at one wallet descriptor QR code."
    app.camera_unavailable = True
    assert app.scan_prompt() == "The camera is not available."


def test_a_blank_picture_has_no_qr_text():
    assert read_qr(Image.new("RGB", (40, 40), "white")) is None

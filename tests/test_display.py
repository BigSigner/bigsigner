import pytest
from PIL import Image

from bigsigner.hardware.display import pack_image

# Red at bit 11, green at bit 5, blue at bit 0. The Pi's 16-bit HDMI layout.
RGB565 = ((11, 5), (5, 6), (0, 5))
# Red in byte 2, green in byte 1, blue in byte 0. The 32-bit layout this app already uses.
BGRX = ((16, 8), (8, 8), (0, 8))


def test_16_bit_red_is_rgb565():
    image = Image.new("RGB", (1, 1), (255, 0, 0))
    assert pack_image(image, 2, 16, RGB565) == b"\x00\xf8"


def test_16_bit_green_and_blue_keep_their_places():
    green = Image.new("RGB", (1, 1), (0, 255, 0))
    blue = Image.new("RGB", (1, 1), (0, 0, 255))
    assert pack_image(green, 2, 16, RGB565) == b"\xe0\x07"
    assert pack_image(blue, 2, 16, RGB565) == b"\x1f\x00"


def test_every_16_bit_path_packs_the_same_bytes():
    """Pillow, numpy, and the Python loop must agree, so a Pillow upgrade cannot shift colors."""
    from bigsigner.hardware import display

    image = Image.effect_noise((37, 11), 90).convert("RGB")
    image.paste(Image.new("RGB", (5, 5), (24, 92, 184)), (3, 3))
    expected = display._pack_image_slow(image, 37 * 2, 16, RGB565)
    pillow = display._pack_image_pillow(image, 37 * 2, 16, RGB565)
    assert pillow is None or pillow == expected
    np = pytest.importorskip("numpy")
    assert display._pack_image_fast(np, image, 37 * 2, 16, RGB565) == expected
    assert pack_image(image, 37 * 2, 16, RGB565) == expected


def test_32_bit_red_is_byte_two():
    image = Image.new("RGB", (1, 1), (255, 0, 0))
    assert pack_image(image, 4, 32, BGRX) == b"\x00\x00\xff\x00"

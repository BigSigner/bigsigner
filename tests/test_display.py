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


def test_32_bit_red_is_byte_two():
    image = Image.new("RGB", (1, 1), (255, 0, 0))
    assert pack_image(image, 4, 32, BGRX) == b"\x00\x00\xff\x00"

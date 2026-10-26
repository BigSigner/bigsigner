"""HDMI framebuffer, following the bigsigner-os touch demo."""

import glob
import os
import struct

FB_DEV = "/dev/fb0"
FBIOGET_VSCREENINFO = 0x4600


def framebuffer_available() -> bool:
    return os.path.exists(FB_DEV)


def framebuffer_info(handle):
    import fcntl

    var = bytearray(160)
    fcntl.ioctl(handle, FBIOGET_VSCREENINFO, var)
    xres, yres, _xv, _yv, _xo, _yo, bpp, _gray = struct.unpack_from("8I", var)

    def bitfield(index):
        offset, length, _msb = struct.unpack_from("3I", var, 32 + index * 12)
        return offset, length

    stride = int(open("/sys/class/graphics/fb0/stride", encoding="ascii").read().strip())
    # The scanline length is the one the hardware scans. Prefer it when bits_per_pixel disagrees.
    if xres and stride % xres == 0:
        stride_bpp = (stride // xres) * 8
        if stride_bpp in (16, 32):
            bpp = stride_bpp
    return xres, yres, stride, bpp, (bitfield(0), bitfield(1), bitfield(2))


def silence_console():
    """Stop the kernel console from drawing over the picture. Failures are ignored."""
    try:
        with open("/sys/class/graphics/fbcon/cursor_blink", "w", encoding="ascii") as handle:
            handle.write("0\n")
    except OSError:
        pass
    for path in glob.glob("/sys/class/vtconsole/vtcon*/bind"):
        try:
            with open(path, "w", encoding="ascii") as handle:
                handle.write("0\n")
        except OSError:
            pass
    try:
        tty = os.open("/dev/tty1", os.O_RDWR)
    except OSError:
        return
    try:
        import fcntl

        fcntl.ioctl(tty, 0x4B3A, 1)  # KDSETMODE, KD_GRAPHICS
    except OSError:
        pass
    finally:
        os.close(tty)


def pack_image(image, stride, bpp, channels):
    """Pack an RGB picture into the framebuffer pixel format.

    16-bit frames are RGB565, which is what bigsigner-os asks the firmware for.
    32-bit frames are kept so a card built before that change still shows the
    right colors. Pillow converts RGB565 in C, about seven times faster than
    numpy on the Pi Zero. numpy is next. A Python loop is the fallback.
    """
    packed = _pack_image_pillow(image, stride, bpp, channels)
    if packed is not None:
        return packed
    try:
        import numpy as np
    except ImportError:
        np = None
    if np is not None:
        packed = _pack_image_fast(np, image, stride, bpp, channels)
        if packed is not None:
            return packed
    return _pack_image_slow(image, stride, bpp, channels)


def _pack_image_pillow(image, stride, bpp, channels):
    """RGB565 through Pillow's BGR;16 raw mode, when this Pillow still has it.

    The mode was removed in Pillow 12. The device image ships Pillow 10 or 11.
    """
    if bpp != 16 or channels != ((11, 5), (5, 6), (0, 5)):
        return None
    width, height = image.size
    if stride != width * 2:
        return None
    import warnings

    rgb = image if image.mode == "RGB" else image.convert("RGB")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return rgb.convert("BGR;16").tobytes()
    except (ValueError, KeyError, AttributeError):
        return None


def _pack_image_fast(np, image, stride, bpp, channels):
    (red_off, red_len), (green_off, green_len), (blue_off, blue_len) = channels
    raw = image.tobytes() if image.mode == "RGB" else image.convert("RGB").tobytes()
    rgb = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3)
    width, height = image.size
    if bpp == 16 and (red_len, green_len, blue_len) == (5, 6, 5):
        red = rgb[:, 0].astype(np.uint16)
        green = rgb[:, 1].astype(np.uint16)
        blue = rgb[:, 2].astype(np.uint16)
        pixels = ((red >> 3) << red_off) | ((green >> 2) << green_off) | ((blue >> 3) << blue_off)
        packed = np.ascontiguousarray(pixels, dtype="<u2").tobytes()
        row_bytes = width * 2
    elif bpp == 32 and (red_len, green_len, blue_len) == (8, 8, 8) and {red_off, green_off, blue_off} <= {0, 8, 16}:
        out = np.zeros((rgb.shape[0], 4), dtype=np.uint8)
        out[:, red_off // 8] = rgb[:, 0]
        out[:, green_off // 8] = rgb[:, 1]
        out[:, blue_off // 8] = rgb[:, 2]
        packed = out.tobytes()
        row_bytes = width * 4
    else:
        return None
    if stride == row_bytes:
        return packed
    frame = bytearray(stride * height)
    for y in range(height):
        start = y * row_bytes
        frame[y * stride : y * stride + row_bytes] = packed[start : start + row_bytes]
    return bytes(frame)


def _pack_image_slow(image, stride, bpp, channels):
    red, green, blue = channels

    def place(channel, offset, length):
        if length < 8:
            channel = channel >> (8 - length)
        return channel << offset

    raw = image.convert("RGB")
    width, height = raw.size
    pixels = raw.tobytes()
    frame = bytearray(stride * height)
    bytes_per = 4 if bpp == 32 else 2
    for y in range(height):
        for x in range(width):
            pos = (y * width + x) * 3
            r, g, b = pixels[pos], pixels[pos + 1], pixels[pos + 2]
            value = place(r, *red) | place(g, *green) | place(b, *blue)
            start = y * stride + x * bytes_per
            frame[start : start + bytes_per] = value.to_bytes(bytes_per, "little")
    return bytes(frame)

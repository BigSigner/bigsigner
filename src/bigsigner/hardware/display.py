"""HDMI framebuffer, following the bigsigner-os touch demo."""

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
    return xres, yres, stride, bpp, (bitfield(0), bitfield(1), bitfield(2))


def pack_image(image, stride, bpp, channels):
    red, green, blue = channels

    def place(channel, offset, length):
        values = channel
        if length < 8:
            values = values >> (8 - length)
        return values << offset

    raw = image.convert("RGB").resize((image.width, image.height))
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
            encoded = value.to_bytes(bytes_per, "little")
            frame[start : start + bytes_per] = encoded
    return bytes(frame)

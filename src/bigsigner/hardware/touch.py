"""Read the ADS7846 touchscreen with the standard library."""

import glob
import os
import select
import struct

EV_KEY = 0x01
EV_ABS = 0x03
ABS_X = 0x00
ABS_Y = 0x01
BTN_TOUCH = 0x14A
EVENT_FORMAT = "llHHi"
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)
EVIOCGABS = lambda axis: 0x80184540 + axis


def find_touch():
    for path in sorted(glob.glob("/dev/input/event*")):
        name_path = f"/sys/class/input/{os.path.basename(path)}/device/name"
        try:
            name = open(name_path, encoding="ascii").read().strip().lower()
        except OSError:
            continue
        if "ads7846" in name or "touchscreen" in name:
            return path
    return None


def axis_range(handle, axis):
    import fcntl

    info = bytearray(24)
    fcntl.ioctl(handle, EVIOCGABS(axis), info)
    _value, minimum, maximum = struct.unpack_from("iii", info)
    return minimum, maximum


def scale(value, low, high, pixels):
    if high == low:
        return 0
    value = max(low, min(high, value))
    return int((value - low) * (pixels - 1) / (high - low))


def read_points(handle, width, height, x_range, y_range, wait=None):
    """Yield ("down", x, y), ("move", x, y), ("up", x, y), or None on timeout.

    A timeout means no touch arrived before wait() elapsed, so the screen can redraw.
    """
    raw = [None, None]
    touching = False
    sent_down = False
    last = (0, 0)
    while True:
        timeout = wait() if callable(wait) else wait
        if timeout is not None:
            ready, _, _ = select.select([handle], [], [], timeout)
            if not ready:
                yield None
                continue
        packet = os.read(handle, EVENT_SIZE * 64)
        if not packet:
            return
        for offset in range(0, len(packet) - EVENT_SIZE + 1, EVENT_SIZE):
            _sec, _usec, ev_type, code, value = struct.unpack_from(EVENT_FORMAT, packet, offset)
            if ev_type == EV_KEY and code == BTN_TOUCH:
                if value:
                    touching = True
                elif sent_down:
                    yield ("up", last[0], last[1])
                    touching = False
                    sent_down = False
                else:
                    touching = False
                continue
            if ev_type != EV_ABS:
                continue
            if code == ABS_X:
                raw[0] = value
            elif code == ABS_Y:
                raw[1] = value
            if raw[0] is None or raw[1] is None or not touching:
                continue
            last = (
                scale(raw[0], x_range[0], x_range[1], width),
                scale(raw[1], y_range[0], y_range[1], height),
            )
            raw = [None, None]
            if sent_down:
                yield ("move", last[0], last[1])
            else:
                sent_down = True
                yield ("down", last[0], last[1])

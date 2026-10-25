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
# Half of a seed-keyboard key. Drift inside this stays on the key that was pressed.
_HOLD = 21


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


class _Contact:
    """Coordinates for one finger, across the events in a report.

    The ADS7846 sends X and Y before BTN_TOUCH. Those coordinates belong to the press.
    """

    def __init__(self, width, height, x_range, y_range):
        self.width = width
        self.height = height
        self.x_range = x_range
        self.y_range = y_range
        self.raw = [None, None]
        self.touching = False
        self.sent_down = False
        self.anchor = (0, 0)
        self.last = (0, 0)

    def feed(self, packet: bytes) -> list[tuple]:
        actions = []
        for offset in range(0, len(packet) - EVENT_SIZE + 1, EVENT_SIZE):
            _sec, _usec, ev_type, code, value = struct.unpack_from(EVENT_FORMAT, packet, offset)
            if ev_type == EV_KEY and code == BTN_TOUCH:
                if value:
                    self.touching = True
                    self._press(actions)
                elif self.sent_down:
                    point = self.anchor if self._near(self.last) else self.last
                    actions.append(("up", point[0], point[1]))
                    self.touching = False
                    self.sent_down = False
                else:
                    self.touching = False
                continue
            if ev_type != EV_ABS:
                continue
            if code == ABS_X:
                self.raw[0] = value
            elif code == ABS_Y:
                self.raw[1] = value
            else:
                continue
            if self.touching:
                self._press(actions)
        return actions

    def _press(self, actions: list):
        if self.raw[0] is None or self.raw[1] is None:
            return
        self.last = (
            scale(self.raw[0], self.x_range[0], self.x_range[1], self.width),
            scale(self.raw[1], self.y_range[0], self.y_range[1], self.height),
        )
        self.raw = [None, None]
        if not self.sent_down:
            self.anchor = self.last
            self.sent_down = True
            actions.append(("down", self.last[0], self.last[1]))
            return
        if self._near(self.last):
            return
        actions.append(("move", self.last[0], self.last[1]))

    def _near(self, point: tuple[int, int]) -> bool:
        return abs(point[0] - self.anchor[0]) < _HOLD and abs(point[1] - self.anchor[1]) < _HOLD


def coalesce(actions: list[tuple]) -> list[tuple]:
    """One redraw per burst: the press, the last move, and the release."""
    down = move = up = None
    for kind, x, y in actions:
        if kind == "down":
            down = (x, y)
            move = None
        elif kind == "move":
            move = (x, y)
        elif kind == "up":
            up = (x, y)
    if down is not None and up is not None and move is None:
        return [("up", up[0], up[1])]
    result = []
    if down is not None:
        result.append(("down", down[0], down[1]))
    if move is not None:
        result.append(("move", move[0], move[1]))
    if up is not None:
        result.append(("up", up[0], up[1]))
    return result


def read_points(handle, width, height, x_range, y_range, wait=None):
    """Yield ("down", x, y), ("move", x, y), ("up", x, y), or None on timeout.

    A timeout means no touch arrived before wait() elapsed, so the screen can redraw.
    One finger report is one yield, not one yield per input event. The device is
    read without blocking, the same way the touch demo drains its event device.
    """
    import fcntl

    flags = fcntl.fcntl(handle, fcntl.F_GETFL)
    fcntl.fcntl(handle, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    contact = _Contact(width, height, x_range, y_range)
    while True:
        timeout = wait() if callable(wait) else wait
        if timeout is not None:
            ready, _, _ = select.select([handle], [], [], timeout)
            if not ready:
                yield None
                continue
        actions = []
        while True:
            try:
                packet = os.read(handle, EVENT_SIZE * 64)
            except BlockingIOError:
                break
            if not packet:
                return
            actions.extend(contact.feed(packet))
        for action in coalesce(actions):
            yield action

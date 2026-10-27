"""Read the ADS7846 touchscreen with the standard library."""

import fcntl
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
        self.left_hold = False
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
                    point = self.anchor if not self.left_hold else self.last
                    actions.append(("up", point[0], point[1]))
                    self.touching = False
                    self.sent_down = False
                    self.left_hold = False
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
            self.left_hold = False
            actions.append(("down", self.last[0], self.last[1]))
            return
        # Jitter around the press is not a move. After the finger leaves that
        # box, later points are reported even when it comes back.
        if not self.left_hold and self._near(self.last):
            return
        self.left_hold = True
        actions.append(("move", self.last[0], self.last[1]))

    def _near(self, point: tuple[int, int]) -> bool:
        return abs(point[0] - self.anchor[0]) < _HOLD and abs(point[1] - self.anchor[1]) < _HOLD


def coalesce(actions: list[tuple]) -> list[tuple]:
    """Collapse moves inside one gesture. Separate taps in the same burst all stay.

    A finger that taps twice while the screen is busy is two keys, not one.
    """
    result = []
    down = move = None
    started = False

    def flush(up):
        nonlocal down, move, started
        if not started:
            return
        if down is not None and up is not None and move is None:
            result.append(("up", up[0], up[1]))
        else:
            if down is not None:
                result.append(("down", down[0], down[1]))
            if move is not None:
                result.append(("move", move[0], move[1]))
            if up is not None:
                result.append(("up", up[0], up[1]))
        down = move = None
        started = False

    for kind, x, y in actions:
        if kind == "down":
            if started:
                flush(None)
            started = True
            down = (x, y)
            move = None
        elif kind == "move":
            started = True
            move = (x, y)
        elif kind == "up":
            started = True
            flush((x, y))
    flush(None)
    return result


def tap_line(line: bytes):
    """One injected point. "x y" is a tap. "down x y" is that phase."""
    parts = line.decode("ascii", errors="replace").split()
    try:
        if len(parts) == 2:
            return ("up", int(parts[0]), int(parts[1]))
        if len(parts) == 3 and parts[0] in ("down", "move", "up"):
            return (parts[0], int(parts[1]), int(parts[2]))
    except ValueError:
        return None
    return None


def read_points(handle, width, height, x_range, y_range, wait=None, inject=None):
    """Yield ("down", x, y), ("move", x, y), ("up", x, y), or None on timeout.

    A timeout means no touch arrived before wait() elapsed, so the screen can redraw.
    A wait of None sleeps until a finger arrives. The process must not spin on the
    device: the Pi Zero has one core, and the touch controller's kernel thread
    needs it. One finger report is one yield, not one yield per input event. The
    device is read without blocking, the same way the touch demo drains it.
    inject is an optional pipe of tap lines, so a test can press without the panel.
    """
    flags = fcntl.fcntl(handle, fcntl.F_GETFL)
    fcntl.fcntl(handle, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    if inject is not None:
        flags = fcntl.fcntl(inject, fcntl.F_GETFL)
        fcntl.fcntl(inject, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    contact = _Contact(width, height, x_range, y_range)
    pending = bytearray()
    while True:
        timeout = wait() if callable(wait) else wait
        watch = [handle] if inject is None else [handle, inject]
        ready, _, _ = select.select(watch, [], [], timeout)
        if not ready:
            # The pen is still down and the controller has gone quiet. Keep the
            # gesture alive so a long hold is not mistaken for the end of a tap.
            if contact.touching and contact.sent_down:
                yield ("hold", contact.last[0], contact.last[1])
            else:
                yield None
            continue
        if inject is not None and inject in ready:
            try:
                chunk = os.read(inject, 256)
            except BlockingIOError:
                chunk = b""
            if chunk:
                pending.extend(chunk)
                while b"\n" in pending:
                    line, _, rest = bytes(pending).partition(b"\n")
                    pending[:] = rest
                    point = tap_line(line)
                    if point is not None:
                        yield point
        if handle not in ready:
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

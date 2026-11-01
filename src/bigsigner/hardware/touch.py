"""Read the ADS7846 touchscreen with the standard library."""

import fcntl
import glob
import os
import select
import struct

from ..rpc import feed_lines

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
_MIN_MOVEMENT = 5
# A gap longer than this between reports drops a gesture that never lifted.
_LONG_STALE = 2
_SHORT_STALE = 0.6
LIFTED = 0
DETECTING = 1
DETECTED = 2
MOVING = 3


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
    """One finger. The button arrives first, then X and Y, until the lift."""

    def __init__(self, width, height, x_range, y_range):
        self.width = width
        self.height = height
        self.x_range = x_range
        self.y_range = y_range
        self._stamp = None
        self.anchor = (0, 0)
        self.last = (0, 0)
        self._reset()

    def _reset(self) -> None:
        self.touching = LIFTED
        self.raw = [None, None]

    def feed(self, packet: bytes) -> list[tuple]:
        actions = []
        for offset in range(0, len(packet) - EVENT_SIZE + 1, EVENT_SIZE):
            sec, usec, ev_type, code, value = struct.unpack_from(EVENT_FORMAT, packet, offset)
            lift = ev_type == EV_KEY and code == BTN_TOUCH and not value
            # Reset the gesture if no event has arrived for a while.
            # A still finger sends nothing until the lift, so if no event has arrived for a short while,
            # but then a lift event arrives, the gesture is still valid.
            gap = self._gap(sec, usec)
            if gap > _LONG_STALE or (gap > _SHORT_STALE and not lift):
                self._reset()
            self._stamp = (sec, usec)
            if ev_type == EV_KEY and code == BTN_TOUCH:
                if value:
                    self.touching = DETECTING
                    self.raw = [None, None]
                else:
                    if self.touching in (DETECTED, MOVING):
                        actions.append(("up", self.last[0], self.last[1]))
                    self._reset()
                continue
            if ev_type != EV_ABS:
                continue
            if self.touching == LIFTED:
                continue
            if code == ABS_X:
                self.raw[0] = value
            elif code == ABS_Y:
                self.raw[1] = value
            else:
                continue
            if self.raw[0] is None or self.raw[1] is None:
                continue
            self._sample(actions)
        return actions

    def _sample(self, actions: list) -> None:
        self.last = (
            scale(self.raw[0], self.x_range[0], self.x_range[1], self.width),
            scale(self.raw[1], self.y_range[0], self.y_range[1], self.height),
        )
        self.raw = [None, None]
        if self.touching == DETECTING:
            actions.append(("down", self.last[0], self.last[1]))
            self.anchor = self.last
            self.touching = DETECTED
            return
        if self.touching == DETECTED and self._far(self.last, _HOLD):
            self.touching = MOVING
            self.anchor = self.last
            actions.append(("move", self.last[0], self.last[1]))
            return
        if self.touching == MOVING and self._far(self.last, _MIN_MOVEMENT):
            self.anchor = self.last
            actions.append(("move", self.last[0], self.last[1]))

    def _far(self, point: tuple[int, int], dist: int) -> bool:
        return abs(point[0] - self.anchor[0]) > dist or abs(point[1] - self.anchor[1]) > dist

    def _gap(self, sec: int, usec: int) -> float:
        """Seconds and microseconds are one clock. The microseconds field wraps each second."""
        if self._stamp is None:
            return False
        prev_sec, prev_usec = self._stamp
        elapsed = (sec - prev_sec) + (usec - prev_usec) / 1_000_000
        return elapsed


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


def _nonblocking(handle):
    """A later read returns immediately when this pipe has nothing waiting."""
    if handle is None:
        return
    flags = fcntl.fcntl(handle, fcntl.F_GETFL)
    fcntl.fcntl(handle, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def read_points(handle, width, height, x_range, y_range, wait=None, inject=None, rpc=None):
    """Yield ("down", x, y), ("move", x, y), ("up", x, y), ("rpc", line), or None.

    A timeout means no touch arrived before wait() elapsed, so the screen can redraw.
    A wait of None sleeps until a finger arrives. The process must not spin on the
    device: the Pi Zero has one core, and the touch controller's kernel thread
    needs it. One finger report is one yield, not one yield per input event. The
    device is read without blocking, the same way the touch demo drains it.
    inject is an optional pipe of tap lines, so a test can press without the panel.
    rpc is an optional pipe of command lines. ("rpc-error", message) means a
    line was longer than the pipe allows and was dropped.
    """
    contact = None
    if handle is not None:
        _nonblocking(handle)
        contact = _Contact(width, height, x_range, y_range)
    _nonblocking(inject)
    _nonblocking(rpc)
    pending = bytearray()
    rpc_pending = bytearray()
    while True:
        timeout = wait() if callable(wait) else wait
        watch = [item for item in (handle, inject, rpc) if item is not None]
        if not watch:
            return
        ready, _, _ = select.select(watch, [], [], timeout)
        if not ready:
            # The pen is still down and the controller has gone quiet. Keep the
            # gesture alive so a long hold is not mistaken for the end of a tap.
            if contact is not None and contact.touching != LIFTED and contact.last is not None:
                yield ("hold", contact.last[0], contact.last[1])
            else:
                yield None
            continue
        if rpc is not None and rpc in ready:
            try:
                chunk = os.read(rpc, 4096)
            except BlockingIOError:
                chunk = b""
            if chunk:
                lines, overflow = feed_lines(rpc_pending, chunk)
                if overflow:
                    yield ("rpc-error", "command line was too long")
                for line in lines:
                    yield ("rpc", line)
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
        if handle is None or handle not in ready:
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

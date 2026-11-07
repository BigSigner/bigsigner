"""Display hosts start a fixed guard after presenting a tap's result."""

import os
import struct
from types import SimpleNamespace

import pytest
from PIL import Image

from bigsigner.hardware import panel
from bigsigner.hardware.touch import ABS_X, ABS_Y, BTN_TOUCH, EVENT_FORMAT, EV_ABS, EV_KEY, _Contact, coalesce, flush_touch
from bigsigner.ui.app import App


@pytest.fixture
def guarded_app(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("bigsigner.ui.app.time.monotonic", lambda: clock[0])
    app = App()
    app.screen = "keys"
    actions = []
    monkeypatch.setattr(app, "_act", actions.append)
    app.hits = [{"action": "next", "box": (0, 100, 480, 800)}]
    return app, clock, actions


def _present(app):
    guarded = app.frame_presented()
    discard = app.take_queued_touch_discard()
    assert guarded == discard
    return guarded


def _click(app):
    app.pointer_down(240, 400)
    return app.pointer_up(240, 400)


def test_guard_starts_after_slow_action_and_slow_display_write(guarded_app):
    app, clock, actions = guarded_app
    assert _click(app)
    assert actions == ["next"]
    clock[0] += 10  # Computation, rendering and framebuffer write.
    assert _present(app)
    clock[0] += 0.249
    assert not app.tap(240, 400)
    assert not _click(app)
    assert not _present(app)  # Ignored input cannot restart the clock.
    assert actions == ["next"]
    clock[0] = 110.25
    assert _click(app)
    assert actions == ["next", "next"]
    assert _present(app)
    assert not _click(app)  # The second accepted action has its own gap.


def test_press_started_during_guard_cannot_click_after_it(guarded_app):
    app, clock, actions = guarded_app
    _click(app)
    _present(app)
    clock[0] += 0.1
    app.pointer_down(240, 400)
    clock[0] += 1
    assert not app.pointer_up(240, 400)
    assert actions == ["next"]
    assert _click(app)
    assert actions == ["next", "next"]


def test_scroll_and_passive_redraws_do_not_arm_guard(guarded_app):
    app, clock, actions = guarded_app
    app.scroll_max["keys"] = 1000
    app.pointer_down(240, 600)
    assert app.pointer_move(240, 300)
    assert not _present(app)
    assert app.pointer_up(240, 300)
    assert not _present(app)
    clock[0] += 1  # The separate existing scroll quiet period.
    assert _click(app)
    assert actions == ["next"]
    _present(app)
    clock[0] += 0.24
    assert not _present(app)
    clock[0] += 0.02
    assert _click(app)


def test_deferred_work_starts_a_fresh_gap_when_its_result_is_presented(guarded_app):
    app, clock, actions = guarded_app
    _click(app)
    _present(app)  # Loading.
    clock[0] += 10
    app._arm_search_touch_quiet()  # Deferred work finishes.
    clock[0] += 10  # Slow result paint.
    assert _present(app)
    assert not _click(app)
    clock[0] += 0.25
    assert _click(app)
    assert actions == ["next", "next"]


def test_qr_placeholder_keeps_the_action_pending_until_the_qr_is_ready(guarded_app):
    app, clock, actions = guarded_app
    _click(app)
    app._qr_strip_due = True
    assert _present(app)
    clock[0] += 10
    app._qr_strip_due = False
    assert _present(app)
    assert not _click(app)
    clock[0] += 0.25
    assert _click(app)
    assert actions == ["next", "next"]


def test_queued_event_times_cannot_bypass_the_current_clock(guarded_app):
    app, clock, actions = guarded_app
    # Both taps were already parsed before the first action started. The
    # event timestamps are deliberately far apart and unrelated to this clock.
    contact = _Contact(480, 800, (0, 479), (0, 799))
    packet = b"".join(
        struct.pack(EVENT_FORMAT, sec, 0, kind, code, value)
        for sec in (1, 2)
        for kind, code, value in (
            (EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 240),
            (EV_ABS, ABS_Y, 400), (EV_KEY, BTN_TOUCH, 0),
        )
    )
    points = coalesce(contact.feed(packet) + contact.finish_lift(sec=3))
    assert [point[0] for point in points] == ["down", "up", "down", "up"]
    for phase, x, y in points:
        if phase == "down":
            app.pointer_down(x, y)
        elif app.pointer_up(x, y):
            clock[0] += 5
            _present(app)
    assert actions == ["next"]


def test_device_queue_is_drained_after_presenting_an_action(guarded_app):
    app, _clock, _actions = guarded_app
    reader, writer = os.pipe()
    try:
        _click(app)
        stale = struct.pack(EVENT_FORMAT, 1, 0, EV_KEY, BTN_TOUCH, 1)
        os.write(writer, stale)
        assert app.frame_presented()
        assert app.take_queued_touch_discard()
        assert flush_touch(reader) == len(stale)
        assert flush_touch(reader) == 0
    finally:
        os.close(reader)
        os.close(writer)


def test_panel_guards_after_the_write_and_does_not_repaint_rejected_taps(guarded_app, monkeypatch):
    app, clock, actions = guarded_app
    writes, drains = [], []

    def write(_fd, _payload):
        clock[0] += 5  # Painting can itself outlast the entire guard period.
        writes.append(clock[0])

    def points(*_args, **_kwargs):
        yield ("down", 240, 400)
        yield ("up", 240, 400)
        yield ("down", 240, 400)  # Already parsed events from the same burst.
        yield ("up", 240, 400)
        clock[0] += 0.25
        yield ("down", 240, 400)
        yield ("up", 240, 400)

    monkeypatch.setattr(panel, "App", lambda: app)
    monkeypatch.setattr(panel, "LiveCamera", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(panel, "os", SimpleNamespace(
        open=lambda *_args: 10, O_RDWR=os.O_RDWR, O_RDONLY=os.O_RDONLY,
        O_NONBLOCK=os.O_NONBLOCK, SEEK_SET=os.SEEK_SET, environ={},
        lseek=lambda *_args: None, write=write,
    ))
    monkeypatch.setattr(panel, "framebuffer_info", lambda _fd: (480, 800, 1920, 32, ()))
    monkeypatch.setattr(panel, "find_touch", lambda: "/fake/touch")
    monkeypatch.setattr(panel, "axis_range", lambda *_args: (0, 799))
    monkeypatch.setattr(panel, "open_rpc_pipe", lambda: None)
    monkeypatch.setattr(panel, "silence_console", lambda: None)
    monkeypatch.setattr(panel, "_kmsg", lambda _message: None)
    monkeypatch.setattr(panel, "_with_camera", lambda *_args: Image.new("RGB", (480, 800)))
    monkeypatch.setattr(panel, "pack_image", lambda *_args: b"frame")
    monkeypatch.setattr(panel, "read_points", points)
    monkeypatch.setattr(panel, "flush_touch", lambda _fd: drains.append(clock[0]) or 0)
    panel.run_panel()
    assert actions == ["next", "next"]
    assert len(writes) == 3  # Boot plus two accepted actions.
    assert drains == writes[1:]
    assert app._search_touch_at == writes[-1]

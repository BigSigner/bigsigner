import os
import struct
import threading
import time

from bigsigner.hardware.touch import (
    ABS_PRESSURE,
    ABS_X,
    ABS_Y,
    BTN_TOUCH,
    DETECTED,
    EVENT_FORMAT,
    EV_ABS,
    EV_KEY,
    EV_SYN,
    _Contact,
    coalesce,
    read_points,
)


def _packet(*events, sec=0, usec=0):
    return b"".join(struct.pack(EVENT_FORMAT, sec, usec, ev_type, code, value) for ev_type, code, value in events)


def _contact():
    return _Contact(480, 800, (0, 479), (0, 799))


def test_a_press_is_the_sample_after_the_button():
    contact = _contact()
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 1))) == []
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200))) == [("down", 100, 200)]
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == []
    assert contact.finish_lift(sec=0, usec=100_000) == [("up", 100, 200)]
    assert contact.touching == 0
    assert contact.anchor == (100, 200)


def test_a_sample_before_the_button_is_ignored():
    contact = _contact()
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200))) == []
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 1))) == []
    assert contact.feed(_packet((EV_ABS, ABS_X, 30), (EV_ABS, ABS_Y, 40))) == [("down", 30, 40)]


def test_a_point_far_from_the_press_is_a_move():
    contact = _contact()
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 100),
    )) == [("down", 100, 100)]
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 500))) == [("move", 100, 500)]
    assert contact.touching == 3


def test_a_gap_before_a_new_press_drops_the_old_gesture():
    contact = _contact()
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 10), (EV_ABS, ABS_Y, 10), sec=10))
    assert contact.anchor == (10, 10)
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), sec=11))
    assert contact.touching == 1
    assert contact.last == (10, 10)
    assert contact.feed(_packet((EV_ABS, ABS_X, 80), (EV_ABS, ABS_Y, 90), sec=11)) == [("down", 80, 90)]
    assert contact.anchor == (80, 90)
    assert contact.last == (80, 90)


def test_a_late_lift_still_ends_the_gesture():
    contact = _contact()
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 10), (EV_ABS, ABS_Y, 20), sec=5))
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0), sec=6)) == []
    assert contact.finish_lift(sec=6, usec=100_000) == [("up", 10, 20)]
    assert contact.touching == 0


def test_a_burst_of_moves_becomes_one_position():
    contact = _contact()
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 10), (EV_ABS, ABS_Y, 10)))
    moves = []
    for value in (20, 40, 80):
        moves.extend(contact.feed(_packet((EV_ABS, ABS_X, value), (EV_ABS, ABS_Y, value))))
    assert coalesce(moves) == [("move", 80, 80)]


def test_a_finger_that_comes_back_keeps_reporting_moves():
    contact = _contact()
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 200),
    )) == [("down", 100, 200)]
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 280))) == [("move", 100, 280)]
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 205))) == [("move", 100, 205)]
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == []
    assert contact.finish_lift(sec=0, usec=100_000) == [("up", 100, 205)]


def test_a_lift_leaves_the_anchor_until_the_next_press():
    contact = _contact()
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200)))
    assert contact.anchor == (100, 200)
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 0)))
    assert contact.anchor == (100, 200)
    assert contact.touching == DETECTED
    assert contact.finish_lift(sec=0, usec=100_000) == [("up", 100, 200)]
    assert contact.touching == 0
    assert contact.anchor == (100, 200)
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 4), (EV_ABS, ABS_Y, 5))) == [("down", 4, 5)]
    assert contact.anchor == (4, 5)


def test_a_small_drift_is_not_a_move():
    contact = _contact()
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 200),
    )) == [("down", 100, 200)]
    assert contact.feed(_packet((EV_ABS, ABS_X, 115), (EV_ABS, ABS_Y, 210))) == []
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == []
    assert contact.finish_lift(sec=0, usec=100_000) == [("up", 115, 210)]


def test_the_reader_sleeps_until_a_touch_when_nothing_is_pending():
    """With no timeout the loop must block in select, not spin on the device."""
    reader, writer = os.pipe()
    polls = []

    def wait():
        polls.append(time.monotonic())
        return None

    def tap_later():
        time.sleep(0.3)
        os.write(writer, _packet(
            (EV_KEY, BTN_TOUCH, 1),
            (EV_ABS, ABS_X, 30),
            (EV_ABS, ABS_Y, 40),
            (EV_KEY, BTN_TOUCH, 0),
        ))

    threading.Thread(target=tap_later, daemon=True).start()
    try:
        points = read_points(reader, 480, 800, (0, 479), (0, 799), wait=wait)
        first = next(points)
        second = next(points)
    finally:
        os.close(reader)
        os.close(writer)
    assert first == ("down", 30, 40)
    assert second == ("up", 30, 40)
    assert len(polls) == 2


def test_two_taps_in_one_burst_stay_two_taps():
    actions = [
        ("down", 10, 10),
        ("up", 10, 10),
        ("down", 20, 20),
        ("up", 22, 20),
    ]
    assert coalesce(actions) == [
        ("down", 10, 10),
        ("up", 10, 10),
        ("down", 20, 20),
        ("up", 22, 20),
    ]


def test_a_seed_line_wakes_the_reader_without_a_touch():
    touch_reader, touch_writer = os.pipe()
    seed_reader, seed_writer = os.pipe()
    os.write(seed_writer, b"one two\n")

    def wait():
        return 0.2

    try:
        point = next(read_points(touch_reader, 480, 800, (0, 479), (0, 799), wait=wait, rpc=seed_reader))
    finally:
        os.close(touch_reader)
        os.close(touch_writer)
        os.close(seed_reader)
        os.close(seed_writer)
    assert point == ("rpc", "one two")


def test_a_tap_in_one_burst_is_a_single_release():
    contact = _contact()
    actions = contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 30),
        (EV_ABS, ABS_Y, 40),
        (EV_KEY, BTN_TOUCH, 0),
    ))
    assert actions == [("down", 30, 40)]
    assert contact.finish_lift(sec=0, usec=100_000) == [("up", 30, 40)]


def test_a_lift_that_returns_within_100ms_stays_one_gesture():
    contact = _contact()
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 200),
        sec=1,
    )) == [("down", 100, 200)]
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0), sec=1, usec=10_000)) == []
    assert contact.finish_lift(sec=1, usec=50_000) == []
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 260),
        sec=1,
        usec=50_000,
    )) == [("move", 100, 260)]
    assert contact.touching == 3
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0), sec=1, usec=60_000)) == []
    assert contact.finish_lift(sec=1, usec=160_000) == [("up", 100, 260)]


def test_a_coordinate_during_the_lift_wait_keeps_the_gesture():
    contact = _contact()
    contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 1),
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 200),
        sec=2,
    ))
    assert contact.feed(_packet(
        (EV_KEY, BTN_TOUCH, 0),
        (EV_ABS, ABS_PRESSURE, 0),
        (EV_SYN, 0, 0),
        sec=2,
        usec=5_000,
    )) == []
    assert contact.finish_lift(sec=2, usec=50_000) == []
    assert contact.feed(_packet(
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 240),
        sec=2,
        usec=40_000,
    )) == [("move", 100, 240)]
    assert contact.finish_lift(sec=2, usec=140_000) == []
    assert contact.touching == 3


def test_search_timer_runs_between_down_and_debounced_up(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("bigsigner.hardware.touch.time.monotonic", lambda: clock[0])
    reader, writer = os.pipe()
    try:
        os.write(writer, _packet(
            (EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 30),
            (EV_ABS, ABS_Y, 40), (EV_KEY, BTN_TOUCH, 0),
        ))
        points = read_points(reader, 480, 800, (0, 479), (0, 799), wait=lambda: 0)
        assert next(points) == ("down", 30, 40)
        assert next(points) is None  # Background work can run without ending the press.
        clock[0] += 0.1
        assert next(points) == ("up", 30, 40)
    finally:
        os.close(reader)
        os.close(writer)

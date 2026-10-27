import os
import struct
import threading
import time

from bigsigner.hardware.touch import BTN_TOUCH, EVENT_FORMAT, EV_ABS, EV_KEY, ABS_X, ABS_Y, _Contact, coalesce, read_points


def _packet(*events):
    return b"".join(struct.pack(EVENT_FORMAT, 0, 0, ev_type, code, value) for ev_type, code, value in events)


def _contact():
    return _Contact(480, 800, (0, 479), (0, 799))


def test_a_press_uses_coordinates_that_arrive_before_the_button():
    contact = _contact()
    actions = contact.feed(_packet(
        (EV_ABS, ABS_X, 100),
        (EV_ABS, ABS_Y, 200),
        (EV_KEY, BTN_TOUCH, 1),
    ))
    assert actions == [("down", 100, 200)]
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == [("up", 100, 200)]


def test_a_burst_of_moves_becomes_one_position():
    contact = _contact()
    contact.feed(_packet((EV_KEY, BTN_TOUCH, 1), (EV_ABS, ABS_X, 10), (EV_ABS, ABS_Y, 10)))
    moves = []
    for value in (20, 40, 80):
        moves.extend(contact.feed(_packet((EV_ABS, ABS_X, value), (EV_ABS, ABS_Y, value))))
    assert coalesce(moves) == [("move", 80, 80)]


def test_a_finger_that_comes_back_keeps_the_release_point():
    contact = _contact()
    contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200), (EV_KEY, BTN_TOUCH, 1)))
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 280))) == [("move", 100, 280)]
    assert contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 205))) == [("move", 100, 205)]
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == [("up", 100, 205)]


def test_a_small_drift_stays_on_the_key_that_was_pressed():
    contact = _contact()
    contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200), (EV_KEY, BTN_TOUCH, 1)))
    assert contact.feed(_packet((EV_ABS, ABS_X, 115), (EV_ABS, ABS_Y, 210))) == []
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == [("up", 100, 200)]


def test_the_reader_sleeps_until_a_touch_when_nothing_is_pending():
    """With no timeout the loop must block in select, not spin on the device."""
    reader, writer = os.pipe()
    polls = []

    def wait():
        polls.append(time.monotonic())
        return None

    def tap_later():
        time.sleep(0.3)
        os.write(writer, _packet((EV_ABS, ABS_X, 30), (EV_ABS, ABS_Y, 40), (EV_KEY, BTN_TOUCH, 1), (EV_KEY, BTN_TOUCH, 0)))

    threading.Thread(target=tap_later, daemon=True).start()
    try:
        point = next(read_points(reader, 480, 800, (0, 479), (0, 799), wait=wait))
    finally:
        os.close(reader)
        os.close(writer)
    assert point == ("up", 30, 40)
    assert len(polls) == 1


def test_two_taps_in_one_burst_stay_two_taps():
    actions = [
        ("down", 10, 10),
        ("up", 10, 10),
        ("down", 20, 20),
        ("up", 22, 20),
    ]
    assert coalesce(actions) == [("up", 10, 10), ("up", 22, 20)]


def test_a_written_line_is_a_tap():
    touch_reader, touch_writer = os.pipe()
    inject_reader, inject_writer = os.pipe()
    os.write(inject_writer, b"12 34\n")

    def wait():
        return 0.2

    try:
        point = next(read_points(touch_reader, 480, 800, (0, 479), (0, 799), wait=wait, inject=inject_reader))
    finally:
        os.close(touch_reader)
        os.close(touch_writer)
        os.close(inject_reader)
        os.close(inject_writer)
    assert point == ("up", 12, 34)


def test_a_tap_in_one_burst_is_a_single_release():
    contact = _contact()
    actions = contact.feed(_packet(
        (EV_ABS, ABS_X, 30),
        (EV_ABS, ABS_Y, 40),
        (EV_KEY, BTN_TOUCH, 1),
        (EV_KEY, BTN_TOUCH, 0),
    ))
    assert coalesce(actions) == [("up", 30, 40)]

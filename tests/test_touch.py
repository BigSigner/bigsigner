import struct

from bigsigner.hardware.touch import BTN_TOUCH, EVENT_FORMAT, EV_ABS, EV_KEY, ABS_X, ABS_Y, _Contact, coalesce


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


def test_a_small_drift_stays_on_the_key_that_was_pressed():
    contact = _contact()
    contact.feed(_packet((EV_ABS, ABS_X, 100), (EV_ABS, ABS_Y, 200), (EV_KEY, BTN_TOUCH, 1)))
    assert contact.feed(_packet((EV_ABS, ABS_X, 115), (EV_ABS, ABS_Y, 210))) == []
    assert contact.feed(_packet((EV_KEY, BTN_TOUCH, 0))) == [("up", 100, 200)]


def test_a_tap_in_one_burst_is_a_single_release():
    contact = _contact()
    actions = contact.feed(_packet(
        (EV_ABS, ABS_X, 30),
        (EV_ABS, ABS_Y, 40),
        (EV_KEY, BTN_TOUCH, 1),
        (EV_KEY, BTN_TOUCH, 0),
    ))
    assert coalesce(actions) == [("up", 30, 40)]

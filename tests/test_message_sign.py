"""BIP-137 message signing on a Native-Segwit singlesig wallet."""

import base64

from bigsigner.message_sign import (
    ADDRESS_MESSAGE_COMMAND,
    BAD_ADDRESS,
    BAD_COMMAND,
    BAD_NETWORK,
    BAD_PATH,
    BAD_PURPOSE,
    MESSAGE_MAX_BYTES,
    NOT_ASCII,
    TOO_LONG,
    address_message_text,
    bip137_signature,
    message_ending,
    message_lines,
    native_sign_path,
    parse_sign_command,
    read_sign_command,
    signing_secret,
)
from bigsigner.session import SessionError
from bigsigner.ui.app import (
    ADDRESS_QR,
    ADDRESS_SIGN_ONLY,
    KEYBOARD_TOP,
    MESSAGE_NOTE_SIZE,
    MESSAGE_QR,
    MESSAGE_ADDRESS_COMMAND,
    MESSAGE_EMPTY,
    MESSAGE_ENDS_NEWLINE,
    MESSAGE_ENDS_SPACE,
    MESSAGE_MORE,
    QR_BRIGHTNESS_STOPS,
    App,
)
from bigsigner.ui.canvas import BLUE, HEADER, HEIGHT, INK, MUTED, NAVY, RED, WARNING, WIDTH

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# m/84h/0h/0h/0/0 of the Abandon seed, native segwit, mainnet.
ABANDON_ADDRESS = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
HELLO_SIGNATURE = "J18BiThkjafFLKfWaBanx1KmmnDfOg4R2FPIdVrFZ1bxK7gyRFRrNmD0L6XSXtSf/doM1j5Xv4FGcxIdbq2e4fU="


def _native_wallet(network="main"):
    app = App()
    app.session.network = network
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.notice = ""
    return app


def _command(path, message):
    return f"signmessage {path} ascii:{message}"


def _tap(app, label):
    app.render()
    matches = [hit for hit in app.hits if hit["label"] == label or hit["action"] == label]
    if not matches:
        app.scroll[app.screen] = 10**9
        app.render()
        matches = [hit for hit in app.hits if hit["label"] == label or hit["action"] == label]
    if not matches:
        raise AssertionError(label)
    hit = min(matches, key=lambda item: (item["box"][2] - item["box"][0]) * (item["box"][3] - item["box"][1]))
    left, top, right, bottom = hit["box"]
    app.tap((left + right) // 2, (top + bottom) // 2)


def _texts(app):
    return [item["text"] for item in app.texts]


def _scan(app, payload):
    if app.screen != "scan":
        _tap(app, "Scan QR Code")
    assert app.screen == "scan"
    app.accept_qr(payload)


def test_a_line_breaks_before_the_character_that_would_overflow():
    lines = message_lines("hello world", 4)
    assert lines == [(0, "hell"), (4, "o wo"), (8, "rld")]
    assert message_lines("ab\ncd", 10) == [(0, "ab"), (3, "cd")]
    assert message_lines("ab\n", 10) == [(0, "ab"), (3, "")]
    assert message_lines("", 10) == [(0, "")]
    assert message_ending("hello ") == "space"
    assert message_ending("hello\n") == "newline"
    assert message_ending("hello\r\n") == "newline"
    assert message_ending("hello") is None


def test_the_path_must_match_this_network_and_account():
    branch, index, steps = native_sign_path("m/84h/0h/0h/0/0", "main", 0)
    assert (branch, index) == (0, 0)
    assert native_sign_path("m/84'/0'/4'/1/12", "main", 4)[:2] == (1, 12)
    assert native_sign_path("m/84h/1h/0h/0/3", "test", 0)[:2] == (0, 3)
    assert native_sign_path("m/84h/1h/0h/0/3", "regtest", 0)[:2] == (0, 3)
    for path, network, account, message in (
        ("84h/0h/0h/0/0", "main", 0, BAD_PATH),
        ("m/86h/0h/0h/0/0", "main", 0, BAD_PURPOSE),
        ("m/48h/0h/0h/2h/0/0", "main", 0, BAD_PURPOSE),
        ("m/84h/1h/0h/0/0", "main", 0, BAD_NETWORK),
        ("m/84h/0h/0h/0/0", "test", 0, BAD_NETWORK),
        ("m/84h/0h/2h/0/0", "main", 0, "This command is for account index 2, but the account index you selected is 0."),
        ("m/84h/0h/0h/2/0", "main", 0, BAD_ADDRESS),
        ("m/84h/0h/0h/0", "main", 0, BAD_ADDRESS),
        ("m/84h/0h/0h/0/0/1", "main", 0, BAD_ADDRESS),
        ("m/84h/0h/0h/0h/0", "main", 0, BAD_ADDRESS),
        ("m/not-a-path", "main", 0, BAD_PATH),
    ):
        try:
            native_sign_path(path, network, account)
        except SessionError as exc:
            assert str(exc) == message
        else:
            raise AssertionError(path)


def test_only_a_signmessage_line_is_a_signing_command():
    text = _command("m/84h/0h/0h/0/0", "hello\nworld")
    assert read_sign_command(text, "QR code", "main") == text
    assert parse_sign_command(text) == ("m/84h/0h/0h/0/0", "hello\nworld")
    assert parse_sign_command(_command("m/84h/0h/0h/0/0", "")) == ("m/84h/0h/0h/0/0", "")
    cases = (
        ("signmessage m/84h/0h/0h/0/0 hello", BAD_COMMAND),
        ("signmessage  m/84h/0h/0h/0/0 ascii:hello", BAD_COMMAND),
        (_command("m/84h/0h/0h/0/0", "héllo"), NOT_ASCII),
        (ABANDON, "This is a seed, not a message signing command."),
        ("cHNidP8BAH0CAAAA", "This is a transaction, not a message signing command."),
        ("wpkh([abcd1234/84h/0h/0h]xpub)", "This is a wallet descriptor, not a message signing command."),
        (ABANDON_ADDRESS, "This is an address, not a message signing command."),
        ("signmessage", "That QR code is not a message signing command."),
        ("", "That file is empty."),
        ("   ", "That file is empty."),
    )
    for payload, message in cases:
        source = "file" if payload.strip() == "" else "QR code"
        try:
            read_sign_command(payload, source, "main")
            parse_sign_command(payload)
        except SessionError as exc:
            assert str(exc) == message
        else:
            raise AssertionError(payload)


def test_bip137_signs_the_abandon_receive_address():
    app = _native_wallet()
    wallet = app.session.wallets[0]
    _branch, _index, steps = native_sign_path("m/84h/0h/0h/0/0", "main", 0)
    secret = signing_secret(app.session._seed_for(wallet.fingerprints[0]), steps)
    signature = bip137_signature(secret, "hello world")
    assert signature == HELLO_SIGNATURE
    assert signature.isascii()
    raw = base64.b64decode(signature)
    assert len(raw) == 65
    assert 39 <= raw[0] <= 42
    assert app.session.addresses(0, 0, 0, 1) == [ABANDON_ADDRESS]


def test_a_native_segwit_wallet_offers_message_signing():
    app = _native_wallet()
    app.scroll["wallet"] = 10**9
    app.render()
    assert any(hit["label"] == "Sign Message (BIP137)" for hit in app.hits)
    _tap(app, "Sign Message (BIP137)")
    assert app.screen == "message-source"
    app.render()
    shown = " ".join(_texts(app))
    assert (
        "If you don't have a file or QR code from a wallet app, "
        "go back and select the address you want to sign a message with."
    ) in shown
    assert any(hit["label"] == "Scan QR Code" for hit in app.hits)
    assert any(hit["label"] == "Load from SD Card" for hit in app.hits)


def _assert_message_signing_is_disabled(app):
    app.scroll["wallet"] = 10**9
    image = app.render()
    assert not any(hit["label"] == "Sign Message (BIP137)" for hit in app.hits)
    assert ADDRESS_SIGN_ONLY in " ".join(item["text"] for item in app.texts)
    note = next(item for item in app.texts if item["text"].startswith("Signing messages"))
    assert note["box"][3] - note["box"][1] > MESSAGE_NOTE_SIZE
    grey = (186, 190, 196)
    assert any(
        image.getpixel((x, y))[:3] == grey
        for y in range(max(HEADER, note["box"][1] - 90), note["box"][1])
        for x in range(40, 440, 8)
    )


def test_taproot_and_multisig_wallets_disable_message_signing():
    taproot = _native_wallet()
    taproot.screen = "key"
    taproot._act("derive-taproot")
    taproot._act("derive-wallet")
    assert taproot.session.wallets[taproot.wallet_index].role != "singlesig_native"
    _assert_message_signing_is_disabled(taproot)

    multi = App()
    first = multi.session.add_mnemonic(ABANDON.split())
    second = multi.session.add_mnemonic(ABANDON.split(), passphrase="second")
    multi.multisig_m = 2
    multi.multisig_selected = {first["fingerprint"], second["fingerprint"]}
    multi._create_selected_multisig()
    _assert_message_signing_is_disabled(multi)


def test_a_watch_only_wallet_disables_message_signing():
    from test_domain import expression

    app = App()
    app.session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})")
    app.screen = "wallet"
    app.wallet_index = 0
    image = app.render()
    assert not any(hit["label"] == "Sign Message (BIP137)" for hit in app.hits)
    assert ADDRESS_SIGN_ONLY not in " ".join(item["text"] for item in app.texts)
    note = next(item for item in app.texts if item["text"].startswith("Unavailable in watch-only"))
    grey = (186, 190, 196)
    assert any(
        image.getpixel((x, y))[:3] == grey
        for y in range(max(HEADER, note["box"][1] - 80), note["box"][1])
        for x in range(40, 440, 8)
    )


def test_a_bad_qr_or_file_stays_on_the_choice_screen():
    from bigsigner.sdcard import mount_memory, unmount_memory

    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, ABANDON)
    assert app.screen == "message-source"
    assert app.notice_error
    assert app.notice == "This is a seed, not a message signing command."

    _tap(app, "Dismiss")
    _scan(app, _command("m/84h/1h/0h/0/0", "hello"))
    assert app.notice == BAD_NETWORK
    _tap(app, "Dismiss")
    _scan(app, _command("m/84h/0h/0h/0/0", "héllo"))
    assert app.notice == NOT_ASCII

    mount_memory({"files": {"note.txt": _command("m/84h/0h/0h/0/0", "hello\n")}})
    try:
        _tap(app, "Dismiss")
        _tap(app, "Load from SD Card")
        _tap(app, "note.txt")
        assert app.screen == "message-edit"
        assert app.message_text == "hello\n"
        app.render()
        assert MESSAGE_ENDS_NEWLINE in _texts(app)
    finally:
        unmount_memory()


def test_the_editor_warns_wraps_and_asks_for_the_hidden_end():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/1/7", "hello "))
    assert app.screen == "message-edit"
    image = app.render()
    warning = next(item for item in app.texts if item["text"] == MESSAGE_ENDS_SPACE)
    assert any(
        image.getpixel((x, y))[:3] == WARNING
        for x in range(warning["box"][0], warning["box"][2])
        for y in range(warning["box"][1], warning["box"][3])
    )
    _tap(app, "Continue")
    assert app.screen == "message-review"
    app.render()
    assert "Address Type: Change" in _texts(app)
    assert "Address Index: 7" in _texts(app)
    assert any(item["text"].startswith("m/84h/0h/0h/1/7") for item in app.texts)

    app.back_one()
    app.message_text = "W" * 400
    app.message_cursor = 0
    app.message_scroll = 0
    app.message_end_dirty = True
    app.message_reached_end = False
    app.render()
    box = app.message_box
    visible = [item for item in app.texts if item["text"].startswith("W") and item["box"][1] >= box[1]]
    assert len(visible) > 1
    assert all(item["box"][2] <= box[2] for item in visible)
    assert not app.message_reached_end
    _tap(app, "Continue")
    assert app.confirm == "message-more"
    assert app._confirm_message() == MESSAGE_MORE
    image = app.render()
    assert any(hit["label"] == "OK" for hit in app.hits)
    assert not any(hit["label"] == "Confirm" for hit in app.hits)
    _tap(app, "OK")
    assert app.confirm is None
    assert app.screen == "message-edit"

    x = (box[0] + box[2]) // 2
    y = (box[1] + box[3]) // 2
    app.pointer_down(x, y)
    app.pointer_move(x, y - app.message_scroll_max - 40)
    app.pointer_up(x, y - 80)
    assert app.message_reached_end
    app._scroll_at = None
    _tap(app, "Continue")
    assert app.confirm is None
    assert app.screen == "message-review"


def test_an_empty_message_disables_continue():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", "a"))
    app.message_cursor = 1
    app._act("passkey-backspace")
    assert app.message_text == ""
    app.message_keyboard = True
    app.render()
    assert MESSAGE_EMPTY not in _texts(app)
    assert any(hit["label"] == "Hide Keyboard" for hit in app.hits)
    app.message_keyboard = False
    image = app.render()
    note = next(item for item in app.texts if item["text"] == MESSAGE_EMPTY)
    assert any(
        image.getpixel((x, y))[:3] == RED
        for x in range(note["box"][0], note["box"][2])
        for y in range(note["box"][1], note["box"][3])
    )
    assert not any(hit["label"] == "Continue" for hit in app.hits)
    assert image.getpixel((WIDTH // 2, HEIGHT - 50))[:3] == (186, 190, 196)
    app._act("passkey-b")
    app.render()
    assert any(hit["label"] == "Continue" for hit in app.hits)
    app.back_one()
    _scan(app, _command("m/84h/0h/0h/0/0", ""))
    assert app.screen == "message-edit"
    assert app.message_text == ""
    assert app.message_keyboard
    app.render()
    assert MESSAGE_EMPTY not in _texts(app)


def test_the_keyboard_types_at_the_cursor_and_hides():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", "hello"))
    app.render()
    _tap(app, "Message")
    assert app.message_keyboard
    app.render()
    assert not any(hit["label"] == "Continue" for hit in app.hits)
    hide = next(hit for hit in app.hits if hit["label"] == "Hide Keyboard")
    assert hide["box"][3] <= KEYBOARD_TOP
    assert app.keyboard_top == KEYBOARD_TOP
    app.message_cursor = 0
    app._act("passkey-A")
    assert app.message_text == "Ahello"
    assert app.message_cursor == 1
    app.render()
    app.tap(40, 40)
    assert not app.message_keyboard
    app.render()
    assert any(hit["label"] == "Continue" for hit in app.hits)


def test_opening_the_keyboard_keeps_the_clicked_line_visible():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", "\n".join(f"line{i:02d}" for i in range(24))))
    app.render()
    box = app.message_box
    app.tap((box[0] + box[2]) // 2, box[3] - 8)
    assert app.message_keyboard
    app.render()
    small = app.message_box
    layout = app.message_layout
    cursor_line = 0
    for index, (start, _visible) in enumerate(layout["lines"]):
        if start <= app.message_cursor:
            cursor_line = index
    top = layout["pad"] + cursor_line * layout["line_h"] - app.message_scroll
    view_h = small[3] - small[1]
    assert app.message_scroll > 0
    assert 0 <= top
    assert top + layout["line_h"] <= view_h


def test_a_gap_between_keys_keeps_the_keyboard_and_enter_inserts_a_newline():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", "hello"))
    _tap(app, "Message")
    app.render()
    q = next(hit for hit in app.hits if hit["label"] == "q")
    w = next(hit for hit in app.hits if hit["label"] == "w")
    gap_x = (q["box"][2] + w["box"][0]) // 2
    assert q["box"][2] <= gap_x < w["box"][0]
    app.tap(gap_x, (q["box"][1] + q["box"][3]) // 2)
    assert app.message_keyboard
    assert app.message_text == "hello"
    _tap(app, "enter")
    assert app.message_text == "hello\n"
    assert app.message_cursor == len(app.message_text)
    assert app.message_keyboard


def test_a_long_derivation_path_breaks_before_the_slash():
    app = _native_wallet()
    wallet = app.session.wallets[0]
    wallet.accounts[wallet.fingerprints[0]] = 2147483647
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/2147483647h/1/2147483647", "hi"))
    _tap(app, "Continue")
    app.render()
    assert "Address Type: Change" in _texts(app)
    lines = [text for text in _texts(app) if text.startswith("m/") or text.startswith("/")]
    assert lines == ["m/84h/0h/2147483647h/1", "/2147483647"]
    for text in lines:
        box = next(item["box"] for item in app.texts if item["text"] == text)
        assert abs((box[0] + box[2]) / 2 - WIDTH / 2) <= 4


def test_signing_shows_the_address_and_an_ascii_signature():
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", "hello world"))
    _tap(app, "Continue")
    assert app.screen == "message-review"
    image = app.render()
    assert "Account: 0" in _texts(app)
    assert "Address Type: Receive" in _texts(app)
    assert "Address" in _texts(app)
    sign = next(hit for hit in app.hits if hit["action"] == "message-sign")
    assert sign["box"][3] >= HEIGHT - 20
    assert "Address Index: 0" in _texts(app)
    odd = next(item for item in app.texts if item["text"] == "bc1q")
    even = next(item for item in app.texts if item["text"] == "cr8t")
    next_row = next(item for item in app.texts if item["text"] == "cawu")
    third = next(item for item in app.texts if item["text"] == "jy8z")
    path = next(item for item in app.texts if item["text"].startswith("m/84h/0h/0h/0/0"))
    assert path["box"][1] > third["box"][1]
    assert abs((path["box"][0] + path["box"][2]) / 2 - WIDTH / 2) <= 4
    assert odd["box"][0] == next_row["box"][0] == third["box"][0]
    assert abs(odd["box"][1] - even["box"][1]) <= 2
    assert next_row["box"][1] > odd["box"][1]

    def ink_of(item):
        return {
            image.getpixel((x, y))[:3]
            for x in range(item["box"][0], min(item["box"][2], WIDTH))
            for y in range(max(item["box"][1], 0), min(item["box"][3], HEIGHT))
        }

    assert INK in ink_of(odd)
    assert MUTED not in ink_of(odd)
    assert MUTED in ink_of(even)
    assert INK not in ink_of(even)
    assert INK in ink_of(next_row)
    assert MUTED not in ink_of(next_row)
    assert "yu  " in _texts(app)
    _tap(app, "Sign Message")
    assert app.screen == "message-signed"
    assert app.message_signature == HELLO_SIGNATURE
    app.render()
    assert HELLO_SIGNATURE[:12] in "".join(_texts(app))
    assert any(hit["action"] == "brightness-up" for hit in app.hits)
    image = app.render()
    qr_left = (WIDTH - ADDRESS_QR) // 2
    qr_top = HEADER + 12
    dark = [
        (x, y)
        for y in range(qr_top, qr_top + ADDRESS_QR)
        for x in range(WIDTH)
        if image.getpixel((x, y))[:3] == (0, 0, 0)
    ]
    assert dark
    assert min(x for x, _y in dark) >= qr_left
    assert max(x for x, _y in dark) < qr_left + ADDRESS_QR
    assert min(y for _x, y in dark) >= qr_top
    assert max(y for _x, y in dark) < qr_top + ADDRESS_QR
    page = (8, qr_top + MESSAGE_QR + 8 + 26)
    assert image.getpixel((0, HEADER + 8))[:3] == QR_BRIGHTNESS_STOPS[app.qr_brightness]
    assert image.getpixel(page)[:3] == QR_BRIGHTNESS_STOPS[app.qr_brightness]
    assert image.getpixel((16, 40))[:3] == NAVY
    app._act("brightness-down")
    app._act("brightness-down")
    dim = app.render()
    assert dim.getpixel((0, HEADER + 8))[:3] == QR_BRIGHTNESS_STOPS[app.qr_brightness]
    assert dim.getpixel(page)[:3] == QR_BRIGHTNESS_STOPS[app.qr_brightness]
    assert sum(dim.getpixel((16, 40))[:3]) < sum(NAVY)
    app.scroll["message-signed"] = app.scroll_max.get("message-signed", 0)
    _tap(app, "Back to Wallet")
    assert app.screen == "wallet"
    assert "message-signed" not in app.back
    assert "message-review" not in app.back


def _open_address(app, branch=0, index=0):
    app.address_branch = branch
    app.address_index = index
    app.back = ["wallets", "wallet", "addresses"]
    app.screen = "address"
    app.scroll["address"] = 10**9
    app.render()
    return app


def test_plain_text_is_an_address_message_and_a_command_is_not():
    assert address_message_text("") == ""
    assert address_message_text("  hello\n") == "  hello\n"
    assert address_message_text("signmessage") == "signmessage"
    assert address_message_text("hello\nsignmessage m/84h/0h/0h/0/0 ascii:x") == (
        "hello\nsignmessage m/84h/0h/0h/0/0 ascii:x"
    )
    for text in (
        "héllo",
        "\n  signmessage m/84h/0h/0h/0/0 ascii:héllo",
    ):
        try:
            address_message_text(text)
        except SessionError as exc:
            assert str(exc) == NOT_ASCII
        else:
            raise AssertionError(text)
    for text in (
        "signmessage m/84h/0h/0h/0/0 ascii:hello",
        "\n\r  signmessage m/84h/0h/0h/0/0 ascii:hello",
        " \n signmessage ",
    ):
        try:
            address_message_text(text)
        except SessionError as exc:
            assert str(exc) == ADDRESS_MESSAGE_COMMAND
        else:
            raise AssertionError(text)


def test_a_native_address_signs_with_its_own_path():
    from bigsigner.sdcard import mount_memory, unmount_memory

    app = _native_wallet()
    wallet = app.session.wallets[app.wallet_index]
    fingerprint = wallet.fingerprints[0]
    wallet.accounts[fingerprint] = 4
    app.scroll["address"] = 0
    app.address_branch = 1
    app.address_index = 9
    app.screen = "address"
    app.render()
    assert app.scroll_max["address"] > 0
    _open_address(app, branch=1, index=9)
    image = app.render()
    sign = next(hit for hit in app.hits if hit["action"] == "address-sign")
    assert image.getpixel((sign["box"][0] + 8, (sign["box"][1] + sign["box"][3]) // 2))[:3] == BLUE
    assert any(hit["label"] == "Export to SD Card" for hit in app.hits)
    _tap(app, "Sign Message")
    assert app.screen == "address-message"
    app.render()
    labels = ["Manual Entry", "Load from SD Card", "Scan QR Code"]
    tops = []
    for label in labels:
        hit = next(item for item in app.hits if item["label"] == label)
        tops.append(hit["box"][1])
    assert tops[0] < tops[1] < tops[2]

    _tap(app, "Manual Entry")
    assert app.screen == "message-edit"
    assert app.message_text == ""
    assert app.message_keyboard
    assert app.message_steps
    app.render()
    assert MESSAGE_EMPTY not in _texts(app)
    assert any(hit["label"] == "Hide Keyboard" for hit in app.hits)
    _tap(app, "Hide Keyboard")
    assert not app.message_keyboard
    app.render()
    assert MESSAGE_EMPTY in _texts(app)
    assert not any(hit["label"] == "Continue" for hit in app.hits)
    _tap(app, "back")
    assert app.screen == "address-message"

    _scan(app, "héllo")
    assert app.screen == "address-message"
    assert app.notice == NOT_ASCII
    _tap(app, "Dismiss")
    _scan(app, "\n\r  signmessage m/84h/0h/0h/0/0 ascii:hello")
    assert app.screen == "address-message"
    assert app.notice == ADDRESS_MESSAGE_COMMAND

    mount_memory(
        {
            "files": {
                "bad.txt": "héllo",
                "command.txt": "\n  signmessage m/84h/0h/4h/1/9 ascii:hello",
                "note.txt": "  hello world",
            }
        }
    )
    try:
        _tap(app, "Dismiss")
        _tap(app, "Load from SD Card")
        _tap(app, "bad.txt")
        assert app.screen == "address-message"
        assert app.notice == NOT_ASCII
        _tap(app, "Dismiss")
        _tap(app, "Load from SD Card")
        _tap(app, "command.txt")
        assert app.screen == "address-message"
        assert app.notice == ADDRESS_MESSAGE_COMMAND
        _tap(app, "Dismiss")
        _tap(app, "Load from SD Card")
        _tap(app, "note.txt")
    finally:
        unmount_memory()
    assert app.screen == "message-edit"
    assert app.message_text == "  hello world"
    assert app.message_branch == 1
    assert app.message_index == 9
    app.render()
    _tap(app, "Message")
    assert app.message_keyboard
    app.render()
    app.tap(40, 40)
    assert not app.message_keyboard
    _tap(app, "Continue")
    assert app.screen == "message-review"
    app.render()
    assert "Address Type: Change" in _texts(app)
    assert "Address Index: 9" in _texts(app)
    assert any(item["text"].startswith("m/84h/0h/4h/1/9") for item in app.texts)
    secret = signing_secret(app.session._seed_for(fingerprint), app.message_steps)
    expected = bip137_signature(secret, "  hello world")
    _tap(app, "Sign Message")
    assert app.screen == "message-signed"
    assert app.message_signature == expected
    assert app.message_signature != HELLO_SIGNATURE
    app.scroll["message-signed"] = 10**9
    _tap(app, "Back to Wallet")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]


def test_other_wallets_disable_signing_from_an_address():
    taproot = _native_wallet()
    taproot.screen = "key"
    taproot._act("derive-taproot")
    taproot._act("derive-wallet")
    _open_address(taproot)
    image = taproot.render()
    assert not any(hit["action"] == "address-sign" for hit in taproot.hits)
    assert ADDRESS_SIGN_ONLY in " ".join(_texts(taproot))
    note = next(item for item in taproot.texts if item["text"].startswith("Signing messages"))
    grey = (186, 190, 196)
    assert any(
        image.getpixel((x, y))[:3] == grey
        for y in range(max(HEADER, note["box"][1] - 90), note["box"][1])
        for x in range(40, 440, 6)
    )

    multi = App()
    first = multi.session.add_mnemonic(ABANDON.split())
    second = multi.session.add_mnemonic(ABANDON.split(), passphrase="second")
    multi.multisig_m = 2
    multi.multisig_selected = {first["fingerprint"], second["fingerprint"]}
    multi._create_selected_multisig()
    _open_address(multi)
    multi.render()
    assert multi.session.wallets[multi.wallet_index].role != "singlesig_native"
    assert not any(hit["action"] == "address-sign" for hit in multi.hits)
    assert ADDRESS_SIGN_ONLY in " ".join(_texts(multi))


def test_a_watch_only_address_can_open_message_signing():
    from test_domain import expression

    app = App()
    app.session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})")
    app.wallet_index = 0
    _open_address(app, index=2)
    assert any(hit["action"] == "address-sign" for hit in app.hits)
    _tap(app, "Sign Message")
    _tap(app, "Manual Entry")
    assert app.message_text == ""
    assert app.message_keyboard
    assert app.message_index == 2
    app.message_keyboard = False
    app.message_text = "hello"
    app.message_cursor = len(app.message_text)
    _tap(app, "Continue")
    assert app.screen == "message-review"
    _tap(app, "Sign Message")
    assert app.screen == "message-review"
    assert app.notice == "This seed is no longer loaded."


def test_typing_a_signmessage_command_from_an_address_disables_continue():
    app = _native_wallet()
    _open_address(app, index=1)
    _tap(app, "Sign Message")
    _tap(app, "Manual Entry")
    assert app.message_keyboard
    app.message_keyboard = False
    app.message_text = "signmessage hello"
    app.message_cursor = len(app.message_text)
    image = app.render()
    assert MESSAGE_ADDRESS_COMMAND in " ".join(_texts(app))
    note = next(item for item in app.texts if item["text"].startswith("In order to use"))
    assert any(
        image.getpixel((x, y))[:3] == RED
        for x in range(note["box"][0], note["box"][2])
        for y in range(note["box"][1], note["box"][3])
    )
    assert not any(hit["label"] == "Continue" for hit in app.hits)
    assert image.getpixel((WIDTH // 2, HEIGHT - 50))[:3] == (186, 190, 196)
    app._act("message-continue")
    assert app.screen == "message-edit"

    for text in ("\n\n  signmessage ", " \r\nsignmessage m/84h/0h/0h/0/1 ascii:hello"):
        app.message_text = text
        app.render()
        assert not any(hit["label"] == "Continue" for hit in app.hits)
        assert MESSAGE_ADDRESS_COMMAND in " ".join(_texts(app))
        assert MESSAGE_ENDS_SPACE not in _texts(app)

    app.message_text = "signmessage"
    app.render()
    assert any(hit["label"] == "Continue" for hit in app.hits)

    app.message_text = "hello signmessage "
    app.render()
    assert any(hit["label"] == "Continue" for hit in app.hits)
    assert MESSAGE_ENDS_SPACE in _texts(app)

    wallet = _native_wallet()
    _tap(wallet, "Sign Message (BIP137)")
    _scan(wallet, _command("m/84h/0h/0h/0/0", "hello"))
    wallet.message_text = "signmessage hello"
    wallet.message_cursor = len(wallet.message_text)
    wallet.render()
    assert any(hit["label"] == "Continue" for hit in wallet.hits)
    assert MESSAGE_ADDRESS_COMMAND not in " ".join(_texts(wallet))


def test_a_message_cannot_be_longer_than_1024_bytes():
    full = "a" * MESSAGE_MAX_BYTES
    assert len(full.encode("utf-8")) == 1024
    assert parse_sign_command(_command("m/84h/0h/0h/0/0", full))[1] == full
    assert address_message_text(full) == full
    try:
        parse_sign_command(_command("m/84h/0h/0h/0/0", full + "b"))
    except SessionError as exc:
        assert str(exc) == TOO_LONG
    else:
        raise AssertionError("long command")
    try:
        address_message_text(full + "\n")
    except SessionError as exc:
        assert str(exc) == TOO_LONG
    else:
        raise AssertionError("long address message")

    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, _command("m/84h/0h/0h/0/0", full + "b"))
    assert app.screen == "message-source"
    assert app.notice == TOO_LONG
    _tap(app, "Dismiss")
    _scan(app, _command("m/84h/0h/0h/0/0", full))
    assert app.screen == "message-edit"
    assert app.message_text == full
    app.message_cursor = len(app.message_text)
    app.message_keyboard = True
    app._act("passkey-c")
    app._act("passkey-enter")
    assert app.message_text == full
    app._act("passkey-backspace")
    assert app.message_text == full[:-1]
    app._act("passkey-z")
    assert app.message_text == full[:-1] + "z"


def test_loading_a_signmessage_command_longer_than_1024_bytes_is_refused():
    from bigsigner.sdcard import mount_memory, unmount_memory

    content = "b" * (MESSAGE_MAX_BYTES + 1)
    assert len(content.encode("utf-8")) == 1025
    command = _command("m/84h/0h/0h/0/0", content)
    app = _native_wallet()
    _tap(app, "Sign Message (BIP137)")
    _scan(app, command)
    assert app.screen == "message-source"
    assert app.notice_error
    assert app.notice == TOO_LONG
    assert app.message_text == ""

    mount_memory({"files": {"long.txt": command}})
    try:
        _tap(app, "Dismiss")
        _tap(app, "Load from SD Card")
        _tap(app, "long.txt")
        assert app.screen == "message-source"
        assert app.notice == TOO_LONG
        assert app.message_text == ""
    finally:
        unmount_memory()


def test_manual_entry_stops_at_1024_characters():
    app = _native_wallet()
    _open_address(app)
    _tap(app, "Sign Message")
    _tap(app, "Manual Entry")
    assert app.screen == "message-edit"
    assert app.message_keyboard
    assert app.message_text == ""
    almost = "c" * (MESSAGE_MAX_BYTES - 1)
    app.message_text = almost
    app.message_cursor = len(almost)
    app._act("passkey-d")
    assert app.message_text == almost + "d"
    assert len(app.message_text.encode("utf-8")) == MESSAGE_MAX_BYTES
    app._act("passkey-e")
    app._act("passkey-enter")
    app._act("passkey- ")
    assert app.message_text == almost + "d"
    assert len(app.message_text) == MESSAGE_MAX_BYTES
    app._act("passkey-backspace")
    assert len(app.message_text) == MESSAGE_MAX_BYTES - 1
    app._act("passkey-f")
    assert app.message_text.endswith("f")
    assert len(app.message_text) == MESSAGE_MAX_BYTES

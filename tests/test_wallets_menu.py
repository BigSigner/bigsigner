from PIL import Image

from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEADER, HEIGHT, MARGIN, MUTED, TITLE_SIZE, WIDTH

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _tap(app, label):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(label)


def test_wallet_screen_names_the_script_on_the_first_line():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    native = app.session.wallets[app.wallet_index]
    assert app._wallet_kind_line(native) == "Native-Segwit"
    app.screen = "key"
    app._act("derive-taproot")
    app._act("derive-wallet")
    taproot = app.session.wallets[app.wallet_index]
    assert app._wallet_kind_line(taproot) == "Taproot"


def test_show_descriptor_opens_a_qr_with_the_text_below_it():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.notice = ""
    app.render()
    assert any(hit["label"] == "Show descriptor" for hit in app.hits)
    assert not any(hit["label"] == "Show descriptor QR" for hit in app.hits)
    app._act("show-descriptor")
    assert app.screen == "qr"
    assert app.qr_kind == "descriptor"
    assert app.qr_text.startswith("wpkh(")
    app.qr_hint_until = 0
    app.render()
    assert any(hit["action"] == "zoom-in" for hit in app.hits)
    assert any(hit["action"] == "brightness-up" for hit in app.hits)
    assert not any(hit["action"] == "qr-form-next" for hit in app.hits)
    assert app.qr_scroll_max > 0
    assert app._qr_payload() == app.session.descriptor_text(app.wallet_index)
    from bigsigner.ui.app import _pretty_descriptor

    shown = _pretty_descriptor(app.qr_text)
    assert shown.startswith("wpkh(\n  [")
    assert shown.endswith("\n)" + app.qr_text.split(")", 1)[1])
    assert "\n" not in app._qr_payload()
    assert shown.replace("\n  ", "").replace("\n", "") == app.qr_text


def test_scrolling_the_descriptor_reuses_one_picture():
    from embit.descriptor.checksum import checksum

    from test_domain import LEGAL, expression

    app = App()
    third = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    keys = [
        expression(ABANDON, "m/48h/0h/0h/2h"),
        expression(LEGAL, "m/48h/0h/1h/2h"),
        expression(third, "m/48h/0h/2h/2h"),
    ]
    body = "wsh(sortedmulti(2," + ",".join(keys) + "))"
    app.session.add_text(f"{body}#{checksum(body)}")
    app._open_descriptor_qr()
    preview = app.preview_qr_frame()
    assert preview is not None
    assert app._qr_strip is None
    assert app.qr_strip_due()
    app.qr_hint_until = 0
    app.render()
    strip = app._qr_strip
    view_h = app.qr_scroll_box[3] - app.qr_scroll_box[1]
    assert strip is not None
    assert strip.height == app.qr_scroll_max + view_h
    assert strip.height < app.qr_scroll_max * view_h
    app.qr_scroll = 80
    app.render()
    assert app._qr_strip is strip
    assert app.qr_scroll == 80


def test_descriptor_text_indents_each_key_and_the_qr_stays_compact():
    from bigsigner.ui.app import _pretty_descriptor

    raw = (
        "wsh(sortedmulti(2,[aaaaaaaa/48h/0h/0h/2h]xpubONE/<0;1>/*,"
        "[bbbbbbbb/48h/0h/0h/2h]xpubTWO/<0;1>/*))#dead"
    )
    assert _pretty_descriptor(raw) == (
        "wsh(sortedmulti(2,\n"
        "  [aaaaaaaa/48h/0h/0h/2h]xpubONE/<0;1>/*,\n"
        "  [bbbbbbbb/48h/0h/0h/2h]xpubTWO/<0;1>/*\n"
        "))#dead"
    )
    from PIL import Image, ImageDraw

    from bigsigner.ui.app import _wrap_indented
    from bigsigner.ui.canvas import font

    draw = ImageDraw.Draw(Image.new("RGB", (40, 20)))
    face = font(22, mono=True)
    wrapped = _wrap_indented(draw, "  " + "x" * 80, face, draw.textlength("x" * 20, font=face))
    assert wrapped[0].startswith("  ")
    assert wrapped[1:] and all(not line.startswith(" ") for line in wrapped[1:])


def test_delete_wallet_asks_first_and_keeps_the_keys():
    app = App()
    added = app.session.add_mnemonic(ABANDON)
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    assert len(app.session.wallets) == 1
    app.notice = ""
    app.render()
    _tap(app, "delete-wallet")
    assert app.confirm == "delete-wallet"
    assert app.session.wallets
    app.render()
    _tap(app, "Cancel")
    assert app.confirm is None
    assert len(app.session.wallets) == 1
    _tap(app, "delete-wallet")
    _tap(app, "Confirm")
    assert app.screen == "wallets"
    assert app.session.wallets == []
    assert added["fingerprint"] in app.session.fingerprints
    assert app.notice == "The wallet was deleted."


def test_wallets_plus_opens_the_descriptor_menu():
    app = App()
    app.screen = "wallets"
    app.render()
    _tap(app, "plus")
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert "Scan descriptor QR code" in labels
    assert "Manual entry of descriptor" not in labels
    assert "Load descriptor from SD card" in labels
    assert "Select from existing multsig keys" in labels
    _tap(app, "close-add")
    assert app.add_menu is False


def test_descriptor_scan_rejects_a_seed():
    app = App()
    app.screen = "wallets"
    app.render()
    _tap(app, "plus")
    _tap(app, "wallet-scan")
    assert app.screen == "scan"
    assert app.scan_kind == "descriptor"
    app.accept_qr(ABANDON)
    assert app.screen == "load-error"
    assert app.load_error == "This is a seed, not a wallet descriptor."
    _tap(app, "OK")
    assert app.screen == "wallets"


def test_selected_seeds_become_a_native_segwit_multisig():
    app = App()
    first = app.session.add_mnemonic(ABANDON)
    second = app.session.add_mnemonic(ABANDON, passphrase="second")
    app.screen = "wallets"
    app.render()
    _tap(app, "plus")
    _tap(app, "wallet-multisig")
    assert app.screen == "multisig"
    _tap(app, f"toggle-ms-{first['fingerprint'].hex()}")
    _tap(app, f"toggle-ms-{second['fingerprint'].hex()}")
    _tap(app, "dropdown-multisig-m")
    _tap(app, "2 of 2 must sign")
    _tap(app, "ms-create")
    assert app.screen == "wallet"
    wallet = app.session.wallets[app.wallet_index]
    assert wallet.multisig
    assert wallet.threshold == 2
    assert app._wallet_kind_line(wallet) == "2-of-2 Native-Segwit"
    app.render()
    assert app.screen == "wallet"
    assert set(wallet.fingerprints) == {first["fingerprint"], second["fingerprint"]}
    assert app.notice == "The multisig wallet was added."
    app.screen = "wallets"
    app.render()
    assert any(hit["label"] == "2-of-2 Native Segwit" for hit in app.hits)
    box = next(hit["box"] for hit in app.hits if hit["label"] == "2-of-2 Native Segwit")
    assert box[3] - box[1] == app._wallet_card_height(wallet)


def test_wallet_cards_list_fingerprints_and_mark_seeds():
    from test_domain import LEGAL, expression

    app = App()
    seed = app.session.add_mnemonic(ABANDON)
    app.selected_fp = seed["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    watched = app.session.add_text(f"wpkh({expression(LEGAL, 'm/84h/0h/0h')})")
    partners = [app.session.add_mnemonic(ABANDON, passphrase=str(number)) for number in range(4)]
    app.multisig_m = 4
    app.multisig_selected = {item["fingerprint"] for item in partners}
    app._create_selected_multisig()
    multisig = app.session.wallets[app.wallet_index]
    assert len(multisig.fingerprints) == 4

    from PIL import ImageDraw

    draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, 4)))
    one = app._wallet_hex_lines(draw, [seed["fingerprint"]])
    two = app._wallet_hex_lines(draw, [seed["fingerprint"], partners[0]["fingerprint"]])
    four = app._wallet_hex_lines(draw, multisig.fingerprints)
    assert one == [seed["fingerprint"].hex()]
    assert two == [f"{seed['fingerprint'].hex()},{partners[0]['fingerprint'].hex()}"]
    assert "".join(four) == ",".join(fingerprint.hex() for fingerprint in multisig.fingerprints)
    assert len(four) == 2
    assert four[0].endswith(",")
    assert not four[-1].endswith(",")
    assert all(" " not in line for line in four)

    app.screen = "wallets"
    app.scroll["wallets"] = 0
    image = app.render()
    tops = _card_tops(app)
    seed_icon = _name_icon_ink(image, tops[0])
    watch_icon = _name_icon_ink(image, tops[1])
    assert seed_icon
    assert watch_icon
    assert seed_icon != watch_icon
    watched_fp = watched["fingerprint"]
    assert any(key.has_seed for key in app.session.fingerprints[seed["fingerprint"]].keys)
    assert not any(key.has_seed for key in app.session.fingerprints[watched_fp].keys)
    right_edge = WIDTH - MARGIN - 16
    assert max(x for x, _y in _muted(image)) <= right_edge
    app.scroll["wallets"] = app.scroll_max["wallets"]
    scrolled = app.render()
    assert max(x for x, _y in _muted(scrolled)) <= right_edge


def _card_tops(app: App) -> list[int]:
    y = HEADER + 24
    tops = []
    for wallet in app.session.wallets:
        tops.append(y)
        y += app._wallet_card_height(wallet) + 14
    return tops


def _muted(image):
    return [
        (x, y)
        for y in range(HEADER, HEIGHT)
        for x in range(WIDTH)
        if image.getpixel((x, y))[:3] == MUTED
    ]


def _name_icon_ink(image, top: int):
    """Muted pixels in the key or eye gutter beside a one-fingerprint card's name."""
    name_y = top + 14 + TITLE_SIZE + 12 + TITLE_SIZE + 12
    inset = MARGIN + 16
    return [
        (x, y)
        for y in range(name_y, name_y + 80)
        for x in range(inset, inset + 32)
        if 0 <= y < HEIGHT and image.getpixel((x, y))[:3] == MUTED
    ]


def test_multisig_lists_seeds_and_native_segwit_multisig_keys_only():
    from PIL import Image, ImageDraw

    from bigsigner.ui.canvas import TITLE_SIZE, font
    from test_domain import LEGAL, expression, root_of

    title = "Native-Segwit Multisig"
    draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, 40)))
    _left, _top, right, _bottom = draw.textbbox((84, 28), title, font=font(TITLE_SIZE))
    assert right <= WIDTH - 16

    app = App()
    seed = app.session.add_mnemonic(ABANDON)
    singlesig = app.session.add_text(expression(LEGAL, "m/84h/0h/0h"))
    hidden = root_of(ABANDON, "hidden")
    public = hidden.derive("m/48h/0h/0h/2h").to_public()
    multisig_key = app.session.add_text(
        f"[{hidden.my_fingerprint.hex()}/48h/0h/0h/2h]{public.to_string()}/<0;1>/*"
    )
    candidates = set(app._multisig_candidates())
    assert seed["fingerprint"] in candidates
    assert multisig_key["fingerprint"] in candidates
    assert singlesig["fingerprint"] not in candidates

    app.multisig_selected = {seed["fingerprint"]}
    app.screen = "multisig"
    app.render()
    labels = {hit["label"] for hit in app.hits}
    assert app.session.fingerprints[seed["fingerprint"]].nickname in labels
    assert app.session.fingerprints[multisig_key["fingerprint"]].nickname in labels
    assert app.session.fingerprints[singlesig["fingerprint"]].nickname not in labels
    dropdown = next(hit for hit in app.hits if hit["action"] == "dropdown-multisig-m")
    assert dropdown["box"][1] == HEADER + 16


def test_creating_the_same_multisig_again_says_it_is_already_loaded():
    app = App()
    first = app.session.add_mnemonic(ABANDON)
    second = app.session.add_mnemonic(ABANDON, passphrase="second")
    app.screen = "multisig"
    app.multisig_m = 2
    app.multisig_selected = {first["fingerprint"], second["fingerprint"]}
    app._create_selected_multisig()
    assert len(app.session.wallets) == 1
    app.screen = "multisig"
    app._create_selected_multisig()
    assert len(app.session.wallets) == 1
    assert app.notice == "The wallet is already loaded."


def test_multisig_threshold_follows_the_selected_keys():
    from bigsigner.ui.canvas import HEIGHT, WIDTH

    app = App()
    first = app.session.add_mnemonic(ABANDON)
    second = app.session.add_mnemonic(ABANDON, passphrase="second")
    app.screen = "multisig"
    app.render()
    assert not any(hit["action"] == "dropdown-multisig-m" for hit in app.hits)
    assert not any(hit["action"] == "ms-create" for hit in app.hits)
    assert app.render().getpixel((WIDTH // 2, HEIGHT - 70)) == (186, 190, 196)

    _tap(app, f"toggle-ms-{first['fingerprint'].hex()}")
    app.render()
    assert any(hit["label"] == "1 of 1 must sign" for hit in app.hits)
    assert any(hit["action"] == "ms-create" for hit in app.hits)
    _tap(app, "ms-create")
    assert app.notice == "A multisig needs at least two keys."
    _tap(app, "dropdown-multisig-m")
    app.render()
    assert {hit["label"] for hit in app.hits if hit["action"].startswith("dropdown-pick-multisig-m-")} == {
        "1 of 1 must sign"
    }

    _tap(app, "dropdown-close")
    _tap(app, f"toggle-ms-{second['fingerprint'].hex()}")
    app.render()
    assert any(hit["label"] == "1 of 2 must sign" for hit in app.hits)
    _tap(app, "dropdown-multisig-m")
    app.render()
    assert {hit["label"] for hit in app.hits if hit["action"].startswith("dropdown-pick-multisig-m-")} == {
        "1 of 2 must sign",
        "2 of 2 must sign",
    }
    _tap(app, "2 of 2 must sign")
    assert app.multisig_m == 2

    _tap(app, f"toggle-ms-{second['fingerprint'].hex()}")
    assert app.multisig_m == 1
    app.render()
    assert any(hit["label"] == "1 of 1 must sign" for hit in app.hits)

    _tap(app, f"toggle-ms-{first['fingerprint'].hex()}")
    app.render()
    assert not any(hit["action"] == "dropdown-multisig-m" for hit in app.hits)
    assert not any(hit["action"] == "ms-create" for hit in app.hits)
    assert app.screen == "multisig"

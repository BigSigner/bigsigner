"""The Transaction Signing screen, the OP_RETURN page, and the signed-PSBT QR."""

from PIL import Image, ImageDraw

from ..psbt_view import format_btc, hex_lines, is_ascii
from .canvas import (
    BLUE,
    Frame,
    HEADER,
    HEIGHT,
    INK,
    LINE,
    MARGIN,
    MUTED,
    PAPER,
    RED,
    TITLE_SIZE,
    WARNING,
    WHITE,
    WIDTH,
    Icons,
    font,
    glyph_sprite,
    ink_span,
    wrap,
)

AMOUNT_SIZE = 36
AMOUNT_SIZE_LARGE = 48
TXID_SIZE = 40
# The code uses the same side gap as the rest of the page. Brightness sits
# just above the format switcher, which is drawn at HEIGHT - 88.
QR_BOX = WIDTH - 2 * MARGIN
_BRIGHTNESS_HEIGHT = 52
_FORMAT_TOP = HEIGHT - 88
_CONTROL_GAP = 12
_TONE = {"red": RED, "yellow": WARNING, "grey": MUTED}
# Cards are drawn only while they meet this screen or the one above or below.
# Fixed blocks and each chevron mode stay cached. A hundred cards do not.


def _clip_top(frame) -> int:
    """Title bar on a normal frame; 0 when painting a scroll tile strip."""
    return getattr(frame, "clip_top", HEADER)


def _strip_visible(frame, top: float, span: float) -> bool:
    """True when this box meets the strip being painted.

    A tile uses clip_top 0 and still draws a box that began on the previous
    tile, so the stitch does not cut a glyph in half. A live frame keeps
    clip_top at the title bar and skips a box that starts underneath it.
    """
    clip_top = _clip_top(frame)
    clip_bottom = getattr(frame, "clip_bottom", HEIGHT)
    if top >= clip_bottom or top + span <= clip_top:
        return False
    if top >= clip_top:
        return True
    return clip_top == 0


def paint_signing(app, frame):
    view = app.psbt_view
    if not view:
        frame.header("Transaction Signing", "back")
        frame.text("This transaction is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
        return
    sheet = app._psbt_sheet
    if sheet is None or sheet.get("view_id") != id(view):
        sheet = {"view_id": id(view), "pictures": {}}
        app._psbt_sheet = sheet
    parts = _parts(app, view)
    probe = None
    y = 0
    for part in parts:
        height = app._psbt_heights.get(part["height_key"])
        if height is None:
            if probe is None:
                probe = Frame()
            height = int(part["paint"](probe, 0, False, 0))
            app._psbt_heights[part["height_key"]] = height
        part["y"] = y
        part["height"] = height
        y += height
    end = max(y, HEIGHT)
    sheet["end"] = end
    offset = app._scroll_offset("psbt-yaml", end, clearance=16)
    window_top = offset - HEIGHT
    window_bottom = offset + 2 * HEIGHT
    needed = set()
    rendered_new = False
    for part in parts:
        if part["height"] <= 0:
            continue
        on_screen = part["y"] < offset + HEIGHT and part["y"] + part["height"] > offset
        in_window = part["y"] < window_bottom and part["y"] + part["height"] > window_top
        if not part["retain"] and not in_window:
            continue
        needed.add(part["picture_key"])
        picture = sheet["pictures"].get(part["picture_key"])
        if picture is None:
            picture = _render_part(part)
            sheet["pictures"][part["picture_key"]] = picture
            rendered_new = True
        if on_screen:
            part["picture"] = picture
    for key, picture in list(sheet["pictures"].items()):
        if picture["retain"] or key in needed:
            continue
        del sheet["pictures"][key]
    _blit_parts(frame, parts, offset)
    frame.header("Transaction Signing", "back")
    # A drag inside the cached window only copies pictures that already exist.
    if not rendered_new and app._press is not None:
        app.dirty = (HEADER, HEIGHT)


def _render_part(part) -> dict:
    """Draw this part whole, from its top through its own height."""
    height = max(1, int(part["height"]))
    frame = Frame()
    frame.image = Image.new("RGB", (WIDTH, height), PAPER)
    frame.draw = ImageDraw.Draw(frame.image)
    frame.clip_top = 0
    frame.clip_bottom = height
    part["paint"](frame, 0, True, 0)
    return {
        "image": frame.image,
        "hits": frame.hits,
        "marks": frame.marks,
        "retain": part["retain"],
    }


def _blit_parts(frame, parts, offset: int) -> None:
    bottom = offset + HEIGHT
    seen_hits = set()
    for part in parts:
        picture = part.get("picture")
        if picture is None:
            continue
        image = picture["image"]
        part_y = part["y"]
        if part_y + image.height <= offset or part_y >= bottom:
            continue
        src_top = max(0, offset - part_y)
        dst_top = max(0, part_y - offset)
        src_bottom = min(image.height, bottom - part_y)
        if src_bottom <= src_top:
            continue
        frame.image.paste(
            image.crop((0, src_top, WIDTH, src_bottom)),
            (0, dst_top),
        )
        shift = part_y - offset
        for hit in picture["hits"]:
            box = hit["box"]
            top = box[1] + shift
            bot = box[3] + shift
            if bot <= HEADER or top >= HEIGHT:
                continue
            key = (hit["action"], int(box[0]), int(box[1]), int(box[2]), int(box[3]), part_y)
            if key in seen_hits:
                continue
            seen_hits.add(key)
            frame.hit((box[0], top, box[2], bot), hit["action"], hit.get("label", ""))
        for mark in picture["marks"]:
            box = mark["box"]
            top = box[1] + shift
            bot = box[3] + shift
            if bot > HEADER and top < HEIGHT:
                frame.marks.append(
                    {"text": mark["text"], "box": [box[0], int(top), box[2], int(bot)]}
                )


def _card_painter(app, card, kind):
    def paint(frame, y, do_paint, offset, item=card):
        if kind == "output":
            return _output_card(app, frame, y, do_paint, offset, item)
        if kind == "change":
            return _change_card(app, frame, y, do_paint, offset, item)
        return _input_card(app, frame, y, do_paint, offset, item)

    return paint


def _sign_key(app, view):
    signing_fp = None if app._psbt_signing_fp is None else app._psbt_signing_fp.hex()
    return (
        "signs",
        bool(app._psbt_signing),
        signing_fp,
        bool(app.psbt_continue),
        view.get("signature_note") or "",
        tuple(
            (signer["fingerprint"], signer["signed"], signer.get("note") or "", signer["button"])
            for signer in view.get("signers", ())
        ),
    )


def paint_opreturn(app, frame):
    frame.header("OP_RETURN", "back")
    card = _op_card(app)
    if card is None:
        frame.text("This output is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
        return
    payload = card["payload"] or b""
    ascii_mode = app.psbt_op_mode == "ascii"
    name = "ASCII text" if ascii_mode else "HEX"
    switch = HEIGHT - 88
    note = ""
    if ascii_mode and not is_ascii(payload):
        lines = wrap(
            frame.draw, "The content is not ASCII text.", font(TITLE_SIZE, mono=True), WIDTH - 2 * MARGIN,
        )
    elif ascii_mode:
        lines = wrap(frame.draw, payload.decode("ascii") or "", font(TITLE_SIZE, mono=True), WIDTH - 2 * MARGIN)
        if not lines:
            lines = [""]
    else:
        lines = hex_lines(payload)
    line_h = TITLE_SIZE + 8
    body_top = HEADER + 16
    limit = switch - 16
    if body_top + len(lines) * line_h > limit:
        note = "Content is too long to fit the screen. Scroll down to see the rest."
    note_h = app._text_height(frame, note, TITLE_SIZE) + 8 if note else 0
    end = body_top + note_h + len(lines) * line_h
    offset = app._scroll_offset("psbt-opreturn", end, clearance=HEIGHT - limit)
    y = body_top
    if note:
        y = app._flow_text(frame, y, note, True, offset, TITLE_SIZE, fill=MUTED)
    for line in lines:
        screen_y = y - offset
        if HEADER <= screen_y < limit:
            if ascii_mode:
                face = font(TITLE_SIZE, mono=True)
                frame.draw.text((MARGIN, screen_y), line, font=face, fill=INK)
                frame.mark(line, frame.draw.textbbox((MARGIN, screen_y), line, font=face))
            else:
                face = font(TITLE_SIZE, mono=True)
                left = _hex_left(frame)
                frame.draw.text((left, screen_y), line, font=face, fill=INK)
                frame.mark(line, frame.draw.textbbox((left, screen_y), line, font=face))
        y += line_h
    app._format_switcher(frame, name, "psbt-op-prev", "psbt-op-next")


def _hex_left(frame) -> int:
    """A full line of eight bytes has the same gap on the left and the right."""
    sample = "00 11 22 33 44 55 66 77"
    width = frame.draw.textlength(sample, font=font(TITLE_SIZE, mono=True))
    return round((WIDTH - width) / 2)


def paint_input_qr(app, frame):
    from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

    from ..psbt_view import EXPLORER_NETWORKS, input_qr_text

    card = _input_card_for_qr(app)
    names = ("Raw", "Mempool.space", "Blockstream.info")
    kinds = ("raw", "mempool", "blockstream")
    frame.header("Input QR" if card is None else f"Input #{card['index']}", "back")
    if card is None:
        frame.text("This input is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
        return
    kind = kinds[app.input_qr_format % 3]
    slug, label = EXPLORER_NETWORKS[app.input_explorer % len(EXPLORER_NETWORKS)]
    text = input_qr_text(app.session.network, card["txid"], card["vout"], kind, slug)
    image = app._input_qr_images.get(text)
    if image is None:
        image = _qr_image(text, QR_BOX, light=_qr_light(QR_BRIGHTNESS_DEFAULT))
        app._input_qr_images[text] = image
    _paste_qr(frame, image)
    if app.session.network in ("test", "regtest") and kind != "raw":
        app._choice_control(frame, _explorer_y(), label, "input-explorer-prev", "input-explorer-next")
    app._brightness_control(frame, _brightness_y())
    app._format_switcher(frame, names[app.input_qr_format % 3], "input-qr-prev", "input-qr-next")


def _input_card_for_qr(app):
    view = app.psbt_view
    if not view:
        return None
    for card in view["inputs"]:
        if card["index"] == app.input_qr_index:
            return card
    return None


def paint_share(app, frame):
    frame.header("Sign Transaction", "back")
    if app.signed_psbt is None:
        frame.text("This transaction has not been signed.", MARGIN, HEADER + 24, size=TITLE_SIZE)
        return
    y = frame.button(HEADER + 24, "Show QR Code", "psbt-show-qr")
    frame.button(y, "Export to SD Card", "psbt-export")
    back_h = frame.button_height("Back to Wallet")
    frame.button(HEIGHT - 16 - back_h, "Back to Wallet", "psbt-back-wallet")


def paint_export_format(app, frame):
    frame.header("Export Format", "back")
    y = frame.button(HEADER + 24, "Binary", "psbt-export-binary")
    frame.button(y, "Base64", "psbt-export-base64")


def paint_qr(app, frame):
    from .app import QR_BRIGHTNESS_DEFAULT, _qr_image, _qr_light

    frame.header("Signed Transaction", "back")
    parts = app._psbt_qr_parts()
    names = ("Animated UR", "Static UR", "Base64", "Specter Animated", "BBQr")
    name = names[app.psbt_qr_format]
    if not parts:
        frame.text(
            f"This PSBT does not fit in one {name} QR. Choose another format.",
            MARGIN,
            HEADER + 24,
            size=TITLE_SIZE,
        )
        app._format_switcher(frame, name, "psbt-qr-prev", "psbt-qr-next")
        return
    index = app.psbt_qr_part % len(parts)
    image = app._psbt_qr_images.get(parts[index])
    if image is None:
        image = _qr_image(parts[index], QR_BOX, light=_qr_light(QR_BRIGHTNESS_DEFAULT))
        app._psbt_qr_images[parts[index]] = image
    bottom = _paste_qr(frame, image)
    if len(parts) > 1:
        _centered(frame, f"{index + 1} of {len(parts)}", bottom + 8, TITLE_SIZE, INK)
    app._brightness_control(frame, _brightness_y())
    app._format_switcher(frame, name, "psbt-qr-prev", "psbt-qr-next")


def _brightness_y() -> int:
    return _FORMAT_TOP - _CONTROL_GAP - _BRIGHTNESS_HEIGHT


def _explorer_y() -> int:
    return _brightness_y() - _CONTROL_GAP - _BRIGHTNESS_HEIGHT


def _paste_qr(frame, image) -> int:
    left = (WIDTH - image.width) // 2
    top = HEADER + MARGIN
    frame.image.paste(image, (left, top))
    return top + image.height


def _body(app, frame, view, paint: bool, offset: int) -> int:
    y = 0
    for part in _parts(app, view):
        y = part["paint"](frame, y, paint, offset)
    return y


def _parts(app, view) -> list:
    """The column, top to bottom.

    A retained part is a fixed block or one chevron mode. Its picture stays
    after the first draw. A card is not retained: only its height is kept,
    and its picture exists while the card meets the screen or a neighbor.
    """
    parts = []

    def add(key, painter, retain, height_key=None):
        parts.append({
            "picture_key": key,
            "height_key": key if height_key is None else height_key,
            "paint": painter,
            "retain": retain,
        })

    name = view["wallet_name"]
    account = view["account_line"]

    def wallet(frame, y, paint, offset):
        y += HEADER + 16
        y = _centered_flow(frame, "Spending from Wallet:", y, paint, offset, TITLE_SIZE, INK)
        y = _name_center(frame, name, y, paint, offset, TITLE_SIZE, INK)
        return _wrapped_center(frame, account, y, paint, offset, TITLE_SIZE, INK)

    add(("wallet", name, account), wallet, True)

    txid_open = bool(app.psbt_txid_open)
    rows = tuple(view["txid_rows"])

    def txid(frame, y, paint, offset, open_now=txid_open, lines=rows):
        y = _chevron(frame, y, paint, offset, "Transaction Id", open_now, "psbt-toggle-txid")
        if open_now:
            for row in lines:
                y = _centered_flow(frame, row, y, paint, offset, TXID_SIZE, INK, mono=True)
        return y

    add(("txid", txid_open, rows), txid, True)

    banner = view["banner"]
    if banner:
        def banner_paint(frame, y, paint, offset, text=banner):
            return _wrapped(app, frame, text, y + 8, paint, offset, TITLE_SIZE, MUTED)

        add(("banner", banner), banner_paint, True)

    more = view["more_info"]
    if more:
        more_open = bool(app.psbt_more_open)

        def more_paint(frame, y, paint, offset, text=more, open_now=more_open):
            y = _chevron(frame, y, paint, offset, "More Information", open_now, "psbt-toggle-more")
            if open_now:
                y = _wrapped(app, frame, text, y, paint, offset, TITLE_SIZE, MUTED)
            return y

        add(("more", more_open, more), more_paint, True)

    warnings = tuple(view["warnings"])
    if warnings:
        frozen = tuple(
            (item["text"], item["tone"], item.get("center") or "", item.get("after") or "")
            for item in warnings
        )

        def warnings_paint(frame, y, paint, offset, items=warnings):
            title = "Warning" if len(items) == 1 else "Warnings"
            y = _centered_flow(frame, title, y + 8, paint, offset, TITLE_SIZE, WARNING)
            for item in items:
                tone = _TONE[item["tone"]]
                y = _wrapped(app, frame, item["text"], y, paint, offset, TITLE_SIZE, tone)
                if item.get("center"):
                    y = _centered_flow(frame, item["center"], y, paint, offset, TITLE_SIZE, tone)
                if item.get("after"):
                    y = _wrapped(app, frame, item["after"], y, paint, offset, TITLE_SIZE, tone)
            return y

        add(("warnings", frozen), warnings_paint, True)

    note = view["outputs_note"]
    if note:
        def outputs_note(frame, y, paint, offset, text=note):
            return _wrapped(app, frame, text, y + 8, paint, offset, TITLE_SIZE, MUTED)

        add(("outputs-note", note), outputs_note, True)
    else:
        outputs_open = bool(app.psbt_outputs_open)
        label = _count_label("Output", len(view["outputs"]))

        def outputs_head(frame, y, paint, offset, open_now=outputs_open, title=label):
            return _chevron(frame, y + 8, paint, offset, title, open_now, "psbt-toggle-outputs")

        add(("outputs-head", outputs_open, label), outputs_head, True)
        if outputs_open:
            for card in view["outputs"]:
                shape = _output_shape(app, card)
                add(
                    ("output", card["index"], shape),
                    _card_painter(app, card, "output"),
                    False,
                    ("output", shape),
                )

    fee_fill = RED if view["fee_high"] else INK
    fee_text = format_btc(view["fee"])
    fee_rate = view["fee_rate"]
    rate_size = _fee_rate_size(view, fee_text)

    def fee(frame, y, paint, offset, text=fee_text, fill=fee_fill, rate=fee_rate, size=rate_size):
        y += 8
        y = _wrapped(app, frame, "Absolute Fee (BTC):", y, paint, offset, TITLE_SIZE, fill)
        y = _amount_flow(frame, text, y, paint, offset, fill)
        y = _wrapped(app, frame, "Fee Rate:", y, paint, offset, TITLE_SIZE, fill)
        return _centered_flow(frame, f"~{rate} sat/vB", y, paint, offset, size, fill)

    add(("fee", fee_text, view["fee_high"], fee_rate, rate_size), fee, True)

    lock_label = view["locktime_label"]
    lock_tone = view["locktime_tone"]
    relative = view["relative_line"]

    def locktime(frame, y, paint, offset, label=lock_label, tone=lock_tone, line=relative):
        y += 8
        y = _wrapped(app, frame, label, y, paint, offset, TITLE_SIZE, _TONE[tone])
        if line:
            y = _wrapped(app, frame, line, y, paint, offset, TITLE_SIZE, WARNING)
        return y

    add(("locktime", lock_label, lock_tone, relative), locktime, True)

    change_outputs = view["change_outputs"]
    if not change_outputs:
        def no_change(frame, y, paint, offset):
            return _section_label(frame, y + 8, paint, offset, "0 Change Outputs")

        add(("change-none",), no_change, True)
    else:
        change_open = bool(app.psbt_change_open)
        change_label = _count_label("Change Output", len(change_outputs))

        def change_head(frame, y, paint, offset, open_now=change_open, title=change_label):
            return _chevron(frame, y + 8, paint, offset, title, open_now, "psbt-toggle-change")

        add(("change-head", change_open, change_label), change_head, True)
        if change_open:
            for index, card in enumerate(change_outputs):
                shape = _change_shape(card)
                add(
                    ("change", index, shape),
                    _card_painter(app, card, "change"),
                    False,
                    ("change", shape),
                )

    inputs_open = bool(app.psbt_inputs_open)
    inputs_label = _count_label("Input", len(view["inputs"]))

    def inputs_head(frame, y, paint, offset, open_now=inputs_open, title=inputs_label):
        return _chevron(frame, y + 8, paint, offset, title, open_now, "psbt-toggle-inputs")

    add(("inputs-head", inputs_open, inputs_label), inputs_head, True)
    if inputs_open:
        for card in view["inputs"]:
            shape = _input_shape(view, card)
            add(
                ("input", card["index"], shape),
                _card_painter(app, card, "input"),
                False,
                ("input", shape),
            )

    sign_key = _sign_key(app, view)

    def signs(frame, y, paint, offset):
        return _sign_controls(app, frame, y + 12, paint, offset)

    add(sign_key, signs, True)
    return parts


def _sign_controls(app, frame, y, paint, offset) -> int:
    note = app.psbt_view.get("signature_note") or ""
    if note:
        y = _wrapped(app, frame, note, y, paint, offset, TITLE_SIZE, MUTED)
        y += 8
    signers = app.psbt_view["signers"]
    signing = app._psbt_signing
    signing_fp = None if app._psbt_signing_fp is None else app._psbt_signing_fp.hex()
    if len(signers) <= 1:
        signer = signers[0] if signers else None
        if signing:
            y = app._flow_button(frame, y, "Signing\u2026", "psbt-sign", paint, offset, enabled=False)
        else:
            enabled = signer is not None and not signer["signed"]
            y = app._flow_button(frame, y, "Sign Transaction", "psbt-sign", paint, offset, enabled=enabled)
        if signer and signer["signed"] and not signing:
            y = _wrapped_center(frame, signer["note"], y, paint, offset, TITLE_SIZE, MUTED)
        return y
    for signer in signers:
        action = f"psbt-sign-{signer['fingerprint']}"
        if signing and signing_fp == signer["fingerprint"]:
            y = app._flow_button(frame, y, "Signing\u2026", action, paint, offset, enabled=False)
        else:
            y = app._flow_button(
                frame,
                y,
                signer["button"],
                action,
                paint,
                offset,
                enabled=not signer["signed"] and not signing,
            )
        if signer["signed"] and not (signing and signing_fp == signer["fingerprint"]):
            y = _wrapped_center(frame, signer["note"], y, paint, offset, TITLE_SIZE, MUTED)
    y += 8
    y = app._flow_button(
        frame, y, "Continue", "psbt-continue", paint, offset, enabled=app.psbt_continue and not signing,
    )
    return y


def _output_shape(app, card):
    if card["kind"] == "op_return":
        return ("op_return", len(format_btc(card["amount"], bare_zero=True)), bool(card["amount"]))
    owned = app.psbt_found.get(card["index"], card["owned"])
    amount = len(format_btc(card["amount"]))
    if owned:
        return ("owned", len(card["address"]), owned["name"], owned["account_line"], owned["place"], amount)
    return ("external", len(card["address"]), amount)


def _input_shape(view, card):
    relative = card["relative"]
    lock = None if relative is None else (relative["kind"], relative["duration"], bool(view["locktime"]))
    return (len(format_btc(card["amount"])), card["rbf_disabled"], lock)


def _change_shape(card):
    return (len(card["address"]), card["place"], len(format_btc(card["amount"])))


def _output_card(app, frame, y, paint, offset, card) -> int:
    start = y
    cursor = y + 16
    if card["kind"] == "op_return":
        cursor = _centered_flow(frame, "OP_RETURN", cursor, paint, offset, TITLE_SIZE, INK)
    else:
        cursor = _address_flow(app, frame, card["address"], cursor, paint, offset)
        owned = app.psbt_found.get(card["index"], card["owned"])
        if owned:
            cursor = _card_text(frame, "Wallet:", cursor, paint, offset, TITLE_SIZE, INK)
            cursor = _name_center(frame, owned["name"], cursor, paint, offset, TITLE_SIZE, INK)
            cursor = _centered_flow(frame, owned["account_line"], cursor, paint, offset, TITLE_SIZE, INK)
            cursor = _centered_flow(frame, owned["place"], cursor, paint, offset, TITLE_SIZE, INK)
        else:
            cursor += 12
            cursor = _centered_flow(frame, "External Address", cursor, paint, offset, TITLE_SIZE, INK)
            cursor += 12
            cursor = _card_button(
                frame, cursor, "Search for Address in Loaded Wallets", f"psbt-search-{card['index']}-0", paint, offset,
            )
            cursor += 12
    if card["kind"] != "op_return":
        cursor = _btc_amount(frame, cursor, paint, offset, card["amount"], INK)
    else:
        fill = RED if card["amount"] else INK
        cursor += 16
        cursor = _btc_amount(frame, cursor, paint, offset, card["amount"], fill, bare_zero=True)
        cursor += 16
        cursor = _card_button(
            frame, cursor, "Show OP_RETURN Content", f"psbt-opreturn-{card['index']}", paint, offset,
        )
    height = cursor - start + 8
    if paint:
        top = start - offset
        frame.draw.rounded_rectangle(
            (MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=WHITE, outline=LINE,
        )
        # The card is painted after the text, so paint the text again on top.
        return _output_card_text(app, frame, start, offset, card, height)
    return start + height + 12


def _output_card_text(app, frame, start, offset, card, height):
    """Draw the card contents after the white rectangle."""
    cursor = start + 16
    if card["kind"] == "op_return":
        cursor = _centered_flow(frame, "OP_RETURN", cursor, True, offset, TITLE_SIZE, INK)
        fill = RED if card["amount"] else INK
        cursor += 16
        cursor = _btc_amount(frame, cursor, True, offset, card["amount"], fill, bare_zero=True)
        cursor += 16
        cursor = _card_button(
            frame, cursor, "Show OP_RETURN Content", f"psbt-opreturn-{card['index']}", True, offset,
        )
    else:
        cursor = _address_flow(app, frame, card["address"], cursor, True, offset)
        owned = app.psbt_found.get(card["index"], card["owned"])
        if owned:
            cursor = _card_text(frame, "Wallet:", cursor, True, offset, TITLE_SIZE, INK)
            cursor = _name_center(frame, owned["name"], cursor, True, offset, TITLE_SIZE, INK)
            cursor = _centered_flow(frame, owned["account_line"], cursor, True, offset, TITLE_SIZE, INK)
            cursor = _centered_flow(frame, owned["place"], cursor, True, offset, TITLE_SIZE, INK)
        else:
            cursor += 12
            cursor = _centered_flow(frame, "External Address", cursor, True, offset, TITLE_SIZE, INK)
            cursor += 12
            cursor = _card_button(
                frame, cursor, "Search for Address in Loaded Wallets", f"psbt-search-{card['index']}-0", True, offset,
            )
            cursor += 12
        cursor = _btc_amount(frame, cursor, True, offset, card["amount"], INK)
    return start + height + 12


def _change_card(app, frame, y, paint, offset, card) -> int:
    start = y
    cursor = _change_body(app, frame, card, y + 16, False, offset)
    height = cursor - start + 8
    if paint:
        top = start - offset
        frame.draw.rounded_rectangle(
            (MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=WHITE, outline=LINE,
        )
        _change_body(app, frame, card, start + 16, True, offset)
    return start + height + 12


def _change_body(app, frame, card, cursor, paint, offset) -> int:
    cursor = _address_flow(app, frame, card["address"], cursor, paint, offset)
    cursor += 8
    fill = WARNING if card["receive_change"] else INK
    cursor = _centered_flow(frame, card["place"], cursor, paint, offset, TITLE_SIZE, fill)
    return _btc_amount(frame, cursor, paint, offset, card["amount"], INK)


def _input_card(app, frame, y, paint, offset, card) -> int:
    start = y
    cursor = y + 16
    cursor = _input_body(app, frame, card, cursor, paint, offset)
    height = cursor - start + 8
    if paint:
        top = start - offset
        frame.draw.rounded_rectangle((MARGIN, top, WIDTH - MARGIN, top + height), radius=16, fill=WHITE, outline=LINE)
        return _input_words(app, frame, start, offset, card)
    return start + height + 12


def _input_words(app, frame, start, offset, card) -> int:
    return _input_body(app, frame, card, start + 16, True, offset) + 20


def _input_body(app, frame, card, cursor, paint, offset) -> int:
    cursor = _card_text(frame, f"Input #{card['index']}", cursor, paint, offset, TITLE_SIZE, INK)
    cursor = _card_text(frame, "Previous Transaction Id:", cursor, paint, offset, TITLE_SIZE, MUTED)
    for row in card["txid_rows"]:
        cursor = _centered_flow(frame, row, cursor, paint, offset, TXID_SIZE, INK, mono=True)
    cursor = _card_text(frame, f"Output Index: {card['vout']}", cursor, paint, offset, TITLE_SIZE, INK)
    cursor += 16
    cursor = _btc_amount(frame, cursor, paint, offset, card["amount"], INK)
    cursor += 16
    cursor = _sequence_line(frame, cursor, paint, offset, card["sequence"])
    if card["rbf_disabled"]:
        cursor = _card_text(frame, "Replace-by-Fee (RBF) Disabled", cursor, paint, offset, TITLE_SIZE, WARNING)
        cursor = _card_text(
            frame, "The Bitcoin network no longer honors this flag.", cursor, paint, offset, TITLE_SIZE, WARNING,
        )
    relative = card["relative"]
    if relative:
        cursor = _card_text(frame, relative["label"], cursor, paint, offset, TITLE_SIZE, WARNING)
        if relative["kind"] == "time":
            cursor = _comma_centered(frame, relative["duration"], cursor, paint, offset, TITLE_SIZE, WARNING)
        else:
            cursor = _centered_flow(frame, relative["duration"], cursor, paint, offset, TITLE_SIZE, WARNING)
        if relative["kind"] == "time":
            note = (
                "This transaction can be mined only after that time since the previous transaction was mined. "
                "The time is calculated from the median timestamp reported in recent blocks, "
                "so it can differ significantly from the real current time."
            )
        else:
            note = (
                "This transaction can be mined only after that many blocks "
                "since the previous transaction was mined."
            )
        if app.psbt_view["locktime"]:
            note += " This is an additional requirement on top of the absolute locktime."
        cursor = _card_text(frame, note, cursor, paint, offset, TITLE_SIZE, WARNING)
    cursor += 16
    cursor = _card_button(
        frame, cursor, "Show Input QR", f"psbt-input-qr-{card['index']}", paint, offset,
    )
    return cursor


def _card_button(frame, y, label, action, paint, offset, enabled=True) -> int:
    height = frame.button_height(label)
    top = y - offset
    # rounded_rectangle includes the bottom row, so the span is one past height.
    box = (MARGIN + 16, top, WIDTH - MARGIN - 16, top + height)
    if paint and _strip_visible(frame, top, height + 1):
        color = BLUE if enabled else (186, 190, 196)
        text = WHITE if enabled else (132, 136, 142)
        frame.draw.rounded_rectangle(box, radius=14, fill=color)
        face = font(36)
        lines = wrap(frame.draw, label, face, box[2] - box[0] - 24)
        line_h = 42
        text_y = top + (height - line_h * len(lines)) / 2
        for index, line in enumerate(lines):
            width = frame.draw.textlength(line, font=face)
            x = (box[0] + box[2] - width) / 2
            frame.draw.text((x, text_y + index * line_h), line, font=face, fill=text)
        frame.mark(label, box)
        if enabled:
            frame.hit(box, action, label)
    return y + height + 12


def _address_flow(app, frame, address, y, paint, offset) -> int:
    height = app._grouped_address(frame, address, 0, paint=False)
    if paint:
        app._grouped_address(frame, address, y - offset, paint=True)
    return y + height


def _chevron(frame, y, paint, offset, title, open_now, action) -> int:
    height = TITLE_SIZE + 20
    top = y - offset
    if paint and _strip_visible(frame, top, height):
        text_y = top + 4
        _left, ink_top, _right, ink_bottom = frame.draw.textbbox((0, 0), title, font=font(TITLE_SIZE))
        _section_chevron(frame, open_now, MARGIN + 16, text_y + (ink_top + ink_bottom - 1) / 2)
        frame.text(title, MARGIN + 40, text_y, size=TITLE_SIZE)
        frame.hit((MARGIN, top, WIDTH - MARGIN, top + height), action, title)
    return y + height + 8


def _section_label(frame, y, paint, offset, title) -> int:
    height = TITLE_SIZE + 20
    top = y - offset
    if paint and _strip_visible(frame, top, height):
        frame.text(title, MARGIN + 40, top + 4, size=TITLE_SIZE)
    return y + height + 8


def _count_label(word: str, count: int) -> str:
    noun = word if count == 1 else word + "s"
    return f"{count} {noun}"


def _op_card(app):
    view = app.psbt_view
    if not view:
        return None
    for card in view["outputs"]:
        if card["index"] == app.psbt_op_index and card["kind"] == "op_return":
            return card
    return None


def _wrapped(app, frame, text, y, paint, offset, size, fill) -> int:
    return app._flow_text(frame, y, text, paint, offset, size, fill=fill)


def _btc_size(text: str) -> int:
    return AMOUNT_SIZE if len(text) > 13 else AMOUNT_SIZE_LARGE


def _fee_rate_size(view, fee_text: str) -> int:
    """Larger than the label, and smaller than every bitcoin amount on the screen."""
    sizes = [_btc_size(fee_text)]
    for card in view["outputs"] + view["change_outputs"]:
        sizes.append(_btc_size(format_btc(card["amount"], bare_zero=card["kind"] == "op_return")))
    for card in view["inputs"]:
        sizes.append(_btc_size(format_btc(card["amount"])))
    limit = min(sizes)
    return 40 if limit > 40 else TITLE_SIZE


def _btc_amount(frame, y, paint, offset, amount, fill, bare_zero=False) -> int:
    """A zero amount shares the label line: ``Amount (BTC): 0``."""
    if int(amount) == 0:
        return _zero_amount_line(frame, y, paint, offset)
    shown = format_btc(amount, bare_zero=bare_zero)
    y = _card_text(frame, "Amount (BTC):", y, paint, offset, TITLE_SIZE, MUTED)
    return _amount_flow(frame, shown, y, paint, offset, fill)


def _zero_amount_line(frame, y, paint, offset) -> int:
    label = "Amount (BTC): "
    value = "0"
    face = font(TITLE_SIZE)
    x = MARGIN + 16
    if paint:
        yy = y - offset
        if _strip_visible(frame, yy, ink_span(TITLE_SIZE)):
            frame.draw.text((x, yy), label, font=face, fill=MUTED)
            frame.draw.text((x + frame.draw.textlength(label, font=face), yy), value, font=face, fill=INK)
            frame.mark(label + value, frame.draw.textbbox((x, yy), label + value, font=face))
    return y + TITLE_SIZE + 8


def _amount_flow(frame, text, y, paint, offset, fill) -> int:
    return _centered_flow(frame, text, y, paint, offset, _btc_size(text), fill)


def _section_chevron(frame, open_now: bool, cx: float, cy: float):
    if open_now:
        frame.glyph(Icons.CHEVRON_DOWN, cx, cy, 28, INK)
        return
    rendered = glyph_sprite(Icons.CHEVRON_DOWN, 28, INK)
    if rendered is None:
        return
    image, _center = rendered
    turned = image.rotate(90, expand=True)
    ink = turned.getchannel("A").point(lambda alpha: 255 if alpha > 16 else 0).getbbox()
    if ink is None:
        return
    min_x, min_y, right_edge, bottom_edge = ink
    ink_cx = (min_x + right_edge - 1) / 2
    ink_cy = (min_y + bottom_edge - 1) / 2
    frame.image.paste(
        turned,
        (round(cx - ink_cx), round(cy - ink_cy)),
        turned,
    )


def _sequence_line(frame, y, paint, offset, sequence: int) -> int:
    label = "Sequence: "
    value = f"0x{int(sequence):08X}"
    face = font(TITLE_SIZE)
    mono = font(TITLE_SIZE, mono=True)
    x = MARGIN + 16
    if paint:
        yy = y - offset
        if _strip_visible(frame, yy, ink_span(TITLE_SIZE)):
            frame.draw.text((x, yy), label, font=face, fill=MUTED)
            label_w = frame.draw.textlength(label, font=face)
            frame.draw.text((x + label_w, yy), value, font=mono, fill=INK)
            frame.mark(label + value, frame.draw.textbbox((x, yy), label + value, font=face))
    return y + TITLE_SIZE + 8


def _card_text(frame, text, y, paint, offset, size, fill) -> int:
    face = font(size)
    lines = wrap(frame.draw, text, face, WIDTH - 2 * MARGIN - 32) or [""]
    x = MARGIN + 16
    if paint:
        for index, line in enumerate(lines):
            yy = y - offset + index * (size + 8)
            if _strip_visible(frame, yy, ink_span(size)):
                frame.draw.text((x, yy), line, font=face, fill=fill)
                frame.mark(line, frame.draw.textbbox((x, yy), line, font=face))
    return y + len(lines) * (size + 8)


def _name_center(frame, text, y, paint, offset, size, fill) -> int:
    face = font(size)
    for line in _wrap_name(frame.draw, text, face, WIDTH - 2 * MARGIN) or [""]:
        y = _centered_flow(frame, line, y, paint, offset, size, fill)
    return y


def _wrap_name(draw, text, face, width) -> list[str]:
    """Wrap a wallet name.

    A word of two letters or fewer stays with the word before it. A
    comma-separated list, such as multisig fingerprints, may break after a
    comma. The comma stays on the line it ended. A space after a comma stays
    a space, and a break at that space drops the space.
    """
    pieces = []
    for word_index, word in enumerate(text.split(" ")):
        chunks = [word] if "," not in word else []
        if not chunks:
            parts = word.split(",")
            for index, part in enumerate(parts):
                if index < len(parts) - 1:
                    chunks.append(part + ",")
                elif part:
                    chunks.append(part)
            chunks = chunks or [""]
        for chunk_index, chunk in enumerate(chunks):
            pieces.append((chunk, word_index > 0 and chunk_index == 0))
    lines = []
    current = []

    def joined(parts) -> str:
        text = ""
        for chunk, spaced in parts:
            if not text or not spaced:
                text += chunk
            else:
                text += " " + chunk
        return text

    def length(parts) -> float:
        return draw.textlength(joined(parts), font=face)

    for piece in pieces:
        if not current or length(current + [piece]) <= width:
            current.append(piece)
            continue
        if len(piece[0]) <= 2 and current:
            carried = current.pop()
            if current:
                lines.append(joined(current))
            current = [carried, piece]
            continue
        lines.append(joined(current))
        current = [piece]
    if current:
        lines.append(joined(current))
    return lines


def _comma_lines(draw, text: str, face, width: int) -> list[str]:
    """Wrap only after a comma. A line keeps the comma that ended it."""
    if draw.textlength(text, font=face) <= width:
        return [text]
    pieces = [part.strip() for part in text.split(",") if part.strip()]
    chunks = [f"{part}," for part in pieces[:-1]]
    if pieces:
        chunks.append(pieces[-1])
    lines = []
    current = ""
    for chunk in chunks:
        trial = chunk if not current else f"{current} {chunk}"
        if current and draw.textlength(trial, font=face) > width:
            lines.append(current)
            current = chunk
        else:
            current = trial
    if current:
        lines.append(current)
    return lines or [text]


def _comma_centered(frame, text, y, paint, offset, size, fill) -> int:
    face = font(size)
    for line in _comma_lines(frame.draw, text, face, WIDTH - 2 * MARGIN):
        y = _centered_flow(frame, line, y, paint, offset, size, fill)
    return y


def _wrapped_center(frame, text, y, paint, offset, size, fill) -> int:
    face = font(size)
    for line in wrap(frame.draw, text, face, WIDTH - 2 * MARGIN) or [""]:
        y = _centered_flow(frame, line, y, paint, offset, size, fill)
    return y


def _centered_flow(frame, text, y, paint, offset, size, fill, mono=False) -> int:
    if paint:
        _centered(frame, text, y - offset, size, fill, mono=mono)
    return y + size + 8


def _centered(frame, text, y, size, fill, mono=False):
    if not _strip_visible(frame, y, ink_span(size)):
        return
    face = font(size, mono=mono)
    width = frame.draw.textlength(text, font=face)
    x = (WIDTH - width) / 2
    frame.draw.text((x, y), text, font=face, fill=fill)
    frame.mark(text, frame.draw.textbbox((x, y), text, font=face))

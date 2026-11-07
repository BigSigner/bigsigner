"""The Transaction Signing screen, the OP_RETURN page, and the signed-PSBT QR."""

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
    RED,
    TITLE_SIZE,
    WARNING,
    WHITE,
    WIDTH,
    Icons,
    font,
    glyph_sprite,
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
# Keep a few screen-tall tiles around the scroll position. A full sheet of
# open inputs would be tens of megabytes on this panel.
_PSBT_TILE = HEIGHT
_PSBT_TILE_PAD = 1


def _clip_top(frame) -> int:
    """Title bar on a normal frame; 0 when painting a scroll tile strip."""
    return getattr(frame, "clip_top", HEADER)


def paint_signing(app, frame):
    view = app.psbt_view
    if not view:
        frame.header("Transaction Signing", "back")
        frame.text("This transaction is no longer loaded.", MARGIN, HEADER + 24, size=TITLE_SIZE)
        return
    key = _signing_sheet_key(app)
    sheet = app._psbt_sheet
    reused = sheet is not None and sheet["key"] == key
    if not reused:
        sheet = _new_signing_sheet(app, view, key)
        app._psbt_sheet = sheet
    offset = app._scroll_offset("psbt-yaml", sheet["end"], clearance=16)
    covered = _signing_tiles_cover(sheet, offset)
    _ensure_signing_tiles(app, sheet, view, offset)
    _blit_signing_tiles(frame, sheet, offset)
    frame.header("Transaction Signing", "back")
    # The body is already drawn. A drag only copies the visible slice.
    if reused and covered and app._press is not None:
        app.dirty = (HEADER, HEIGHT)


def _signing_sheet_key(app):
    view = app.psbt_view
    signing_fp = app._psbt_signing_fp.hex() if app._psbt_signing_fp is not None else None
    return (
        id(view),
        app.psbt_outputs_open,
        app.psbt_inputs_open,
        app.psbt_change_open,
        app.psbt_more_open,
        app.psbt_txid_open,
        app.psbt_continue,
        app._psbt_signing,
        signing_fp,
        tuple(
            (signer["fingerprint"], signer["signed"], signer.get("note") or "")
            for signer in (view or {}).get("signers", ())
        ),
        (view or {}).get("signature_note") or "",
    )


def _new_signing_sheet(app, view, key) -> dict:
    probe = Frame()
    end = _body(app, probe, view, paint=False, offset=0)
    return {"key": key, "end": max(end, HEIGHT), "tiles": {}}


def _signing_tiles_cover(sheet, offset: int) -> bool:
    first = max(0, (offset // _PSBT_TILE) - _PSBT_TILE_PAD) * _PSBT_TILE
    last = min(sheet["end"], offset + HEIGHT + _PSBT_TILE * _PSBT_TILE_PAD)
    y = first
    while y < last:
        if y not in sheet["tiles"]:
            return False
        y += _PSBT_TILE
    return True


def _ensure_signing_tiles(app, sheet, view, offset: int) -> None:
    first = max(0, (offset // _PSBT_TILE) - _PSBT_TILE_PAD) * _PSBT_TILE
    last = min(sheet["end"], offset + HEIGHT + _PSBT_TILE * _PSBT_TILE_PAD)
    needed = []
    y = first
    while y < last:
        needed.append(y)
        y += _PSBT_TILE
    keep = set(needed)
    for tile_y in list(sheet["tiles"]):
        if tile_y not in keep:
            del sheet["tiles"][tile_y]
    for tile_y in needed:
        if tile_y in sheet["tiles"]:
            continue
        tile = Frame()
        # Fill the whole strip. The live screen keeps clip_top at HEADER so the
        # title bar is not painted over; a tile has no title bar of its own.
        tile.clip_top = 0
        _body(app, tile, view, paint=True, offset=tile_y)
        height = min(_PSBT_TILE, max(0, sheet["end"] - tile_y))
        if height <= 0:
            continue
        image = tile.image.crop((0, 0, WIDTH, height))
        hits = []
        for hit in tile.hits:
            box = hit["box"]
            hits.append(
                {
                    "box": (box[0], box[1] + tile_y, box[2], box[3] + tile_y),
                    "action": hit["action"],
                    "label": hit.get("label", ""),
                }
            )
        marks = []
        for mark in tile.marks:
            box = mark["box"]
            marks.append(
                {
                    "text": mark["text"],
                    "box": [box[0], box[1] + tile_y, box[2], box[3] + tile_y],
                }
            )
        sheet["tiles"][tile_y] = {"image": image, "hits": hits, "marks": marks}


def _blit_signing_tiles(frame, sheet, offset: int) -> None:
    bottom = offset + HEIGHT
    seen_hits = set()
    for tile_y, tile in sheet["tiles"].items():
        image = tile["image"]
        tile_bottom = tile_y + image.height
        if tile_bottom <= offset or tile_y >= bottom:
            continue
        src_top = max(0, offset - tile_y)
        dst_top = max(0, tile_y - offset)
        src_bottom = min(image.height, bottom - tile_y)
        if src_bottom <= src_top:
            continue
        frame.image.paste(
            image.crop((0, src_top, WIDTH, src_bottom)),
            (0, dst_top),
        )
        for hit in tile["hits"]:
            box = hit["box"]
            top = box[1] - offset
            bot = box[3] - offset
            if bot <= HEADER or top >= HEIGHT:
                continue
            key = (hit["action"], int(box[0]), int(box[1]), int(box[2]), int(box[3]))
            if key in seen_hits:
                continue
            seen_hits.add(key)
            frame.hit((box[0], top, box[2], bot), hit["action"], hit.get("label", ""))
        for mark in tile["marks"]:
            box = mark["box"]
            top = box[1] - offset
            bot = box[3] - offset
            if bot > HEADER and top < HEIGHT:
                frame.marks.append(
                    {"text": mark["text"], "box": [box[0], int(top), box[2], int(bot)]}
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
    y = HEADER + 16
    y = _centered_flow(frame, "Spending from Wallet:", y, paint, offset, TITLE_SIZE, INK)
    y = _name_center(frame, view["wallet_name"], y, paint, offset, TITLE_SIZE, INK)
    y = _wrapped_center(frame, view["account_line"], y, paint, offset, TITLE_SIZE, INK)
    y = _chevron(frame, y, paint, offset, "Transaction Id", app.psbt_txid_open, "psbt-toggle-txid")
    if app.psbt_txid_open:
        for row in view["txid_rows"]:
            y = _centered_flow(frame, row, y, paint, offset, TXID_SIZE, INK, mono=True)
    if view["banner"]:
        y = _wrapped(app, frame, view["banner"], y + 8, paint, offset, TITLE_SIZE, MUTED)
    if view["more_info"]:
        y = _chevron(frame, y, paint, offset, "More Information", app.psbt_more_open, "psbt-toggle-more")
        if app.psbt_more_open:
            y = _wrapped(app, frame, view["more_info"], y, paint, offset, TITLE_SIZE, MUTED)
    warnings = view["warnings"]
    if warnings:
        title = "Warning" if len(warnings) == 1 else "Warnings"
        y = _centered_flow(frame, title, y + 8, paint, offset, TITLE_SIZE, WARNING)
        for item in warnings:
            tone = _TONE[item["tone"]]
            y = _wrapped(app, frame, item["text"], y, paint, offset, TITLE_SIZE, tone)
            if item.get("center"):
                y = _centered_flow(frame, item["center"], y, paint, offset, TITLE_SIZE, tone)
            if item.get("after"):
                y = _wrapped(app, frame, item["after"], y, paint, offset, TITLE_SIZE, tone)
    y += 8
    if view["outputs_note"]:
        y = _wrapped(app, frame, view["outputs_note"], y, paint, offset, TITLE_SIZE, MUTED)
    else:
        y = _chevron(
            frame, y, paint, offset, _count_label("Output", len(view["outputs"])),
            app.psbt_outputs_open, "psbt-toggle-outputs",
        )
        if app.psbt_outputs_open:
            for card in view["outputs"]:
                y = _place_card(
                    app, frame, y, paint, offset, ("output", _output_shape(app, card)),
                    lambda do_paint, off, start=y, item=card: _output_card(
                        app, frame, start, do_paint, off, item,
                    ),
                )
    y += 8
    fee_fill = RED if view["fee_high"] else INK
    fee_text = format_btc(view["fee"])
    y = _wrapped(app, frame, "Absolute Fee (BTC):", y, paint, offset, TITLE_SIZE, fee_fill)
    y = _amount_flow(frame, fee_text, y, paint, offset, fee_fill)
    y = _wrapped(app, frame, "Fee Rate:", y, paint, offset, TITLE_SIZE, fee_fill)
    y = _centered_flow(
        frame, f"~{view['fee_rate']} sat/vB", y, paint, offset, _fee_rate_size(view, fee_text), fee_fill,
    )
    y += 8
    y = _wrapped(app, frame, view["locktime_label"], y, paint, offset, TITLE_SIZE, _TONE[view["locktime_tone"]])
    if view["relative_line"]:
        y = _wrapped(app, frame, view["relative_line"], y, paint, offset, TITLE_SIZE, WARNING)
    y += 8
    change_outputs = view["change_outputs"]
    if not change_outputs:
        y = _section_label(frame, y, paint, offset, "0 Change Outputs")
    else:
        y = _chevron(
            frame, y, paint, offset, _count_label("Change Output", len(change_outputs)),
            app.psbt_change_open, "psbt-toggle-change",
        )
        if app.psbt_change_open:
            for card in change_outputs:
                y = _place_card(
                    app, frame, y, paint, offset, ("change", _change_shape(card)),
                    lambda do_paint, off, start=y, item=card: _change_card(
                        app, frame, start, do_paint, off, item,
                    ),
                )
    y += 8
    y = _chevron(frame, y, paint, offset, _count_label("Input", len(view["inputs"])), app.psbt_inputs_open, "psbt-toggle-inputs")
    if app.psbt_inputs_open:
        for card in view["inputs"]:
            y = _place_card(
                app, frame, y, paint, offset, ("input", _input_shape(view, card)),
                lambda do_paint, off, start=y, item=card: _input_card(
                    app, frame, start, do_paint, off, item,
                ),
            )
    y += 12
    y = _sign_controls(app, frame, y, paint, offset)
    return y


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


def _place_card(app, frame, y, paint, offset, key, draw) -> int:
    """Reuse a measured card height, and draw it only when it is on screen."""
    span = app._psbt_heights.get(key)
    if span is None:
        span = draw(False, 0) - y
        app._psbt_heights[key] = span
    top = y - offset
    if paint and top < HEIGHT and top + span > _clip_top(frame):
        draw(True, offset)
    return y + span


def _output_shape(app, card):
    if card["kind"] == "op_return":
        return ("op_return", len(format_btc(card["amount"], bare_zero=True)), bool(card["amount"]))
    owned = app.psbt_found.get(card["index"], card["owned"])
    amount = len(format_btc(card["amount"]))
    if owned:
        return ("owned", len(card["address"]), owned["name"], owned["account_line"], owned["place"], amount)
    searching = bool(app.psbt_search and app.psbt_search["index"] == card["index"])
    return ("external", len(card["address"]), searching, amount)


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
            searching = app.psbt_search and app.psbt_search["index"] == card["index"]
            if searching:
                label, enabled = "Searching\u2026", False
            else:
                label, enabled = "Search for Address in Loaded Wallets", True
            cursor = _card_button(
                frame, cursor, label, f"psbt-search-{card['index']}-0", paint, offset, enabled=enabled,
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
            searching = app.psbt_search and app.psbt_search["index"] == card["index"]
            if searching:
                label, enabled = "Searching\u2026", False
            else:
                label, enabled = "Search for Address in Loaded Wallets", True
            cursor = _card_button(
                frame, cursor, label, f"psbt-search-{card['index']}-0", True, offset, enabled=enabled,
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
    box = (MARGIN + 16, top, WIDTH - MARGIN - 16, top + height)
    if paint and top + height > _clip_top(frame) and top < HEIGHT:
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
    if paint and top + height > _clip_top(frame) and top < HEIGHT:
        text_y = top + 4
        _left, ink_top, _right, ink_bottom = frame.draw.textbbox((0, 0), title, font=font(TITLE_SIZE))
        _section_chevron(frame, open_now, MARGIN + 16, text_y + (ink_top + ink_bottom - 1) / 2)
        frame.text(title, MARGIN + 40, text_y, size=TITLE_SIZE)
        frame.hit((MARGIN, top, WIDTH - MARGIN, top + height), action, title)
    return y + height + 8


def _section_label(frame, y, paint, offset, title) -> int:
    height = TITLE_SIZE + 20
    top = y - offset
    if paint and top + height > _clip_top(frame) and top < HEIGHT:
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
        if _clip_top(frame) <= yy < HEIGHT:
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
        if _clip_top(frame) <= yy < HEIGHT:
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
            if _clip_top(frame) <= yy < HEIGHT:
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
    face = font(size, mono=mono)
    width = frame.draw.textlength(text, font=face)
    x = (WIDTH - width) / 2
    frame.draw.text((x, y), text, font=face, fill=fill)
    frame.mark(text, frame.draw.textbbox((x, y), text, font=face))

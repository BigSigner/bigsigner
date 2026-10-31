"""One JSON line per painted frame, for a test driving the panel over SSH."""

import json

from ..ui.canvas import MARGIN, WIDTH


def snapshot(app, ms: int, frame: int) -> dict:
    """The screen the panel just painted, with a box for every recorded string."""
    hint = app.screen == "qr" and app.qr_hint_holding()
    panel = None if hint or not app.qr_scroll_box else [int(value) for value in app.qr_scroll_box]
    return {
        "frame": frame,
        "ms": ms,
        "screen": app.screen,
        "menu": bool(app.menu),
        "notice": app.notice or "",
        "scroll": int(app.scroll.get(app.screen, 0)),
        "scroll_max": int(app.scroll_max.get(app.screen, 0)),
        "qr_scroll": int(app.qr_scroll),
        "qr_scroll_max": int(app.qr_scroll_max),
        "hint": hint,
        "qr_panel": panel,
        "qr_box": _qr_box(app, hint),
        "hits": [
            {"label": hit["label"], "action": hit["action"], "box": [int(value) for value in hit["box"]]}
            for hit in app.hits
        ],
        "texts": list(app.texts),
        "qr_texts": _qr_texts(app, hint),
    }


def append_snapshot(path: str, app, ms: int, frame: int) -> None:
    line = json.dumps(snapshot(app, ms, frame), ensure_ascii=True, separators=(",", ":"))
    with open(path, "a", encoding="ascii") as handle:
        handle.write(line + "\n")
        handle.flush()


def _qr_texts(app, hint: bool) -> list[dict]:
    if hint or not app.qr_scroll_box:
        return []
    view_top, view_bottom = app.qr_scroll_box[1], app.qr_scroll_box[3]
    found = []
    for mark in app.qr_line_marks:
        top = view_top + mark["y"] - app.qr_scroll
        bottom = top + mark["h"]
        if bottom <= view_top or top >= view_bottom:
            continue
        found.append({"text": mark["text"], "box": [MARGIN, int(top), WIDTH - MARGIN, int(bottom)]})
    return found


def _qr_box(app, hint: bool):
    if hint or not app.qr_scroll_box or not app.qr_strip_size:
        return None
    size = int(app.qr_strip_size)
    left = (WIDTH - size) // 2
    top = int(app.qr_scroll_box[1] - app.qr_scroll)
    return [left, top, left + size, top + size]

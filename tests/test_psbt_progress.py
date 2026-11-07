"""Progress while a loaded PSBT is checked."""

from pathlib import Path

import bigsigner.ui.app as app_mod
from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.ui.app import App
from bigsigner.ui.canvas import BLUE, BODY_SIZE, HEIGHT
from test_psbt_load import _native, _psbt, _tap
from test_ui import ScreenRecord

# Same clearance as a bottom button row: the bar's bottom edge sits here.
_PROGRESS_BAR_BOTTOM = HEIGHT - 110
_PROGRESS_BAR_H = 28


def _progress_bar_top(image) -> int:
    """Top ink row of the filled blue bar."""
    for y in range(_PROGRESS_BAR_BOTTOM - _PROGRESS_BAR_H - 4, _PROGRESS_BAR_BOTTOM):
        if image.getpixel((MARGIN_SAMPLE, y)) == BLUE:
            return y
    raise AssertionError("progress bar fill was not found")


MARGIN_SAMPLE = 28


def test_check_loaded_psbt_reports_input_progress():
    session = _native()
    psbt = _psbt(session, extra_input=True)
    steps = []

    def progress(message, done, total):
        steps.append((message, done, total))

    check_loaded_psbt(session, 0, psbt, progress=progress)
    messages = [item[0] for item in steps]
    assert any(item.startswith("Reading transaction") for item in messages)
    assert "Parsing input 1 of 2" in messages
    assert "Parsing input 2 of 2" in messages
    assert "Checking input 1 of 2" in messages
    assert "Checking input 2 of 2" in messages
    assert "Checking output 1 of 1" in messages
    assert any(item.startswith("Checking signatures") for item in messages)
    assert steps[0][1] == 0
    assert steps[-1][1] == steps[-1][2]
    assert all(0 <= done <= total for _message, done, total in steps)


def test_accepting_a_psbt_paints_progress_then_opens_signing():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app.screen = "load-psbt"
    frames = []
    previous = app_mod.PSBT_PROGRESS_PAINT_S
    app_mod.PSBT_PROGRESS_PAINT_S = 0

    def flush():
        frames.append(
            {
                "screen": app.screen,
                "text": app.psbt_progress_text,
                "done": app.psbt_progress_done,
                "total": app.psbt_progress_total,
            }
        )
        app.render()

    app.flush_display = flush
    try:
        app._accept_psbt_text(_psbt(session).serialize(), "file")
    finally:
        app_mod.PSBT_PROGRESS_PAINT_S = previous
    assert app.screen == "psbt-yaml"
    assert frames
    assert frames[0]["screen"] == "psbt-progress"
    assert frames[0]["done"] == 0
    assert any(frame["done"] == frame["total"] for frame in frames)
    assert any("input" in frame["text"].lower() for frame in frames)
    mid = next(frame for frame in frames if frame["done"] > 0 and frame["done"] < frame["total"])
    record = ScreenRecord(Path("artifacts/screenshots") / "test_accepting_a_psbt_paints_progress_then_opens_signing")
    record.note("Progress has no title. The bar fills before Transaction Signing.")
    app.screen = "psbt-progress"
    app.psbt_progress_text = mid["text"]
    app.psbt_progress_done = mid["done"]
    app.psbt_progress_total = mid["total"]
    record.shot(app, "progress")
    assert not any(hit.get("action") == "back" for hit in app.hits)
    app.tap(240, 400)
    assert app.screen == "psbt-progress"


def test_the_progress_bar_stays_put_when_the_status_wraps():
    app = App()
    app.screen = "psbt-progress"
    app.psbt_progress_done = 40
    app.psbt_progress_total = 100
    app.psbt_progress_text = "Checking input 7 of 80"
    short = app.render()
    short_top = _progress_bar_top(short)
    app.psbt_progress_text = (
        "Checking a very long status line that wraps onto a second and third row "
        "so the bar must not climb the screen"
    )
    wrapped = app.render()
    wrapped_top = _progress_bar_top(wrapped)
    assert short_top == wrapped_top
    assert short_top == _PROGRESS_BAR_BOTTOM - _PROGRESS_BAR_H + 4
    record = ScreenRecord(Path("artifacts/screenshots") / "test_the_progress_bar_stays_put_when_the_status_wraps")
    record.note("The bar is fixed near the bottom. Status text is centered vertically.")
    record.shot(app, "wrapped")
    mid = next(item for item in app.texts if "wraps" in item["text"])
    assert abs((mid["box"][1] + mid["box"][3]) / 2 - HEIGHT / 2) < BODY_SIZE * 2


def test_a_refused_psbt_leaves_progress_for_the_error_screen():
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app.screen = "load-psbt"
    painted = []
    app.flush_display = lambda: painted.append(app.psbt_progress_text)
    bad = _psbt(session)
    bad.inputs[0].witness_utxo = None
    app._accept_psbt_text(bad.serialize(), "file")
    assert painted
    assert app.screen == "psbt-error"
    _tap(app, "OK")
    assert app.screen == "load-psbt"


def test_deferred_psbt_progress_advances_across_frames():
    """The browser paints progress when delay 0 asks for the next frame."""
    session = _native()
    app = App()
    app.session = session
    app.wallet_index = 0
    app.screen = "load-psbt"
    app.defer_psbt_progress = True
    previous = app_mod.PSBT_PROGRESS_PAINT_S
    app_mod.PSBT_PROGRESS_PAINT_S = 0
    try:
        app._accept_psbt_text(_psbt(session).serialize(), "file")
        assert app.screen == "psbt-progress"
        assert app.notice_delay() is None
        app.render()
        assert app._psbt_progress_shown
        assert app.notice_delay() == 0
        frames = 0
        while app.screen == "psbt-progress" and frames < 50:
            app.render()
            frames += 1
        assert app.screen == "psbt-yaml"
        assert frames >= 2
    finally:
        app_mod.PSBT_PROGRESS_PAINT_S = previous

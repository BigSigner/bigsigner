"""Transaction Signing tiles must match one continuous paint.

A scroll tile is one screen tall. A line, a card, or a button that starts on
one tile and ends on the next has to be drawn on both, or the stitch cuts the
glyph. Wrapping a multisig wallet name shifts every later line, so the cut
moves onto text that a shorter name left between the tiles.
"""

from embit.psbt import PSBT
from PIL import Image, ImageDraw

from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.psbt_view import describe_psbt
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEADER, HEIGHT, PAPER, TITLE_SIZE, WIDTH, Frame
from bigsigner.ui.psbt_screen import (
    _body,
    _card_button,
    _card_text,
    _centered_flow,
    _chevron,
    _input_card,
    _name_center,
    _sequence_line,
    _zero_amount_line,
)
from test_large_tx_scroll import MEDIUM_VECTOR, _native_bulk
from test_psbt_load import _native

# How far a line may start above the tile edge and still leave ink on it.
_ABOVE = 70
_BELOW = 24


def _continuous(paint, tall: int) -> Image.Image:
    frame = Frame()
    frame.image = Image.new("RGB", (WIDTH, tall), PAPER)
    frame.draw = ImageDraw.Draw(frame.image)
    frame.clip_top = 0
    frame.clip_bottom = tall
    paint(frame, 0)
    return frame.image


def _stitched(paint, tall: int) -> Image.Image:
    image = Image.new("RGB", (WIDTH, tall), PAPER)
    tile_y = 0
    while tile_y < tall:
        frame = Frame()
        frame.clip_top = 0
        paint(frame, tile_y)
        height = min(HEIGHT, tall - tile_y)
        image.paste(frame.image.crop((0, 0, WIDTH, height)), (0, tile_y))
        tile_y += HEIGHT
    return image


def _first_diff(got: Image.Image, expect: Image.Image):
    raw_got = got.tobytes()
    raw_expect = expect.tobytes()
    if raw_got == raw_expect:
        return None
    for index in range(0, len(raw_got), 3):
        if raw_got[index : index + 3] != raw_expect[index : index + 3]:
            pixel = index // 3
            return pixel % got.width, pixel // got.width
    return None


def _assert_stitch(paint, tall: int, label: str):
    diff = _first_diff(_stitched(paint, tall), _continuous(paint, tall))
    assert diff is None, f"{label} sliced at {diff}"


def _sweep(paint_at, label: str):
    """Move one element from above a tile edge to below it."""
    tall = HEIGHT * 2

    def paint(frame, offset, doc_y=None):
        paint_at(frame, offset, doc_y)

    for doc_y in range(HEIGHT - _ABOVE, HEIGHT + _BELOW):
        _assert_stitch(lambda frame, offset, y=doc_y: paint_at(frame, offset, y), tall, f"{label} at {doc_y}")


def test_text_that_crosses_a_tile_edge_is_not_sliced():
    app = App()
    app.psbt_view = {"locktime": 500000000}
    address = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    name = "2-of-3 " + ",".join(f"{index:016x}" for index in range(6))
    note = (
        "This transaction can be mined only after that time since the previous transaction was mined. "
        "The time is calculated from the median timestamp reported in recent blocks, "
        "so it can differ significantly from the real current time."
    )
    card = {
        "index": 7,
        "txid_rows": ["05a5651c7035ea27", "5b13e9a450a3da03", "a2384eb99b3e7cc8", "e89377200e3f87af"],
        "vout": 0,
        "amount": 9_000_000,
        "sequence": 144,
        "rbf_disabled": True,
        "relative": {"kind": "blocks", "label": "Relative Locktime:", "duration": "144 blocks"},
    }

    def card_text(frame, offset, doc_y):
        _card_text(frame, "Output Index: 0", doc_y, True, offset, TITLE_SIZE, (22, 26, 31))

    def wrapped(frame, offset, doc_y):
        _card_text(frame, note, doc_y, True, offset, TITLE_SIZE, (138, 96, 0))

    def centered(frame, offset, doc_y):
        _centered_flow(frame, "0.09000000", doc_y, True, offset, 48, (22, 26, 31))

    def wallet_name(frame, offset, doc_y):
        _name_center(frame, name, doc_y, True, offset, TITLE_SIZE, (22, 26, 31))

    def chevron(frame, offset, doc_y):
        _chevron(frame, doc_y, True, offset, "100 Inputs", True, "psbt-toggle-inputs")

    def button(frame, offset, doc_y):
        _card_button(frame, doc_y, "Search for Address in Loaded Wallets", "psbt-search-0-0", True, offset)

    def sign_button(frame, offset, doc_y):
        app._flow_button(
            frame, doc_y, "Sign Transaction with\nCondemned Chocolate\nImpala 0A", "psbt-sign", True, offset,
        )

    def zero_amount(frame, offset, doc_y):
        _zero_amount_line(frame, doc_y, True, offset)

    def sequence(frame, offset, doc_y):
        _sequence_line(frame, doc_y, True, offset, 0xFFFFFFFD)

    def grouped(frame, offset, doc_y):
        app._grouped_address(frame, address, doc_y - offset)

    def input_card(frame, offset, doc_y):
        _input_card(app, frame, doc_y, True, offset, card)

    def edge(paint_at, height: int, label: str):
        """The inclusive bottom row of a control sits on the tile boundary."""
        _assert_stitch(
            lambda frame, offset, y=HEIGHT - height: paint_at(frame, offset, y),
            HEIGHT * 2,
            f"{label} bottom on the tile edge",
        )

    probe = Frame()
    edge(button, probe.button_height("Search for Address in Loaded Wallets"), "search button")
    edge(sign_button, probe.button_height("Sign Transaction with\nCondemned Chocolate\nImpala 0A"), "sign button")
    card_span = _input_card(app, probe, 0, False, 0, card)
    edge(input_card, card_span - 12, "input card")

    _sweep(card_text, "card text")
    _sweep(wrapped, "wrapped note")
    _sweep(centered, "amount")
    _sweep(wallet_name, "wallet name")
    _sweep(chevron, "chevron")
    _sweep(button, "button")
    _sweep(sign_button, "sign button")
    _sweep(zero_amount, "zero amount")
    _sweep(sequence, "sequence")
    _sweep(grouped, "address")
    # A whole input card is tall. Step across the edge instead of every pixel.
    for doc_y in range(HEIGHT - 180, HEIGHT + 40, 7):
        _assert_stitch(
            lambda frame, offset, y=doc_y: input_card(frame, offset, y),
            HEIGHT * 2,
            f"input card at {doc_y}",
        )


def _signing_view(session, psbt, wallet_name: str):
    checked = check_loaded_psbt(session, 0, psbt)
    view = describe_psbt(session, 0, checked)
    view["wallet_name"] = wallet_name
    view["signature_note"] = (
        "Some inputs have no signatures. "
        "2 signatures are required to complete this 2-of-3 transaction."
    )
    view["signers"] = [
        {
            "fingerprint": "aa" * 4,
            "name": "Condemned Chocolate Impala AA",
            "signed": False,
            "note": "",
            "button": "Sign Transaction with\nCondemned Chocolate\nImpala AA",
        },
        {
            "fingerprint": "bb" * 4,
            "name": "Grateful Ivory Labrador BB",
            "signed": True,
            "note": "Already signed by key Grateful Ivory Labrador BB",
            "button": "Sign Transaction with\nGrateful Ivory\nLabrador BB",
        },
    ]
    view["warnings"] = [
        {
            "text": (
                "The absolute fee is high. "
                "Compare it with the amount you intend to send before signing."
            ),
            "tone": "red",
        }
    ]
    return view


def _assert_sheet(app, view, label: str):
    app.psbt_view = view
    app._psbt_heights = {}
    app._psbt_sheet = None
    app.psbt_outputs_open = True
    app.psbt_inputs_open = True
    app.psbt_change_open = True
    app.psbt_txid_open = True
    app.psbt_more_open = True
    probe = Frame()
    end = _body(app, probe, view, paint=False, offset=0)
    tall = max(end + 32, HEIGHT)

    def paint(frame, offset):
        _body(app, frame, view, paint=True, offset=offset)

    _assert_stitch(paint, tall, label)

    # The screen the finger sees: tiles blitted, then the title bar on top.
    app.screen = "psbt-yaml"
    app.scroll["psbt-yaml"] = HEIGHT - 300
    shown = app.render()
    offset = app.scroll["psbt-yaml"]
    expect = _continuous(paint, tall)
    body = shown.crop((0, HEADER + 1, WIDTH, HEIGHT))
    wanted = expect.crop((0, offset + HEADER + 1, WIDTH, offset + HEIGHT))
    diff = _first_diff(body, wanted)
    assert diff is None, f"{label} viewport sliced at {diff[0], diff[1] + HEADER + 1}"


def test_a_wrapping_multisig_name_does_not_slice_the_signing_screen():
    session = _native()
    psbt = _native_bulk(session, 8)
    psbt.tx.vin[0].sequence = 144
    psbt.inputs[0].sequence = 144
    names = [
        "Grateful Ivory Impala 0A (Native-Segwit)",
        "2-of-3 " + ",".join(f"{index:016x}" for index in range(3)),
        "2-of-5 " + ",".join(f"{index:016x}" for index in range(5)),
        "3-of-8 " + ",".join(f"{index:016x}" for index in range(8)),
    ]
    app = App()
    app.session = session
    app.wallet_index = 0
    for name in names:
        _assert_sheet(app, _signing_view(session, psbt, name), name.split()[0])


def test_the_hundred_input_sheet_matches_across_every_tile():
    session = _native()
    psbt = PSBT.parse(MEDIUM_VECTOR.read_bytes())
    name = "2-of-3 " + ",".join(f"{index:016x}" for index in range(4))
    app = App()
    app.session = session
    app.wallet_index = 0
    _assert_sheet(app, _signing_view(session, psbt, name), "100 inputs")


def test_cards_are_drawn_only_near_the_screen():
    session = _native()
    psbt = PSBT.parse(MEDIUM_VECTOR.read_bytes())
    app = App()
    app.session = session
    app.wallet_index = 0
    app.psbt_view = describe_psbt(session, 0, check_loaded_psbt(session, 0, psbt))
    app.psbt_outputs_open = True
    app.psbt_inputs_open = True
    app.psbt_change_open = True
    app.screen = "psbt-yaml"
    app.scroll["psbt-yaml"] = 0
    app.render()
    top_cards = [key for key in app._psbt_sheet["pictures"] if key[0] in ("input", "output", "change")]
    assert top_cards
    assert len(top_cards) < 12
    assert any(key[0] == "input" for key in app._psbt_heights)
    assert any(key[0] == "wallet" for key in app._psbt_sheet["pictures"])
    heights = dict(app._psbt_heights)

    app.scroll["psbt-yaml"] = 10**9
    app.render()
    bottom_cards = [key for key in app._psbt_sheet["pictures"] if key[0] in ("input", "output", "change")]
    bottom_inputs = [key for key in bottom_cards if key[0] == "input"]
    assert bottom_inputs
    assert len(bottom_cards) < 12
    assert set(bottom_cards).isdisjoint(top_cards)
    assert any(key[0] == "wallet" for key in app._psbt_sheet["pictures"])
    assert heights.keys() <= app._psbt_heights.keys()

    app.psbt_txid_open = True
    app.render()
    app.psbt_txid_open = False
    app.render()
    txid = [key for key in app._psbt_sheet["pictures"] if key[0] == "txid"]
    assert {key[1] for key in txid} == {True, False}

    app._psbt_signing = True
    app.render()
    assert any(key[0] == "signs" and key[1] is True for key in app._psbt_sheet["pictures"])
    assert any(key[0] == "signs" and key[1] is False for key in app._psbt_sheet["pictures"])

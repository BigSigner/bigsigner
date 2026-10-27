import pytest
from PIL import Image, ImageDraw

from bigsigner import qr
from bigsigner.ui.canvas import _break_token, font

PAYLOADS = (
    "UR:CRYPTO-PSBT/" + "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789" * 6,
    "0123" * 24,  # a standard SeedQR is digits
    bytes(range(32)),  # a compact SeedQR is raw bytes
    "wpkh([deadbeef/84h/0h/0h]xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz/<0;1>/*)",
)


def _decode(matrix) -> str | bytes:
    pyzbar = pytest.importorskip("pyzbar.pyzbar")
    count = len(matrix)
    scale = 6
    image = Image.new("L", (count * scale, count * scale), 255)
    draw = ImageDraw.Draw(image)
    for y, row in enumerate(matrix):
        for x, dark in enumerate(row):
            if dark:
                draw.rectangle((x * scale, y * scale, (x + 1) * scale - 1, (y + 1) * scale - 1), fill=0)
    codes = pyzbar.decode(image)
    assert len(codes) == 1
    return codes[0].data


def test_matrix_is_square_with_a_two_module_border():
    matrix = qr.qr_matrix("hello")
    assert all(len(row) == len(matrix) for row in matrix)
    assert not any(matrix[0]) and not any(matrix[1])
    assert not any(row[0] or row[1] or row[-1] or row[-2] for row in matrix)
    assert matrix[2][2]  # the finder pattern's corner


@pytest.mark.parametrize("payload", PAYLOADS)
def test_both_builders_encode_the_same_payload(payload):
    python = qr._matrix_from_qrcode(payload)
    native = qr._matrix_from_libqrencode(payload)
    if native is None:
        pytest.skip("libqrencode is not installed here")
    assert len(native) == len(python)
    expected = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    assert _decode(native) == expected
    assert _decode(python) == expected


def _greedy(draw, word, face, width):
    pieces, current = [], ""
    for char in word:
        trial = current + char
        if current and draw.textlength(trial, font=face) > width:
            pieces.append(current)
            current = char
        else:
            current = trial
    if current:
        pieces.append(current)
    return pieces


@pytest.mark.parametrize("width", (120, 200, 437))
def test_long_tokens_split_where_the_character_walk_split_them(width):
    draw = ImageDraw.Draw(Image.new("RGB", (10, 10)))
    for mono in (False, True):
        face = font(32, mono=mono)
        word = PAYLOADS[3]
        assert _break_token(draw, word, face, width) == _greedy(draw, word, face, width)

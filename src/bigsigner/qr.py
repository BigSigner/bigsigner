"""QR code modules, from libqrencode when the device image has it.

Building a code in pure Python (the ``qrcode`` package) takes about four
seconds on a Pi Zero. libqrencode does the same work in C in a few
milliseconds and ships on bigsigner-os. The emulator and the tests use
whichever is present; both produce a valid code for the same payload.

A matrix is a tuple of rows of booleans, True for a dark module, with the
two-module quiet zone included on every side.
"""

import ctypes
import ctypes.util

BORDER = 2
_QR_ECLEVEL_L = 0
_QR_MODE_8 = 2
_LIBRARY = None
_LIBRARY_SEARCHED = False


class _QRcode(ctypes.Structure):
    _fields_ = [("version", ctypes.c_int), ("width", ctypes.c_int), ("data", ctypes.POINTER(ctypes.c_ubyte))]


def _library():
    global _LIBRARY, _LIBRARY_SEARCHED
    if _LIBRARY_SEARCHED:
        return _LIBRARY
    _LIBRARY_SEARCHED = True
    names = [ctypes.util.find_library("qrencode"), "libqrencode.so.4", "libqrencode.so", "libqrencode.dylib"]
    for name in names:
        if not name:
            continue
        try:
            library = ctypes.CDLL(name)
        except OSError:
            continue
        library.QRcode_encodeString.restype = ctypes.POINTER(_QRcode)
        library.QRcode_encodeString.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
        library.QRcode_encodeData.restype = ctypes.POINTER(_QRcode)
        library.QRcode_encodeData.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int, ctypes.c_int]
        library.QRcode_free.argtypes = [ctypes.POINTER(_QRcode)]
        _LIBRARY = library
        break
    return _LIBRARY


def qr_matrix(data) -> tuple[tuple[bool, ...], ...]:
    """Error correction L, smallest version that fits, two-module border."""
    matrix = _matrix_from_libqrencode(data)
    if matrix is None:
        matrix = _matrix_from_qrcode(data)
    return matrix


def _matrix_from_libqrencode(data):
    library = _library()
    if library is None:
        return None
    if isinstance(data, str):
        try:
            text = data.encode("ascii")
        except UnicodeEncodeError:
            text = None
        if text is not None and b"\x00" not in text:
            # Mode 8 with case kept lets the library pick numeric or alphanumeric
            # segments where the text allows them, as the Python package does.
            code = library.QRcode_encodeString(text, 0, _QR_ECLEVEL_L, _QR_MODE_8, 1)
        else:
            code = _encode_bytes(library, data.encode("utf-8"))
    else:
        code = _encode_bytes(library, bytes(data))
    if not code:
        return None
    try:
        width = code.contents.width
        raw = ctypes.string_at(code.contents.data, width * width)
    finally:
        library.QRcode_free(code)
    pad = (False,) * BORDER
    blank = (False,) * (width + 2 * BORDER)
    rows = [blank] * BORDER
    for y in range(width):
        line = raw[y * width : (y + 1) * width]
        rows.append(pad + tuple(bool(cell & 1) for cell in line) + pad)
    rows.extend([blank] * BORDER)
    return tuple(rows)


def _encode_bytes(library, payload: bytes):
    buffer = (ctypes.c_ubyte * len(payload)).from_buffer_copy(payload)
    return library.QRcode_encodeData(len(payload), buffer, 0, _QR_ECLEVEL_L)


def _matrix_from_qrcode(data):
    import qrcode

    code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=BORDER)
    code.add_data(data)
    code.make(fit=True)
    return tuple(tuple(bool(cell) for cell in row) for row in code.get_matrix())

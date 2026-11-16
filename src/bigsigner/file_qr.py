"""QR payloads for a file: one code when it is short, gzip and base64 when it is not."""

import base64
import gzip

# One code of the original text, or of the original bytes.
TEXT_DIRECT = 400
BINARY_DIRECT = 400
# One code of base64. 300 bytes encode to 400 characters.
BASE64_DIRECT = 300
# Above this, Show QR or Base64 is disabled.
QR_SPLIT_LIMIT = 8000
PART_CHARS = 400

BASE64_DECODE = "cat file | base64 -d"


def shell_quote(name: str) -> str:
    """One single-quoted shell word. A quote inside the name is the usual '\\'' break."""
    return "'" + name.replace("'", "'\\''") + "'"


def shell_words(text: str) -> list[str]:
    """Words of one command line. A single-quoted word stays in one piece, including '\\''."""
    words = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        start = index
        if text[index] == "'":
            index += 1
            while index < len(text):
                if text.startswith("'\\''", index):
                    index += 4
                    continue
                if text[index] == "'":
                    index += 1
                    break
                index += 1
        else:
            while index < len(text) and not text[index].isspace():
                index += 1
        words.append(text[start:index])
    return words


def recovery_command(name: str) -> str:
    """The Mac or Linux command that joins the saved QR contents back into this file."""
    return (
        "set -o pipefail\n"
        "cat file-part-* | tr -d ' ' | base64 -d | gzip -t && "
        "cat file-part-* | tr -d ' ' | base64 -d | gzip -dc > " + shell_quote(name)
    )


def plain_base64(data: bytes) -> str:
    """Base64 of the original bytes, with no line breaks."""
    return base64.b64encode(data).decode("ascii")


def gzip_base64(data: bytes) -> str:
    """gzip the bytes, then base64 with no line breaks."""
    return base64.b64encode(gzip.compress(data)).decode("ascii")


def spaced_parts(encoded: str) -> list[str]:
    """Split into 400-character pieces and mark each piece with spaces.

    Every piece starts with one more space than the number of pieces. Piece 0
    has no spaces after it, and each later piece has as many as its index.
    """
    chunks = [encoded[index:index + PART_CHARS] for index in range(0, len(encoded), PART_CHARS)] or [""]
    lead = " " * (len(chunks) + 1)
    return [lead + chunk + (" " * index) for index, chunk in enumerate(chunks)]

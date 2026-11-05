"""Wallet files that wrap one output descriptor.

embit reads a single descriptor string. It does not detect a Specter-DIY JSON
export or a Bitcoin Core descriptor file. Those are unwrapped here. The
descriptor inside is what the rest of the app parses.
"""

import json

from .parse import split_checksum

_SPECTER_KEYS = frozenset({"label", "blockheight", "descriptor"})


def descriptor_from_specter(text: str) -> str | None:
    """The descriptor string from a Specter-DIY wallet export, or None.

    The export is a JSON object whose keys are exactly ``label``,
    ``blockheight``, and ``descriptor``. ``descriptor`` has to be a string.
    """
    raw = _text(text)
    if not raw.startswith("{"):
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, dict) or set(value) != _SPECTER_KEYS:
        return None
    descriptor = value["descriptor"]
    if not isinstance(descriptor, str):
        return None
    return descriptor.strip()


def descriptor_from_bitcoin_core(text: str) -> str | None:
    """The combined descriptor from a Bitcoin Core descriptor file, or None.

    Blank lines and lines that start with ``#`` are ignored. The first
    remaining line is the descriptor that contains ``<0;1>``. Each later line
    is that same descriptor with every ``<0;1>`` written as ``0`` or as ``1``.
    Each line keeps its own checksum, because that text is different.
    """
    lines = _content_lines(text)
    if len(lines) < 2:
        return None
    first = _body(lines[0])
    if "<0;1>" not in first:
        return None
    allowed = {first.replace("<0;1>", "0"), first.replace("<0;1>", "1")}
    if any(_body(line) not in allowed for line in lines[1:]):
        return None
    for line in lines:
        split_checksum(line)
    return lines[0]


def _text(text: str) -> str:
    return str(text).lstrip("\ufeff").strip()


def _content_lines(text: str) -> list[str]:
    lines = []
    for raw in _text(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def _body(line: str) -> str:
    return line.split("#", 1)[0]

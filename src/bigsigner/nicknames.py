"""Nickname uniqueness. Letters and digits stay; other runs become one space."""

import unicodedata


def normalize_nickname(value: str) -> str:
    pieces = []
    gap = False
    for char in value.strip():
        if unicodedata.category(char).startswith(("L", "N")):
            if gap and pieces:
                pieces.append(" ")
            pieces.append(char)
            gap = False
        else:
            gap = True
    return "".join(pieces).casefold()


def collides(candidate: str, existing: list[str]) -> bool:
    key = normalize_nickname(candidate)
    if not key:
        return True
    return any(normalize_nickname(name) == key for name in existing)


def unique_nickname(base: str, existing: list[str]) -> str:
    """Return base, or base plus ' b', ' c', and so on. Raise if none are free."""
    if not collides(base, existing):
        return base
    for code in range(ord("b"), ord("z") + 1):
        trial = f"{base} {chr(code)}"
        if not collides(trial, existing):
            return trial
    raise ValueError("Every nickname suffix is already used.")

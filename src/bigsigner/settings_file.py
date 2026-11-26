"""The language file at the root of the SD card.

A file is accepted only when it is a JSON object whose ``kind`` is
``bigsigner_settings`` and whose ``language`` is ``en`` or ``he``. Anything
else is left untouched. The initial screen is the only place that creates a
missing file. A later save refuses a missing file, so a card inserted after
boot does not gain one.
"""

import json
from dataclasses import dataclass

from .sdcard import SdError, file_exists, read_bytes, write_text

SETTINGS_NAME = "settings.json"
KIND = "bigsigner_settings"
LANGUAGES = frozenset({"en", "he"})
NO_CARD = "No SD card is available."


class SettingsRejected(Exception):
    """The file is missing, unreadable, or not BigSigner settings."""


@dataclass(frozen=True)
class LanguageLoad:
    """What the initial screen should keep after looking at the card."""

    language: str
    saved: str | None
    error: str | None


def _dump(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"


def card_mounted() -> bool:
    """True when an SD card is mounted. A missing file is still a mounted card."""
    try:
        file_exists(SETTINGS_NAME)
    except SdError as exc:
        if str(exc) == NO_CARD:
            return False
        raise
    return True


def read_settings() -> dict:
    """The settings object. SettingsRejected when the file is missing or not ours.

    The bytes are not changed. SdError from a missing card is left to the caller.
    """
    if not file_exists(SETTINGS_NAME):
        raise SettingsRejected("missing")
    try:
        raw = read_bytes(SETTINGS_NAME)
    except SdError as exc:
        raise SettingsRejected("unreadable") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SettingsRejected("invalid") from exc
    if (
        not isinstance(data, dict)
        or data.get("kind") != KIND
        or data.get("language") not in LANGUAGES
    ):
        raise SettingsRejected("invalid")
    return data


def create_default() -> dict:
    """Write the English default. Used only when the initial screen finds no file."""
    data = {"kind": KIND, "language": "en"}
    write_text(SETTINGS_NAME, _dump(data))
    return data


def save_language(language: str) -> None:
    """Update ``language`` on a valid file. Never creates and never touches a bad kind."""
    if language not in LANGUAGES:
        raise SettingsRejected("invalid")
    if not card_mounted():
        raise SettingsRejected("no-card")
    data = read_settings()
    if data.get("language") == language:
        return
    updated = dict(data)
    updated["language"] = language
    write_text(SETTINGS_NAME, _dump(updated))


def load_initial() -> LanguageLoad:
    """Read the card for the initial screen, creating the default when it is missing."""
    try:
        if not card_mounted():
            return LanguageLoad("en", None, None)
        if not file_exists(SETTINGS_NAME):
            create_default()
            return LanguageLoad("en", "en", None)
        data = read_settings()
    except (SettingsRejected, SdError):
        return LanguageLoad("en", None, "Could not save the language.")
    return LanguageLoad(str(data["language"]), str(data["language"]), None)

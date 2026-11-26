"""English and Hebrew UI strings, and visual order for Hebrew.

The catalog matches a whole label. A sentence that is not listed stays in
English. User content is not passed through ``t`` or ``display``.
"""

import json
import re
from contextlib import contextmanager
from pathlib import Path

from .bidi import get_display

_CATALOG = json.loads(
    (Path(__file__).resolve().parent / "resources" / "bigsigner-translations" / "he.json").read_text(
        encoding="utf-8"
    )
)
_language = "en"
_WORDS_SEED = re.compile(r"^(\d+) Words Seed(?: \+ Passphrase(\d+))?$")
_WORD_COUNT = re.compile(r"^(\d+) Words$")
_WORD_PROGRESS = re.compile(r"^Word (\d+) of (\d+)$")
_SEED_PASS = re.compile(r"^(.+\u2026) \+ Passphrase(\d+)$")
_PSBT_COUNT = re.compile(r"^(\d+) (Input|Inputs|Output|Outputs|Change Output|Change Outputs)$")
_INPUT_NUMBER = re.compile(r"^Input #(\d+)$")
_CONFIRMED_ON = re.compile(r"^Confirmed On (\d+) Other Hardware Wallets$")
_LOAD_KEYS = re.compile(
    r"^You are about to load (\d+) external keys for a MultiSig wallet\. "
    r"Your co-signers must verify on their hardware wallets one of the following:$"
)
_VERIFY_ONE = re.compile(
    r"^Verify on the other hardware wallet that it participates in a multisig of exactly "
    r"(\d+)-of-(\d+), and its first Receive Address is:$"
)
_CAMERA_SEED = re.compile(
    r"^This capture makes a (\d+)-word seed\. The same scene on another device does not repeat\.$"
)
_VERIFY_ALL = re.compile(
    r"^Verify on all (\d+) other hardware wallets that they participate in a multisig of exactly "
    r"(\d+)-of-(\d+), and their first Receive Address is:$"
)
_PSBT_NOUN = {
    "Input": "קלט",
    "Inputs": "קלטים",
    "Output": "פלט",
    "Outputs": "פלטים",
    "Change Output": "פלט עודף",
    "Change Outputs": "פלטי עודף",
}


def get_language() -> str:
    return _language


def set_language(code: str) -> None:
    global _language
    if code not in ("en", "he"):
        raise ValueError(code)
    _language = code


def reset_language() -> None:
    global _language
    _language = "en"


def hebrew() -> bool:
    return _language == "he"


def t(text: str) -> str:
    """The Hebrew label when this session is in Hebrew and the whole string is listed.

    A word count such as ``12 Words``, ``12 Words Seed``, and ``Word 3 of 24``
    follows the same wording, because the number is part of the label.
    """
    if _language != "he":
        return text
    found = _CATALOG.get(text)
    if found is not None:
        return found
    count = _WORD_COUNT.fullmatch(text)
    if count:
        return f"{count.group(1)} מילים"
    words = _WORDS_SEED.fullmatch(text)
    if words:
        line = f"מכיל {words.group(1)} מילות מפתח"
        if words.group(2):
            line += f" + ביטוי סודי נוסף {words.group(2)}"
        return line
    progress = _WORD_PROGRESS.fullmatch(text)
    if progress:
        return f"מילה {progress.group(1)} מתוך {progress.group(2)}"
    seed_pass = _SEED_PASS.fullmatch(text)
    if seed_pass:
        return f"{seed_pass.group(1)} + ביטוי סודי נוסף {seed_pass.group(2)}"
    counted = _PSBT_COUNT.fullmatch(text)
    if counted:
        return f"{counted.group(1)} {_PSBT_NOUN[counted.group(2)]}"
    numbered = _INPUT_NUMBER.fullmatch(text)
    if numbered:
        return f"קלט #{numbered.group(1)}"
    confirmed = _CONFIRMED_ON.fullmatch(text)
    if confirmed:
        return f"אושר ב-{confirmed.group(1)} ארנקי חומרה אחרים"
    loading = _LOAD_KEYS.fullmatch(text)
    if loading:
        return (
            f"עומדים להיטען {loading.group(1)} מפתחות חיצוניים לארנק רב-חתימות. "
            "על השותפים לאמת באחד מארנקי החומרה שלהם אחד מהבאים:"
        )
    verify_one = _VERIFY_ONE.fullmatch(text)
    if verify_one:
        return (
            "יש לאמת בארנק החומרה האחר שהוא משתתף בארנק רב-חתימות "
            f"של בדיוק {verify_one.group(1)}-מתוך-{verify_one.group(2)}, וכתובת הקבלה הראשונה שלו היא:"
        )
    camera_seed = _CAMERA_SEED.fullmatch(text)
    if camera_seed:
        return (
            f"צילום זה יוצר {camera_seed.group(1)} מילות מפתח. "
            "אותה סצנה במכשיר אחר אינה חוזרת."
        )
    verify_all = _VERIFY_ALL.fullmatch(text)
    if verify_all:
        return (
            f"יש לאמת בכל {verify_all.group(1)} ארנקי החומרה האחרים שהם משתתפים בארנק רב-חתימות "
            f"של בדיוק {verify_all.group(2)}-מתוך-{verify_all.group(3)}, וכתובת הקבלה הראשונה שלהם היא:"
        )
    return text


def has_hebrew(text: str) -> bool:
    return any("\u0590" <= char <= "\u05ff" for char in text)


def hebrew_layout(text: str) -> bool:
    """Whether this string uses the Hebrew layout.

    Right alignment, right-to-left order, an icon on the right of its words,
    and a dropdown chevron on the left apply only when the string contains
    Hebrew. An English label with no catalog entry keeps the English layout,
    so a new sentence is not mirrored before it is translated.
    """
    return has_hebrew(text)


def display(text: str, *, base: str | None = None) -> str:
    """Visual order. A logical Hebrew word is reversed so Pillow draws it correctly.

    A string that contains Hebrew uses an RTL base, including when that string
    also has an English word or a number. An English string is left as it is,
    even while the session language is Hebrew.
    """
    if not text:
        return text
    if base is None:
        if not has_hebrew(text):
            return text
        base = "R"
    if base == "L":
        return text
    shown = get_display(text, base_dir=base)
    return shown if isinstance(shown, str) else shown.decode("utf-8")


def language_name(code: str) -> str:
    """The name drawn in the language menu. Each name stays in its own language."""
    return "עברית" if code == "he" else "English"


@contextmanager
def english_layout():
    """Draw one screen in English without forgetting the language held in memory."""
    previous = _language
    set_language("en")
    try:
        yield
    finally:
        set_language(previous)

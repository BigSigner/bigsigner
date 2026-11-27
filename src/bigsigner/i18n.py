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
_DICE = re.compile(r"^Dice (\d+)/(\d+)$")
_COINS = re.compile(r"^Coins (\d+)/(\d+)$")
_MUST_SIGN = re.compile(r"^(\d+) of (\d+) must sign$")
_DELETE_NAMED = re.compile(r'^Delete "(.*)"\?$')
_REPLACE_NAMED = re.compile(r'^Replace "(.*)"\?$')
_SAVED = re.compile(r"^Saved (.+)\.$")
_MULTISIG_LIMIT = re.compile(r"^A multisig wallet can have at most (\d+) keys\.$")
_SELECT_KEYS = re.compile(r"^Select at least (\d+) keys\.$")
_INDEX_RANGE = re.compile(r"^The index must be between 0 and (\d+)\.$")
_NETWORK_SWITCH = re.compile(
    r"^You are switching to ([^,]+), a network intended for developers\. "
    r"You will not receive or send real Bitcoin\.$"
)
_ADDRESS_FOUND_KIND = re.compile(r"^This address was found as a (Receive|Change) address at index (\d+)\.$")
_ADDRESS_MISSING = re.compile(r"^This address was not found in the index range of (\d+)-(\d+)\.$")
_SEARCH_NEXT = re.compile(r"^Search the next range, (\d+)-(\d+)\?$")
_SEARCH_RANGE = re.compile(r"^Search (\d+)-(\d+)$")
_FOUND_WALLET = re.compile(r"^Address was found in wallet (.+)$")
_FOUND_KIND = re.compile(r"^Address found in (Receive|Change) addresses: #(\d+)$")
_FOUND_ACCOUNT = re.compile(r"^Address found in account #(\d+)$")
_FOUND_SEQUENCE = re.compile(r"^Address found in account-sequence (.+)$")
_WALLET_ALSO = re.compile(r'^Wallet "([^"]+)" was already loaded\. You can now also use (.+)\.$')
_WALLET_POINTS = re.compile(r'^Wallet "([^"]+)" was already loaded\. This descriptor points to (.+)\.$')
_DELETE_EXTRA = re.compile(
    r"^Delete this key\?"
    r'(?: Wallet "(?P<removed>[^"]+)" depends on it and will be removed\.'
    r"| (?P<removed_n>\d+) wallets depend on it and will be removed\.)?"
    r'(?: Wallet "(?P<account_name>[^"]+)" depends on it and will not be able to use account-index (?P<account>\d+)\.'
    r"| (?P<account_n>\d+) wallets depend on it and will not be able to use some account-indexes\.)?$"
)
_OUTPUT_INDEX = re.compile(r"^Output Index: (\d+)$")
_ACCOUNT_LINE = re.compile(r"^Account: (.+) \((default|non-default)\)$")
_PLACE_LINE = re.compile(r"^(Receive|Change) Address #(\d+)$")
_LOCK_HEIGHT = re.compile(r"^Absolute Locktime: After block height (\d+)$")
_LOCK_TIME = re.compile(r"^Absolute Locktime: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)$")
_MINE_HEIGHT = re.compile(r"^This transaction can be mined only after block height (\d+)\.$")
_RELATIVE_INPUT = re.compile(
    r"^Input (\d+) uses a relative locktime\.( This is an additional requirement on top of the absolute locktime\.)?$"
)
_RELATIVE_INPUTS = re.compile(
    r"^Inputs ([\d, ]+) use a relative locktime\.( This is an additional requirement on top of the absolute locktime\.)?$"
)
_OTHER_WALLET = re.compile(
    r"^This transaction does not belong to wallet (.+)\. It belongs to wallet (.+)\.$"
)
_SIGN_WITH = re.compile(r"^Sign Transaction with\n(.+)$", re.S)
_ALREADY_SIGNED = re.compile(r"^Already signed by key (.+)$", re.S)
_EXPORT_SUB = re.compile(r"^Export Private (.+) Subkey$")
_EXISTS = re.compile(r"^(.+) already exists and will be replaced\.$")
_EXIST = re.compile(r"^(.+) already exist and will be replaced\.$")
_PSBT_QR = re.compile(r"^This PSBT does not fit in one (.+) QR\. Choose another format\.$")
_SEARCH_FAILED = re.compile(r"^Address search failed: (.+)$")
_SIG_NONE = re.compile(
    r"^Some inputs have no signatures\. (\d+) signatures? (?:is|are) required to complete this (\d+)-of-(\d+) transaction\.$"
)
_SIG_SOME = re.compile(
    r"^Each input already has (\d+) signatures?\. (\d+) additional signatures? (?:is|are) required to complete this (\d+)-of-(\d+) wallet\.$"
)
_DURATION = re.compile(
    r"^(?:\d+ (?:blocks?|hours?|minutes?|seconds?))"
    r"(?:, \d+ (?:hours?|minutes?|seconds?))*$"
)
_KEY_NOTE = re.compile(r"fingerprint \(([0-9a-fA-F]+)\) is not displayed")
_ROLE_SPLIT = re.compile(r", and | and |, ")
_ROLES = {"Signing": "חתימה", "Encryption": "הצפנה", "Authentication": "הזדהות"}
_UNITS = {
    "block": "בלוק",
    "blocks": "בלוקים",
    "hour": "שעה",
    "hours": "שעות",
    "minute": "דקה",
    "minutes": "דקות",
    "second": "שנייה",
    "seconds": "שניות",
}
_KIND = {"Receive": "קבלה", "Change": "עודף"}
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


def _ltr(value: str) -> str:
    return f"\u202a{value}\u202c"


def _kind(name: str) -> str:
    return _KIND.get(name, name)


def _accounts(phrase: str) -> str:
    phrase = phrase.replace("account-indexes", "אינדקסי חשבון")
    phrase = phrase.replace("account-index", "אינדקס חשבון")
    phrase = phrase.replace("non-default", "לא ברירת המחדל")
    phrase = phrase.replace("default", "ברירת מחדל")
    return phrase


def _roles(text: str) -> str:
    names = [_ROLES.get(part, part) for part in _ROLE_SPLIT.split(text)]
    if len(names) == 1:
        return names[0]
    if len(names) == 2:
        return f"{names[0]} ו{names[1]}"
    return ", ".join(names[:-1]) + f" ו{names[-1]}"


def _duration(text: str) -> str:
    parts = []
    for piece in text.split(", "):
        count, unit = piece.split(" ", 1)
        parts.append(f"{count} {_UNITS[unit]}")
    return ", ".join(parts)


def _signatures(count: str) -> str:
    return "חתימה אחת" if count == "1" else f"{count} חתימות"


def _relative_extra(extra: str | None) -> str:
    if extra:
        return " זו דרישה נוספת מעל נעילת הזמן המוחלטת."
    return ""


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
    dice = _DICE.fullmatch(text)
    if dice:
        return f"קובייה {dice.group(1)}/{dice.group(2)}"
    coins = _COINS.fullmatch(text)
    if coins:
        return f"מטבעות {coins.group(1)}/{coins.group(2)}"
    must_sign = _MUST_SIGN.fullmatch(text)
    if must_sign:
        return f"{must_sign.group(1)} מתוך {must_sign.group(2)} לחתימה"
    named = _DELETE_NAMED.fullmatch(text)
    if named:
        return f'למחוק את "{_ltr(named.group(1))}"?'
    named = _REPLACE_NAMED.fullmatch(text)
    if named:
        return f'להחליף את "{_ltr(named.group(1))}"?'
    saved = _SAVED.fullmatch(text)
    if saved:
        return f"נשמר {_ltr(saved.group(1))}."
    limited = _MULTISIG_LIMIT.fullmatch(text)
    if limited:
        return f"בארנק רב-חתימות יכולים להיות לכל היותר {limited.group(1)} מפתחות."
    selected = _SELECT_KEYS.fullmatch(text)
    if selected:
        return f"יש לבחור לפחות {selected.group(1)} מפתחות."
    index_range = _INDEX_RANGE.fullmatch(text)
    if index_range:
        return f"האינדקס חייב להיות בין 0 ל-{index_range.group(1)}."
    switching = _NETWORK_SWITCH.fullmatch(text)
    if switching:
        return (
            f"מתבצע מעבר ל-{switching.group(1)}, רשת למפתחים. "
            "אי אפשר לקבל או לשלוח בה ביטקוין אמיתי."
        )
    found_kind = _ADDRESS_FOUND_KIND.fullmatch(text)
    if found_kind:
        return f"הכתובת נמצאה ככתובת {_kind(found_kind.group(1))} באינדקס {found_kind.group(2)}."
    missing = _ADDRESS_MISSING.fullmatch(text)
    if missing:
        return f"הכתובת לא נמצאה בטווח האינדקסים {missing.group(1)}–{missing.group(2)}."
    search_next = _SEARCH_NEXT.fullmatch(text)
    if search_next:
        return f"לחפש בטווח הבא, {search_next.group(1)}–{search_next.group(2)}?"
    search_range = _SEARCH_RANGE.fullmatch(text)
    if search_range:
        return f"חיפוש {search_range.group(1)}–{search_range.group(2)}"
    found_wallet = _FOUND_WALLET.fullmatch(text)
    if found_wallet:
        return f"הכתובת נמצאה בארנק {_ltr(found_wallet.group(1))}"
    found_branch = _FOUND_KIND.fullmatch(text)
    if found_branch:
        return f"הכתובת נמצאה בכתובות {_kind(found_branch.group(1))}: #{found_branch.group(2)}"
    found_account = _FOUND_ACCOUNT.fullmatch(text)
    if found_account:
        return f"הכתובת נמצאה בחשבון #{found_account.group(1)}"
    found_sequence = _FOUND_SEQUENCE.fullmatch(text)
    if found_sequence:
        return f"הכתובת נמצאה ברצף חשבונות {_ltr(found_sequence.group(1))}"
    wallet_also = _WALLET_ALSO.fullmatch(text)
    if wallet_also:
        return (
            f"הארנק {_ltr(wallet_also.group(1))} כבר היה טעון. "
            f"עכשיו אפשר להשתמש גם ב{_accounts(wallet_also.group(2))}."
        )
    wallet_points = _WALLET_POINTS.fullmatch(text)
    if wallet_points:
        return (
            f"הארנק {_ltr(wallet_points.group(1))} כבר היה טעון. "
            f"המתאר מצביע על {_accounts(wallet_points.group(2))}."
        )
    deleted = _DELETE_EXTRA.fullmatch(text)
    if deleted and deleted.group(0) != "Delete this key?":
        parts = ["למחוק את המפתח?"]
        if deleted.group("removed"):
            parts.append(f'הארנק "{_ltr(deleted.group("removed"))}" תלוי בו ויימחק.')
        elif deleted.group("removed_n"):
            parts.append(f"{deleted.group('removed_n')} ארנקים תלויים בו ויימחקו.")
        if deleted.group("account_name"):
            parts.append(
                f'הארנק "{_ltr(deleted.group("account_name"))}" תלוי בו ולא יוכל להשתמש באינדקס חשבון {deleted.group("account")}.'
            )
        elif deleted.group("account_n"):
            parts.append(f"{deleted.group('account_n')} ארנקים תלויים בו ולא יוכלו להשתמש בחלק מאינדקסי החשבון.")
        return " ".join(parts)
    output_index = _OUTPUT_INDEX.fullmatch(text)
    if output_index:
        return f"אינדקס פלט: {output_index.group(1)}"
    account_line = _ACCOUNT_LINE.fullmatch(text)
    if account_line:
        note = "ברירת מחדל" if account_line.group(2) == "default" else "לא ברירת המחדל"
        return f"חשבון: {_ltr(account_line.group(1))} ({note})"
    place = _PLACE_LINE.fullmatch(text)
    if place:
        return f"כתובת {_kind(place.group(1))} #{place.group(2)}"
    lock_height = _LOCK_HEIGHT.fullmatch(text)
    if lock_height:
        return f"נעילת זמן מוחלטת: אחרי גובה בלוק {lock_height.group(1)}"
    lock_time = _LOCK_TIME.fullmatch(text)
    if lock_time:
        return f"נעילת זמן מוחלטת: {_ltr(lock_time.group(1))}"
    mine_height = _MINE_HEIGHT.fullmatch(text)
    if mine_height:
        return f"אפשר לכרות את פקודת ההעברה רק אחרי גובה בלוק {mine_height.group(1)}."
    relative_input = _RELATIVE_INPUT.fullmatch(text)
    if relative_input:
        return f"קלט {relative_input.group(1)} משתמש בנעילת זמן יחסית.{_relative_extra(relative_input.group(2))}"
    relative_inputs = _RELATIVE_INPUTS.fullmatch(text)
    if relative_inputs:
        return (
            f"קלטים {_ltr(relative_inputs.group(1))} משתמשים בנעילת זמן יחסית."
            f"{_relative_extra(relative_inputs.group(2))}"
        )
    other_wallet = _OTHER_WALLET.fullmatch(text)
    if other_wallet:
        return (
            f"פקודת העברה זו לא שייכת לארנק {_ltr(other_wallet.group(1))}. "
            f"היא שייכת לארנק {_ltr(other_wallet.group(2))}."
        )
    sign_with = _SIGN_WITH.fullmatch(text)
    if sign_with:
        return f"חתימה על פקודת העברה עם\n{sign_with.group(1)}"
    already = _ALREADY_SIGNED.fullmatch(text)
    if already:
        return f"כבר נחתם במפתח {_ltr(already.group(1))}"
    export_sub = _EXPORT_SUB.fullmatch(text)
    if export_sub and export_sub.group(1) != "Subkey":
        return f"ייצוא מפתח משנה פרטי ל{_roles(export_sub.group(1))}"
    exists = _EXISTS.fullmatch(text)
    if exists:
        return f"{_ltr(exists.group(1))} כבר קיים ויוחלף."
    exist = _EXIST.fullmatch(text)
    if exist:
        return f"{_ltr(exist.group(1))} כבר קיימים ויוחלפו."
    psbt_qr = _PSBT_QR.fullmatch(text)
    if psbt_qr:
        return f"ה-PSBT לא נכנס בקוד QR אחד מסוג {_ltr(psbt_qr.group(1))}. יש לבחור פורמט אחר."
    failed = _SEARCH_FAILED.fullmatch(text)
    if failed:
        return f"חיפוש הכתובת נכשל: {t(failed.group(1))}"
    sig_none = _SIG_NONE.fullmatch(text)
    if sig_none:
        needed = _signatures(sig_none.group(1))
        verb = "נדרשת" if sig_none.group(1) == "1" else "נדרשות"
        return (
            f"לחלק מהקלטים אין חתימות. {verb} {needed} "
            f"כדי להשלים פקודת העברה זו, {sig_none.group(2)} מתוך {sig_none.group(3)}."
        )
    sig_some = _SIG_SOME.fullmatch(text)
    if sig_some:
        held = _signatures(sig_some.group(1))
        extra = _signatures(sig_some.group(2))
        verb = "נדרשת" if sig_some.group(2) == "1" else "נדרשות"
        return (
            f"לכל קלט כבר יש {held}. {verb} עוד {extra} "
            f"כדי להשלים ארנק זה, {sig_some.group(3)} מתוך {sig_some.group(4)}."
        )
    if _DURATION.fullmatch(text):
        return _duration(text)
    if text.startswith("Different wallets may display the key expression"):
        fingerprint = _KEY_NOTE.search(text)
        shown = _ltr(fingerprint.group(1)) if fingerprint else ""
        return (
            "ארנקים שונים עשויים להציג את ביטוי המפתח בצורות שונות. "
            "חלקם מציגים את נתיב הגזירה (החלק בסוגריים []) בנפרד. "
            "חלקם מתחילים את הנתיב ב-m/ במקום קידומת טביעת האצבע בת 8 התווים. "
            "חלקם משתמשים בגרש (') אחרי המספרים במקום האות h. "
            f"זה תקין אם טביעת האצבע ({shown}) לא מוצגת, כל עוד הארנק לא מציג טביעת אצבע אחרת "
            "וכן מציג את אותו ערך xpub/zpub/Zpub."
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

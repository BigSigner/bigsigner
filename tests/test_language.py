"""Language file, Hebrew reordering, and alignment."""

import json

from bigsigner import sdcard
from bigsigner.bidi import get_display
from bigsigner.i18n import display, set_language, t
from bigsigner.settings_file import KIND, load_initial, save_language
from bigsigner.ui.app import App
from bigsigner.ui.canvas import BODY_SIZE, HEADER, HEIGHT, MARGIN, WIDTH, Frame, Icons


def _near_ink(image, x: int, y: int, radius: int = 12) -> bool:
    white = (255, 255, 255)
    for dy in range(-radius, radius + 1):
        for dx in range(-radius, radius + 1):
            if image.getpixel((x + dx, y + dy))[:3] != white:
                return True
    return False


def _one(items, text):
    found = [item for item in items if item.get("text") == text or item.get("label") == text]
    assert len(found) == 1, (text, found or items)
    return found[0]


def _box(item):
    return [int(edge) for edge in item["box"]]


def _read_settings():
    return json.loads(sdcard.read_bytes("settings.json").decode("utf-8"))


def _inside(items):
    for item in items:
        left, _top, right, _bottom = _box(item)
        assert 0 <= left <= right <= WIDTH, item


def test_a_missing_file_is_created_in_english_on_the_initial_screen():
    sdcard.mount_memory({"files": {}})
    app = App()
    app.screen = "warning"
    app.render()
    saved = _read_settings()
    assert saved["kind"] == KIND
    assert saved["language"] == "en"
    assert app.language == "en"
    assert app.saved_language == "en"
    assert app.notice == ""
    assert _one(app.texts, "Choose Language:")
    assert not any(item["text"] == "Remove SD Card" for item in app.texts)


def test_a_valid_file_selects_its_language_and_the_initial_screen_stays_english():
    sdcard.mount_memory({"files": {"settings.json": json.dumps({"kind": KIND, "language": "he"})}})
    app = App()
    app.screen = "warning"
    app.render()
    assert app.language == "he"
    assert _one(app.texts, "Choose Language:")
    assert not any(item["text"] == "בחירת שפה:" for item in app.texts)
    app._act("warning-ok")
    app.menu = False
    app.render()
    assert app.screen == "keys"
    assert _one(app.texts, "מפתחות ביטקוין")


def test_an_invalid_file_is_left_untouched():
    original = '{"kind": "notes", "language": "he"}\n'
    sdcard.mount_memory({"files": {"settings.json": original}})
    app = App()
    app.screen = "warning"
    app.render()
    assert sdcard.read_bytes("settings.json").decode("utf-8") == original
    assert app.language == "en"
    assert app.saved_language is None
    assert app.notice == "Could not save the language."
    assert "Could not save the language." in " ".join(item["text"] for item in app.texts)


def test_a_later_save_refuses_a_bad_kind_and_a_missing_file():
    sdcard.mount_memory({"files": {}})
    assert load_initial().saved == "en"
    sdcard.write_text("settings.json", json.dumps({"kind": "notes", "language": "en", "keep": 1}) + "\n")
    before = sdcard.read_bytes("settings.json")
    try:
        save_language("he")
    except Exception:
        pass
    else:
        raise AssertionError("a different kind was written")
    assert sdcard.read_bytes("settings.json") == before

    sdcard.delete_file("settings.json")
    try:
        save_language("he")
    except Exception:
        pass
    else:
        raise AssertionError("a missing file was created")
    assert not sdcard.file_exists("settings.json")


def test_settings_save_keeps_other_keys_and_refuses_a_missing_file():
    sdcard.mount_memory({"files": {}})
    app = App()
    app.screen = "warning"
    app.render()
    sdcard.write_text(
        "settings.json",
        json.dumps({"kind": KIND, "language": "en", "keep": "yes"}, indent=2) + "\n",
    )
    app.screen = "settings"
    app._act("dropdown-language")
    app._act("dropdown-pick-language-he")
    assert app.language == "he"
    assert _read_settings()["language"] == "en"
    app.render()
    assert _one(app.texts, "שפה:")
    app._act("save-language")
    saved = _read_settings()
    assert saved["kind"] == KIND
    assert saved["language"] == "he"
    assert saved["keep"] == "yes"
    assert app.notice == "Language saved."
    app.render()
    assert _one(app.texts, "השפה נשמרה.")

    sdcard.delete_file("settings.json")
    app.saved_language = "en"
    app.language = "he"
    set_language("he")
    app._act("save-language")
    assert not sdcard.file_exists("settings.json")
    assert app.notice == "Could not save the language."
    app.render()
    assert _one(app.texts, "שמירת השפה נכשלה.")


def test_no_card_stays_quiet_until_a_choice_fails_in_english():
    app = App()
    app.screen = "warning"
    app.render()
    assert app.language == "en"
    assert app.notice == ""
    app._act("dropdown-language")
    app._act("dropdown-pick-language-he")
    assert app.language == "he"
    assert app.notice == "Could not save the language."
    app.render()
    assert "Could not save the language." in " ".join(item["text"] for item in app.texts)
    assert _one(app.texts, "Choose Language:")


def test_a_mixed_hebrew_line_is_reordered_with_an_rtl_base_and_centered():
    set_language("he")
    logical = "שלום Transaction 12"
    shown = display(logical)
    assert shown == "Transaction 12 םולש"
    # A line that starts with a number would stay left-to-right under first-strong.
    numbered = "12 Transaction שלום"
    assert display(numbered) == "םולש Transaction 12"
    assert get_display(numbered) != display(numbered)

    frame = Frame()
    frame.clip_top = 0
    frame.text(logical, MARGIN, 40, size=32, width=WIDTH - 2 * MARGIN, align="center")
    mark = _one(frame.marks, logical)
    left, _top, right, _bottom = _box(mark)
    column_left = MARGIN
    column_right = WIDTH - MARGIN
    assert abs((left - column_left) - (column_right - right)) <= 3


def test_hebrew_alignment_keeps_the_chrome_and_moves_the_label():
    english = App()
    english.screen = "keys"
    english.render()
    english_plus = _box(_one(english.hits, "plus"))

    set_language("he")
    app = App()
    set_language("he")
    app.screen = "keys"
    app.render()
    label = next(item for item in app.texts if item["text"].startswith("לא נמצאו מפתחות"))
    assert _box(label)[2] >= WIDTH - MARGIN - 8
    title = _one(app.texts, "מפתחות ביטקוין")
    assert abs(_box(title)[0] - 84) <= 8
    menu_hit = next(hit for hit in app.hits if hit["action"] == "menu")
    assert _box(menu_hit)[0] == 0
    assert _box(menu_hit)[2] == 84
    assert _box(_one(app.hits, "plus")) == english_plus
    assert english_plus == [WIDTH - 24 - 94, HEIGHT - 28 - 94, WIDTH - 24, HEIGHT - 28]

    app.menu = True
    app.render()
    menu_label = _one(app.texts, "הגדרות")
    menu_row = next(hit for hit in app.hits if hit["action"] == "nav-settings")
    assert _box(menu_row)[0] == 0
    assert _box(menu_row)[2] == 320
    assert 280 <= _box(menu_label)[2] <= 300
    assert _box(menu_label)[0] > 40
    gpg_label = _one(app.texts, "GPG")
    assert 280 <= _box(gpg_label)[2] <= 300
    assert _box(gpg_label)[0] > 40

    app.menu = False
    app.add_menu = True
    app.render()
    scan = _one(app.texts, "סריקת קוד QR")
    icon_left = (WIDTH - 24) - 18 - BODY_SIZE
    assert _box(scan)[2] < icon_left
    assert abs(_box(scan)[2] - (icon_left - 12)) <= 6


def test_hebrew_screens_and_glossary_buttons_stay_inside_the_panel():
    set_language("he")
    app = App()
    set_language("he")
    app.language = "he"
    app.screen = "settings"
    app.render()
    _inside(app.texts)
    assert _one(app.hits, "שמירה לכרטיס זכרון נשלף")
    save = _one(app.texts, "שמירה לכרטיס זכרון נשלף")
    assert _box(save)[2] <= WIDTH - MARGIN

    app.menu = True
    app.render()
    _inside(app.texts)
    for label in ("מפתחות ביטקוין", "ארנקי ביטקוין", "קבצים", "אודות"):
        assert _box(_one(app.texts, label))[2] <= 320
    settings_labels = [item for item in app.texts if item["text"] == "הגדרות"]
    assert settings_labels
    assert any(_box(item)[2] <= 320 and _box(item)[0] > 40 for item in settings_labels)

    app.menu = False
    app.screen = "keys"
    app.add_menu = True
    app.render()
    _inside(app.texts)
    for label in ("הזנת מילות מפתח", "סריקת קוד QR", "טעינה מקובץ", "מילות מפתח חדשות"):
        item = _one(app.texts, label)
        assert _box(item)[2] <= WIDTH - 24

    frame = Frame()
    frame.button(HEADER + 24, "Sign Transaction", "sign")
    frame.button(HEADER + 160, "Scan QR Code", "scan", icon=Icons.CAMERA, awesome=True)
    _inside(frame.marks)
    signed = [item for item in frame.marks if item["text"]]
    assert signed
    for item in signed:
        assert MARGIN <= _box(item)[0] and _box(item)[2] <= WIDTH - MARGIN
    assert t("Sign Transaction") == "חתימה על פקודת העברה"


WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".split()


def test_the_shoulder_warning_is_translated_and_right_aligned():
    set_language("he")
    app = App()
    set_language("he")
    app.language = "he"
    app.screen = "key"
    app.confirm = "show-seed"
    app.render()
    warning = next(item for item in app.texts if item["text"].startswith("נא לוודא"))
    dialog = next(hit["box"] for hit in app.hits if hit["label"] == "dialog")
    assert _box(warning)[2] >= dialog[2] - 28
    assert _box(warning)[0] > dialog[0] + 40


def test_untranslated_english_stays_left_and_the_chevron_follows_the_value():
    set_language("he")
    app = App()
    set_language("he")
    app.language = "he"
    app.screen = "settings"
    image = app.render()
    sentence = next(item for item in app.texts if item["text"].startswith("Switching network"))
    assert abs(_box(sentence)[0] - MARGIN) <= 4
    network = next(item for item in app.texts if item["text"] == "Network:")
    assert abs(_box(network)[0] - MARGIN) <= 4
    hebrew_value = _one(app.texts, "עברית")
    language_field = next(hit["box"] for hit in app.hits if hit["action"] == "dropdown-language")
    network_field = next(hit["box"] for hit in app.hits if hit["action"] == "dropdown-network")
    assert _box(hebrew_value)[2] > language_field[2] - 28
    assert _box(hebrew_value)[0] > language_field[0] + 52
    language_mid = (language_field[1] + language_field[3]) // 2
    network_mid = (network_field[1] + network_field[3]) // 2
    assert _near_ink(image, language_field[0] + 36, language_mid)
    assert not _near_ink(image, language_field[2] - 8, language_mid, radius=4)
    assert _near_ink(image, network_field[0] + 40, network_mid)
    assert _near_ink(image, network_field[2] - 36, network_mid)
    assert not _near_ink(image, network_field[0] + 8, network_mid, radius=4)


def test_storage_usage_uses_the_hebrew_labels():
    set_language("he")
    sdcard.mount_memory({"files": {}})
    app = App()
    set_language("he")
    app._act("nav-filesystem")
    app._act("storage-temporary")
    app.render()
    usage = next(item for item in app.texts if item["text"].startswith("בשימוש:"))
    assert "פנוי:" in usage["text"]
    assert "\u202a" in usage["text"]
    shown = display(usage["text"])
    assert shown.endswith(display("בשימוש:"))
    assert shown.startswith("64.0 MiB")
    assert _box(usage)[2] >= WIDTH - MARGIN - 4
    assert _box(usage)[0] >= MARGIN - 4
    path = _one(app.texts, "/")
    assert abs(_box(path)[0] - MARGIN) <= 4


def test_empty_wallet_and_key_lists_are_translated():
    set_language("he")
    app = App()
    set_language("he")
    app.screen = "wallets"
    app.render()
    wallets = next(item for item in app.texts if item["text"].startswith("אין עדיין ארנקים"))
    assert _box(wallets)[2] >= WIDTH - MARGIN - 8
    app.screen = "keys"
    app.render()
    assert any(item["text"].startswith("לא נמצאו מפתחות") for item in app.texts)


def test_the_seed_key_screen_uses_the_seed_key_wording():
    set_language("he")
    assert t("Show") == "הצגה"
    assert t("Delete Seed") == "מחיקת מפתח מילים"
    assert t("Seeds") == "מפתחות מילים"
    assert t("Bitcoin Seed Raw Entropy (BIP-85)") == "אנטרופיה ממילות מפתח (BIP-85)"
    assert t("GPG keys stay in RAM and are cleared when the power is off.") == "מפתחות GPG נשארים ב-RAM ונמחקים עם כיבוי החשמל."
    assert t("This capture makes a 24-word seed. The same scene on another device does not repeat.") == (
        "צילום זה יוצר 24 מילות מפתח. אותה סצנה במכשיר אחר אינה חוזרת."
    )
    assert t("This capture makes a 12-word seed. The same scene on another device does not repeat.") == (
        "צילום זה יוצר 12 מילות מפתח. אותה סצנה במכשיר אחר אינה חוזרת."
    )
    assert t("12 Words") == "12 מילים"
    assert t("18 Words") == "18 מילים"
    assert t("24 Words") == "24 מילים"
    assert t("12 Words Seed") == "מכיל 12 מילות מפתח"
    assert t("24 Words Seed + Passphrase2") == "מכיל 24 מילות מפתח + ביטוי סודי נוסף 2"
    assert t("Word 3 of 24") == "מילה 3 מתוך 24"

    set_language("he")
    app = App()
    set_language("he")
    added = app.session.add_mnemonic(WORDS)
    app.screen = "key"
    app.selected_fp = added["fingerprint"]
    app.render()
    _inside(app.texts)
    assert _one(app.texts, "מפתח מילים")
    label = _one(app.texts, "מילה ראשונה:")
    word = _one(app.texts, "abandon")
    assert _box(word)[2] <= _box(label)[0]
    assert _box(label)[2] >= WIDTH - MARGIN - 48
    assert _one(app.texts, "מכיל 12 מילות מפתח")
    assert any(item["text"] == "ללא ביטוי סודי נוסף" for item in app.texts)
    assert _one(app.hits, "הצגה")
    assert _one(app.hits, "ייצוא")
    assert _one(app.hits, "גזירת מפתח ציבורי מורחב")
    assert _one(app.hits, "יצירת עותק של מפתח המילים עם ביטוי סודי נוסף")
    signed = [item["text"] for item in app.texts]
    assert any("גזירת תת-מפתח מילים לפי BIP85" in item or item.startswith("גזירת תת-מפתח") for item in signed)
    assert _one(app.hits, "מחיקת מפתח מילים")

    app.screen = "keys"
    app.render()
    assert _one(app.texts, "מפתחות מילים")

    app.screen = "seed-backup"
    app.render()
    heading = _one(app.texts, "אזהרה")
    assert abs((_box(heading)[0] + _box(heading)[2]) / 2 - WIDTH / 2) <= 8
    body = next(item for item in app.texts if item["text"].startswith("גיבוי מילות מפתח צריך"))
    assert _box(body)[2] >= WIDTH - MARGIN - 4

    app.screen = "derive-type"
    app.render()
    _inside(app.texts)
    assert _one(app.hits, "מפתח סגוויט-טבעי חד-חתימה")
    assert _one(app.hits, "מפתח סגוויט-טבעי רב-חתימות")
    assert _one(app.hits, "מפתח טאפרוט חד-חתימה")

    app.screen = "key"
    app._act("show-seed")
    app._act("confirm-yes")
    app.render()
    count = _one(app.texts, "12 מילים")
    assert abs((_box(count)[0] + _box(count)[2]) / 2 - WIDTH / 2) <= 8


def test_remaining_screens_and_popups_are_hebrew():
    set_language("he")
    assert t("Scan Address") == "סריקת כתובת"
    assert t("No BIP39 word matches this.") == "אין מילה תואמת ברשימת BIP39."
    assert t("Dice 12/50") == "קובייה 12/50"
    assert t("Coins 40/128") == "מטבעות 40/128"
    assert t("2 of 3 must sign") == "2 מתוך 3 לחתימה"
    assert t("Encryption") == "הצפנה"
    assert t('Delete "notes.txt"?') == 'למחוק את "\u202anotes.txt\u202c"?'
    assert t("The wallet was added successfully.") == "הארנק נוסף בהצלחה."
    assert t("Address found in Receive addresses: #120") == "הכתובת נמצאה בכתובות קבלה: #120"
    assert t("Search 0-99") == "חיפוש 0–99"
    assert t("Sequence:") == "רצף:"
    assert t("A transaction with more than 100 inputs is not supported by this hardware wallet.").startswith("פקודת העברה")
    assert "אינו נתמך" in t("A transaction with no inputs is not supported by this hardware wallet.")
    note = t(
        "Different wallets may display the key expression in different formats. "
        "fingerprint (aabbccdd) is not displayed, as long as the wallet does not show a different fingerprint."
    )
    assert "aabbccdd" in note
    assert note.startswith("ארנקים שונים")


def test_seed_entry_placeholder_checksum_and_ok_are_hebrew():
    set_language("he")
    assert t("Type a seed word") == "נא להזין מילות מפתח"
    assert t("The next word has to match the checksum") == "המילה הבאה חייבת להיות מילת ביקורת"
    assert t("OK") == "אישור"
    app = App()
    set_language("he")
    app.screen = "seed"
    app.render()
    placeholder = _one(app.texts, "נא להזין מילות מפתח")
    assert _box(placeholder)[0] >= MARGIN
    assert _box(placeholder)[2] >= WIDTH - MARGIN - 24
    app.seed_length = 12
    app.seed_words = WORDS[:11]
    app.render()
    note = next(item for item in app.texts if item["text"].startswith("המילה הבאה"))
    assert _box(note)[2] >= WIDTH - MARGIN - 4
    app.screen = "load-error"
    app.render()
    assert _one(app.hits, "אישור")["action"] == "load-error-ok"

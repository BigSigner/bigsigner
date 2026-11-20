"""GPG menu, date entry, confirmation boundaries, and result rendering."""

import base64
from concurrent.futures import Future
from pathlib import Path

import pytest

from bigsigner import sdcard
from bigsigner.gpg import CommandResult, GpgError, Outcome, PublicKey, parse_keys
from bigsigner.file_qr import QR_SPLIT_LIMIT, gzip_base64, recovery_command, spaced_parts
from bigsigner.ui.app import QR_BRIGHTNESS_DEFAULT, App
from bigsigner.ui.canvas import HEADER, HEIGHT, INK, MARGIN, MUTED, RED, WARNING, WIDTH, font
from test_gpg import COLONS, FPR, SUB_FPR, VERIFY_TIME, VERIFICATION_FAILURES, _import, _prepare_verification_failure, real_backend
from test_sdcard import _tap


class FakeBackend:
    supported = True

    def __init__(self):
        self.calls = []
        self.good = True
        self.kinds = {}
        self.secret = False
        self.subkey_only = False
        self.huge = False
        self.fail_export = False
        self.version_text = "gpg (GnuPG) 2.4.8"

    def version_line(self):
        return self.version_text

    def export_key(self, fingerprint, secret=False, subkey=False):
        self.calls.append(("export", fingerprint, secret, subkey))
        name = "Export Private Key" if secret else "Export Public Key"
        if self.fail_export:
            return Outcome(False, "The key could not be exported.", [CommandResult(name, 2, "", "gpg: skipped")])
        kind = "PRIVATE" if secret else "PUBLIC"
        body = f"-----BEGIN PGP {kind} KEY BLOCK-----\n"
        if self.huge:
            body += "A" * (QR_SPLIT_LIMIT + 1) + "\n"
        body += f"-----END PGP {kind} KEY BLOCK-----\n"
        return Outcome(True, stages=[CommandResult(name, 0, body)])

    def list_keys(self, timestamp=None):
        self.calls.append(("list", timestamp))
        keys = parse_keys(COLONS)
        if self.secret or self.subkey_only:
            keys[0].secret = True
            keys[0].secret_available = self.secret and not self.subkey_only
            keys[0].contains_private = keys[0].secret_available
            for sub in keys[0].subkeys:
                sub["secret"] = True
                sub["contains_private"] = True
        return Outcome(True, keys=keys, stages=[CommandResult("list", 0, COLONS, "listing diagnostics")])

    def inspect_key(self, data, timestamp=None):
        self.calls.append(("inspect", data, timestamp))
        if not self.good:
            return Outcome(False, "The GPG key could not be read.", [CommandResult("Key Details", 2, "", "gpg: no valid OpenPGP data found.")])
        return Outcome(True, keys=parse_keys(COLONS), stages=[CommandResult("Key Details", 0, COLONS, "key preview diagnostics")])

    def import_key(self, data, timestamp=None):
        self.calls.append(("import", data, timestamp))
        return Outcome(True, stages=[CommandResult("Import GPG Key", 0, f"[GNUPG:] IMPORT_OK 1 {FPR}\n[GNUPG:] IMPORT_RES 1 0 1", "gpg: public key imported")])

    def delete_key(self, fingerprint):
        self.calls.append(("delete", fingerprint))
        return Outcome(True, stages=[
            CommandResult("Delete Secret Keys", 0, ""),
            CommandResult("Delete Keys", 0, ""),
        ])

    def mix_entropy(self, digest):
        self.calls.append(("mix", digest))
        return True

    def sign_file(self, fingerprint, relative, storage, timestamp):
        self.calls.append(("sign-file", fingerprint, relative, storage, timestamp))
        return Outcome(True, stages=[CommandResult("Sign File", 0, "", "gpg: Good signature")])

    def sign_folder(self, fingerprint, relative, storage, timestamp):
        self.calls.append(("sign-folder", fingerprint, relative, storage, timestamp))
        return Outcome(True, stages=[CommandResult("Sign File", 0, "", "gpg: Good signature")])

    def add_subkey(self, fingerprint, algo, usage, expire, timestamp):
        self.calls.append(("add-subkey", fingerprint, algo, usage, expire, timestamp))
        keys = parse_keys(COLONS)
        keys[0].secret = True
        keys[0].secret_available = True
        keys[0].contains_private = True
        return Outcome(True, keys=keys, stages=[CommandResult("Add a Subkey", 0)])

    def encrypt_file(self, fingerprints, source, output_name, storage):
        self.calls.append(("encrypt", tuple(fingerprints), source, output_name, storage))
        if self.good:
            return Outcome(True, stages=[CommandResult("Encrypt File", 0, "")])
        return Outcome(False, "The file could not be encrypted.", [CommandResult("Encrypt File", 2, "", "gpg: encryption failed")])

    def encrypt_symmetric(self, source, output_name, storage, password):
        self.calls.append(("encrypt-symmetric", source, output_name, storage, password))
        if self.good:
            return Outcome(True, stages=[CommandResult("Encrypt File", 0, "")])
        return Outcome(False, "The file could not be encrypted.", [CommandResult("Encrypt File", 2, "", "gpg: encryption failed")])

    def encryption_kind(self, relative, storage):
        self.calls.append(("kind", relative, storage))
        kind = self.kinds.get(relative)
        if kind is None:
            raise GpgError("This file is not an encrypted message.")
        return kind

    def decrypt_file(self, source, output_name, storage, password):
        self.calls.append(("decrypt", source, output_name, storage, password))
        if self.good:
            return Outcome(True, stages=[CommandResult("Decrypt File", 0, f'The decrypted file "{output_name}" was written.\n')])
        return Outcome(False, "The file could not be decrypted.", [CommandResult("Decrypt File", 2, "", "gpg: decryption failed")])

    def verify(self, relative, storage, timestamp, checksums):
        self.calls.append(("verify", relative, storage, timestamp, checksums))
        stages = [CommandResult("Signature Verification", 0, f"[GNUPG:] VALIDSIG {FPR}\n", "gpg: Good signature")]
        if checksums:
            stages.append(CommandResult("SHA256 Check", 1, "release.zip: FAILED\nother.zip: OK\n", "sha256sum: WARNING: 1 computed checksum did NOT match", True))
        return Outcome(not checksums, "The SHA256 check failed." if checksums else "", stages)


def _app(files=None, *, fixture_date=True):
    sdcard.mount_memory({"files": files or {"key.asc": "test public key", "release.zip.asc": "signature", "SHASUMS.asc": "checksums"}})
    app = App()
    app.screen = "keys"
    app.gpg.backend = FakeBackend()
    if fixture_date:
        app.gpg.date = dict(year=2025, month=6, day=1)
    _tap(app, "menu")
    _tap(app, "GPG")
    return app


def _settle(app):
    assert app.screen == "gpg-working"
    if not app.gpg.work_shown:
        app.render()
    result = app.gpg.job()
    app.gpg.finish(result)
    app._search_touch_at -= 1
    app._ignore_search_touch()
    app.render()


def _review(source="file", good=True):
    app = _app()
    app.gpg.backend.good = good
    _tap(app, "Load GPG Key")
    assert app.screen == "gpg-key-source"
    assert "gpg-date" not in app.back
    if source == "file":
        _tap(app, "Load from File")
        _tap(app, "SD Card")
        _tap(app, "key.asc")
    else:
        _tap(app, "Scan QR Code")
        app.accept_qr(b"public\x00\xffkey")
    _settle(app)
    return app


def test_gpg_menu_is_below_file_system_and_all_three_routes_are_available():
    app = _app()
    _tap(app, "menu")
    app.render()
    rows = {hit["label"]: hit["box"] for hit in app.hits}
    assert rows["File System"][3] == rows["GPG"][1]
    assert rows["GPG"][3] == rows["Settings"][1]
    _tap(app, "GPG")
    app.render()
    assert {hit["label"] for hit in app.hits} >= {"List GPG Keys", "Load GPG Key", "Verify Signature", "Encrypt", "Decrypt"}
    encrypt = next(hit for hit in app.hits if hit["label"] == "Encrypt")
    decrypt = next(hit for hit in app.hits if hit["label"] == "Decrypt")
    entropy = next(hit for hit in app.hits if hit["label"] == "Add Entropy to OS")
    assert encrypt["box"][1] == decrypt["box"][1] and encrypt["box"][3] == decrypt["box"][3]
    assert encrypt["box"][0] == MARGIN and decrypt["box"][2] == WIDTH - MARGIN
    assert encrypt["box"][2] <= decrypt["box"][0]
    assert encrypt["box"][3] <= entropy["box"][1]
    version = next(item for item in app.texts if item["text"] == "gpg (GnuPG) 2.4.8")
    first = next(hit for hit in app.hits if hit["label"] == "List GPG Keys")
    assert version["box"][3] <= first["box"][1]
    assert version["box"][1] >= HEADER
    assert abs((version["box"][0] + version["box"][2]) / 2 - WIDTH / 2) < 2


def test_gpg_menu_omits_the_version_line_when_gpg_has_no_stdout():
    app = _app()
    app.gpg.backend.version_text = ""
    app.render()
    button = next(hit for hit in app.hits if hit["label"] == "List GPG Keys")
    assert button["box"][1] == HEADER + 24
    assert not any(item["text"].startswith("gpg (") for item in app.texts)


def test_date_selector_uses_utc_and_numeric_editing_and_clamps_leap_day():
    app = _app(fixture_date=False)
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    assert app.gpg.date == dict(year=2026, month=6, day=15)
    assert app.gpg.timestamp() == 1781481600  # 2026-06-15 00:00:00 UTC.
    assert "Hour" not in {hit["label"] for hit in app.hits}
    _tap(app, "Year")
    for digit in "2024":
        _tap(app, digit)
    _tap(app, "Save")
    app.gpg.set_date("month", 2)
    app.gpg.set_date("day", 29)
    _tap(app, "gpg-date-step:year:1")
    assert app.gpg.date["day"] == 28


@pytest.mark.parametrize("source", ["file", "qr"])
def test_key_is_only_imported_after_confirmation_and_cancel_discards_content(source):
    app = _review(source)
    assert app.screen == "gpg-review"
    assert [call[0] for call in app.gpg.backend.calls] == ["inspect"]
    expected = b"test public key" if source == "file" else b"public\x00\xffkey"
    assert app.gpg.backend.calls[0] == ("inspect", expected, None)
    _tap(app, "Cancel")
    assert app.screen == "gpg-key-source" and not app.gpg.key_data
    assert [call[0] for call in app.gpg.backend.calls] == ["inspect"]

    app = _review(source)
    _tap(app, "Confirm")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("import", expected, None)
    assert app.screen == "gpg-result" and app.gpg.outcome.ok
    assert not app.gpg.key_data
    assert "Success" in [item["text"] for item in app.texts]
    _tap(app, "Done")
    assert app.screen == "gpg" and app.back == []
    assert any("IMPORT_OK" in row[2] and row[4] == INK for row in app.gpg.rows)
    assert any("public key imported" in row[2] and row[4] == RED for row in app.gpg.rows)
    label = next(row for row in app.gpg.rows if row[2] == "Exit Status:")
    code = next(row for row in app.gpg.rows if row[2] == "success (0)")
    assert label[1] == code[1] and label[0] < code[0]
    assert label[4] == MUTED and code[4] == INK


def _reveal(app, label):
    button = next(item for item in app.gpg.buttons if item[1] == label)
    app.scroll[app.screen] = max(0, button[0] - HEADER - 24)


def _listed(*, secret=False, subkey_only=False):
    app = _app()
    app.gpg.backend.secret = secret
    app.gpg.backend.subkey_only = subkey_only
    _tap(app, "List GPG Keys")
    _settle(app)
    return app


def test_key_list_shows_three_fields_and_opens_details_with_armored_export():
    app = _listed()
    labels = {row[2] for row in app.gpg.rows}
    assert {"User ID:", "Fingerprint:", "Key ID:"} <= labels
    assert not labels.intersection({"Algorithm:", "Created:", "Expires:", "Validity:", "Subkeys:"})
    _tap(app, "gpg-open:0")
    assert app.screen == "gpg-key-details"
    assert any(row[2] == "Algorithm:" for row in app.gpg.rows)
    assert any(row[2] == "EdDSA (255 bits)" for row in app.gpg.rows)
    rows = app.gpg.rows
    for row, nxt in zip(rows, rows[1:]):
        if row[2] != "Usage:":
            continue
        if nxt[2] == "Encryption":
            assert nxt[1] == row[1]
        if nxt[2] == "Certification and Signing":
            assert nxt[1] > row[1]
    _reveal(app, "Export Public Key")
    app.render()
    assert "Export Public Key" in {hit["label"] for hit in app.hits}
    assert "Export Private Key" not in {hit["label"] for hit in app.hits}
    assert "Export Private Encryption Subkey" not in {hit["label"] for hit in app.hits}
    _tap(app, "Export Public Key")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", FPR, False, False)
    assert app.screen == "gpg-export"
    assert app.gpg.armor.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    _tap(app, "Show QR Code")
    assert app.screen == "gpg-key-qr"
    app.render()
    assert any(item["text"] == "Brightness" for item in app.texts)
    app.qr_brightness = 0
    _tap(app, "back")
    assert app.screen == "gpg-export" and app.qr_brightness == QR_BRIGHTNESS_DEFAULT
    _tap(app, "Export to File")
    _tap(app, "SD Card")
    _tap(app, "New File")
    assert app.filename == f"{FPR}-public.asc"
    app._act("export-save-new")
    assert sdcard.read_text(app.filename, raw=True) == app.gpg.armor
    assert app.screen == "gpg-key-details"
    _tap(app, "back")
    assert app.screen == "gpg-keys"


def test_delete_confirms_then_removes_the_primary_key_and_its_subkeys():
    app = _listed()
    _tap(app, "gpg-open:0")
    delete = next(item for item in app.gpg.buttons if item[1] == "Delete")
    assert delete[2] == "gpg-delete" and delete[5] is True and delete[6] == RED
    primary = app.gpg.cards[0]
    assert primary[1] < delete[0] and delete[0] + delete[3] < primary[3]
    subkey = next(row[1] for row in app.gpg.rows if row[2] == "Subkey")
    assert delete[0] < subkey
    assert [item[1] for item in app.gpg.buttons].count("Delete") == 1
    _reveal(app, "Delete")
    image = app.render()
    hit = next(item for item in app.hits if item["label"] == "Delete")
    assert image.getpixel((hit["box"][0] + 18, (hit["box"][1] + hit["box"][3]) // 2)) == RED
    _tap(app, "Delete")
    assert app.confirm == "gpg-delete" and app.screen == "gpg-key-details"
    assert app._confirm_message() == "Delete this GPG key and its subkeys?"
    image = app.render()
    confirm = next(item for item in app.hits if item["label"] == "Confirm")
    assert image.getpixel((confirm["box"][0] + 18, (confirm["box"][1] + confirm["box"][3]) // 2)) == RED
    _tap(app, "Cancel")
    assert app.confirm is None and app.gpg.backend.calls == [("list", None)]
    _tap(app, "Delete")
    _tap(app, "Confirm")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("delete", FPR)
    assert app.screen == "gpg-result" and app.gpg.outcome.ok
    assert [stage.name for stage in app.gpg.outcome.stages] == ["Delete Secret Keys", "Delete Keys"]
    _tap(app, "back")
    assert app.screen == "gpg-keys"
    app.render()
    assert any(row[2] == "No GPG keys are loaded." for row in app.gpg.rows)


def test_secret_key_can_be_exported_as_a_private_key_and_a_large_key_has_no_qr():
    app = _listed(secret=True)
    _tap(app, "gpg-open:0")
    _reveal(app, "Export Private Key")
    _tap(app, "Export Private Key")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", FPR, True, False)
    assert app.gpg.armor.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    _tap(app, "back")
    app.gpg.backend.huge = True
    _reveal(app, "Export Public Key")
    _tap(app, "Export Public Key")
    _settle(app)
    app.render()
    assert "gpg-export-qr" not in {hit["action"] for hit in app.hits}
    assert "too long" in " ".join(item["text"] for item in app.texts)


def test_a_key_longer_than_one_qr_is_split_until_8000_bytes():
    import base64
    import gzip
    import hashlib

    app = _listed()
    _tap(app, "gpg-open:0")
    _reveal(app, "Export Public Key")
    _tap(app, "Export Public Key")
    _settle(app)
    app.gpg.armor = "A" * 500
    app.render()
    assert "gpg-export-qr" in {hit["action"] for hit in app.hits}
    _tap(app, "Show QR Code")
    assert app.screen == "gpg-qr-guide"
    assert app.gpg.qr_parts == spaced_parts(gzip_base64(b"A" * 500))
    assert app.gpg.qr_parts != ["A" * 500]
    assert app.gpg.qr_command == recovery_command(f"{FPR}-public.asc")
    joined = "".join(app.gpg.qr_parts).replace(" ", "")
    assert gzip.decompress(base64.b64decode(joined)) == b"A" * 500
    seed = b"key"
    pieces = []
    while sum(map(len, pieces)) < 2000:
        seed = hashlib.sha256(seed).digest()
        pieces.append(seed.hex())
    app.gpg.armor = "".join(pieces)[:2000]
    app.screen = "gpg-export"
    _tap(app, "Show QR Code")
    assert len(app.gpg.qr_parts) > 1
    joined = "".join(app.gpg.qr_parts).replace(" ", "")
    assert gzip.decompress(base64.b64decode(joined)) == app.gpg.armor.encode()
    app.render()
    assert any("split over" in item["text"] for item in app.texts)
    _tap(app, "Show QR Codes")
    assert app.screen == "gpg-key-qr"
    app.render()
    assert any(item["text"] == f"1 of {len(app.gpg.qr_parts)}" for item in app.texts)
    assert app.qr_text == app.gpg.qr_parts[0]
    _tap(app, "gpg-qr-next")
    assert app.gpg.qr_index == 1 and app.qr_text == app.gpg.qr_parts[1]
    _tap(app, "back")
    assert app.screen == "gpg-qr-guide"
    app.gpg.armor = "B" * (QR_SPLIT_LIMIT + 1)
    app.screen = "gpg-export"
    app.render()
    assert "gpg-export-qr" not in {hit["action"] for hit in app.hits}


def test_secret_subkey_exports_only_that_subkey_secret():
    app = _listed(secret=True)
    _tap(app, "gpg-open:0")
    _reveal(app, "Export Private Encryption Subkey")
    _tap(app, "Export Private Encryption Subkey")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", SUB_FPR, True, True)
    assert any(item["text"] == "Export Private Subkey" for item in app.texts)
    _tap(app, "Export to File")
    _tap(app, "SD Card")
    _tap(app, "New File")
    assert app.filename == f"{SUB_FPR}-private.asc"


def test_each_subkey_shows_its_usage_fingerprint_and_keeps_its_export_under_it():
    from bigsigner.ui.gpg import PRIVATE_NOTE

    signing, encryption, authentication = "A" * 40, "B" * 40, "C" * 40

    def sub(key_id, fingerprint, capabilities, algo="22", bits="255"):
        return f"sub:-:{bits}:{algo}:{key_id}:1704067200:0:::::{capabilities}:\nfpr:::::::::{fingerprint}:\n"

    text = (
        f"pub:-:255:22:89ABCDEF01234567:1704067200:1767225600:::::c:\nfpr:::::::::{FPR}:\n"
        "uid:-::::::::BigSigner Test <test@example.invalid>:\n"
        + sub("1111111111111111", signing, "s")
        + sub("2222222222222222", encryption, "e", algo="18")
        + sub("3333333333333333", authentication, "a")
    )
    app = _app()
    key, = parse_keys(text)
    key.secret_available = True
    key.contains_private = True
    for item in key.subkeys:
        item["secret"] = True
        item["contains_private"] = True
    app.gpg.selected = key
    app.screen = "gpg-key-details"
    app.gpg.build_details()
    app.render()
    assert [row[2] for row in app.gpg.rows if row[2] in ("Certification", "Signing", "Encryption", "Authentication")] == [
        "Certification", "Signing", "Encryption", "Authentication"]
    usages = [row for row in app.gpg.rows if row[2] == "Usage:"]
    values = [row for row in app.gpg.rows if row[2] in ("Certification", "Signing", "Encryption", "Authentication")]
    assert [row[1] for row in usages] == [row[1] for row in values]
    for item in app.gpg.buttons:
        y, _text, _action, height, inset = item[:5]
        assert inset == 16
        assert any(top < y and y + height < bottom for _left, top, _right, bottom in app.gpg.cards)
    notes = [row for row in app.gpg.rows if row[2] == PRIVATE_NOTE]
    assert len(notes) == 4 and all(row[4] == WARNING for row in notes)
    headings = [row[1] for row in app.gpg.rows if row[2] == "Subkey"]
    assert len(headings) == 3
    labels = ["Export Private Signing Subkey", "Export Private Encryption Subkey", "Export Private Authentication Subkey"]
    note_y = [row[1] for row in notes]
    assert note_y[0] < next(item[0] for item in app.gpg.buttons if item[1] == "Export Private Key") < headings[0]
    for heading, note, label, nxt in zip(headings, note_y[1:], labels, headings[1:] + [10**9]):
        button = next(item[0] for item in app.gpg.buttons if item[1] == label)
        assert heading < note < button < nxt
    groups = " ".join(encryption[i:i + 4] for i in range(0, 16, 4))
    assert any(row[2] == groups and row[5] for row in app.gpg.rows)
    _reveal(app, "Export Private Signing Subkey")
    _tap(app, "Export Private Signing Subkey")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", signing, True, True)


def test_adding_a_subkey_is_disabled_without_the_certificate_secret():
    from bigsigner.ui.gpg import SUBKEY_NOTE

    app = _listed()
    _tap(app, "gpg-open:0")
    _reveal(app, "Add a Subkey")
    app.render()
    button = next(item for item in app.gpg.buttons if item[1] == "Add a Subkey")
    assert button[5] is False
    assert "gpg-add-subkey" not in {hit["action"] for hit in app.hits}
    note = next(row[1] for row in app.gpg.rows if row[2].startswith("Adding a subkey"))
    card = next(card for card in app.gpg.cards if card[1] < button[0] < card[3])
    assert button[0] < note < card[3]


def test_add_subkey_mixes_the_camera_hash_and_uses_the_typed_time(monkeypatch):
    import calendar
    import time

    from bigsigner.entropy import camera_digest

    monkeypatch.setattr(time, "time", lambda: 100)
    app = _listed(secret=True)
    _tap(app, "gpg-open:0")
    _reveal(app, "Add a Subkey")
    _tap(app, "Add a Subkey")
    assert app.screen == "camera" and app.camera_purpose == "gpg"
    app.render()
    assert any(item["text"].startswith("Point the camera at a") for item in app.texts)
    assert "OS random number generation entropy" in " ".join(item["text"] for item in app.texts)
    assert not any("word seed" in item["text"] for item in app.texts)
    app.camera_frames = [b"one"]
    app.camera_final = b"scene"
    _tap(app, "Capture")
    digest = camera_digest([b"one"], b"scene", b"bigsigner-emulator", "100")
    assert app.gpg.backend.calls[-1] == ("mix", digest)
    assert app.screen == "gpg-subkey-options"
    assert app.gpg.subkey_algo == "ed25519" and app.gpg.subkey_usage == "sign"
    assert app.gpg.expire_argument() == "never"
    _tap(app, "No Expiration")
    assert app.screen == "gpg-subkey-expire"
    app.render()
    assert any(item["text"].startswith("Hour:") for item in app.texts)
    assert not any(item["text"].startswith("Minute:") for item in app.texts)
    app.gpg.set_date("hour", 5)
    _tap(app, "Set Expiration")
    assert app.screen == "gpg-subkey-options"
    app.render()
    assert any(item["text"] == "2027-06-15 05:00 UTC" for item in app.texts)
    app.gpg.choose("gpg-algo", "ed25519")
    app.gpg.choose("gpg-usage", "auth")
    app.render()
    _tap(app, "Continue")
    assert app.screen == "gpg-subkey-time"
    app.render()
    assert any(item["text"].startswith("Hour:") for item in app.texts)
    assert any(item["text"].startswith("Minute:") for item in app.texts)
    button = next(hit for hit in app.hits if hit["label"] == "Add a Subkey")
    seconds = next(item for item in app.texts if item["text"] == "Seconds are 00 UTC.")
    assert seconds["box"][3] < button["box"][1]
    app.gpg.set_date("hour", 3)
    app.gpg.set_date("minute", 4)
    _tap(app, "Add a Subkey")
    _settle(app)
    assert app.screen == "gpg-key-details"
    assert app.gpg.backend.calls[-1] == ("add-subkey", FPR, "ed25519", "auth", "20270615T050000", calendar.timegm((2026, 6, 15, 3, 4, 0)))
    app.gpg.clock = "date"
    app.screen = "gpg-date"
    app.render()
    assert not any(item["text"] == "Hour:" for item in app.texts)


def test_failed_export_shows_the_error_screen():
    app = _listed()
    app.gpg.backend.fail_export = True
    _tap(app, "gpg-open:0")
    _reveal(app, "Export Public Key")
    _tap(app, "Export Public Key")
    _settle(app)
    assert app.screen == "gpg-result" and not app.gpg.outcome.ok
    assert any("skipped" in row[2] and row[4] == RED for row in app.gpg.rows)
    _tap(app, "back")
    assert app.screen == "gpg-key-details"


def test_listing_keys_does_not_ask_for_a_date_and_back_returns_to_gpg():
    app = _app()
    _tap(app, "List GPG Keys")
    assert app.screen == "gpg-working"
    assert app.back == ["gpg"]
    _settle(app)
    assert app.screen == "gpg-keys"
    assert app.gpg.backend.calls == [("list", None)]
    _tap(app, "back")
    assert app.screen == "gpg"


def test_failed_key_preview_has_error_and_stderr_without_confirmation_buttons():
    app = _review(good=False)
    assert app.screen == "gpg-result" and not app.gpg.outcome.ok
    assert not any(hit["label"] in ("Confirm", "Cancel") for hit in app.hits)
    assert "Error" in [item["text"] for item in app.texts]
    assert "no valid OpenPGP" in " ".join(item["text"] for item in app.texts)


def test_key_card_labels_are_grey_values_black_and_fingerprint_centered():
    app = _review()
    assert all(row[4] == MUTED for row in app.gpg.rows if row[2] in ("User ID:", "Fingerprint:", "Key ID:", "Algorithm:"))
    groups = [FPR[i:i + 4] for i in range(0, len(FPR), 4)]
    expected = {" ".join(groups[i:i + 4]) for i in range(0, len(groups), 4)}
    fingerprints = [row for row in app.gpg.rows if row[5] and row[2] in expected]
    assert fingerprints
    for x, _y, text, size, color, _mono in fingerprints:
        assert color == INK
        assert abs(x + app.gpg.scratch.draw.textlength(text, font=font(size, mono=True)) / 2 - WIDTH / 2) < 1


@pytest.mark.parametrize("checksums", [False, True])
def test_verification_has_date_selection_and_shows_stdout_stderr_and_checksum_failures(checksums):
    app = _app()
    _tap(app, "Verify Signature")
    _tap(app, "Signed Checksum File" if checksums else "Detached Signature")
    assert app.screen == "gpg-date"
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "SHASUMS.asc" if checksums else "release.zip.asc")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("verify", "SHASUMS.asc" if checksums else "release.zip.asc", "sd", VERIFY_TIME, checksums)
    assert app.gpg.outcome.ok != checksums
    assert any("VALIDSIG" in row[2] and row[4] == INK for row in app.gpg.rows)
    assert any("Good signature" in row[2] and row[4] == RED for row in app.gpg.rows)
    if checksums:
        assert any("FAILED" in row[2] and row[4] == RED for row in app.gpg.rows)
        assert any("other.zip: OK" in row[2] and row[4] == INK for row in app.gpg.rows)
        failure = next(row for row in app.gpg.rows if row[2] == "failure (1)")
        assert failure[4] == RED
        assert any(row[2] == "Exit Status:" and row[1] == failure[1] and row[0] < failure[0] for row in app.gpg.rows)


def test_detached_signature_warns_when_the_matching_file_is_a_checksum_list():
    manifest = (
        "f16b96ae65f74e75279c558d35fb4e325df51195cc3f6e19fa00bc2bc3a2af8c *binary2950.bin\n"
        "\n"
        "   \n"
        "e3630883bf967f2689fbaf4ade9dc4d2a23e32d718c34b69815f13513fd0c628 *binary50k.bin\n"
    )
    files = {
        "SHA256SUMS.asc": "signature",
        "SHA256SUMS": manifest,
        "release.zip.asc": "signature",
        "notes.txt.asc": "signature",
        "notes.txt": "hello\n",
    }
    app = _app(files=files)
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "SHA256SUMS.asc")
    app.render()
    assert app.screen == "gpg-checksum-warning"
    assert app.back[-1] == "gpg-formats"
    assert app.gpg.backend.calls == []
    words = " ".join(item["text"] for item in app.texts)
    assert "This file looks like a checksum file." in words
    assert "Signed Checksum File" in words
    button = next(hit for hit in app.hits if hit["label"] == "Continue")
    for item in app.texts:
        left, top, right, bottom = item["box"]
        assert 0 <= left and right <= WIDTH
        if top >= HEADER:
            assert left >= MARGIN - 1
            assert right <= WIDTH - MARGIN + 1
            assert bottom <= button["box"][1]
    _tap(app, "back")
    assert app.screen == "gpg-formats"

    app = _app(files=files)
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "SHA256SUMS.asc")
    _tap(app, "Continue")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("verify", "SHA256SUMS.asc", "sd", VERIFY_TIME, False)

    app = _app(files=files)
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "notes.txt.asc")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("verify", "notes.txt.asc", "sd", VERIFY_TIME, False)

    app = _app(files=files)
    _tap(app, "Verify Signature")
    _tap(app, "Signed Checksum File")
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "SHA256SUMS.asc")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("verify", "SHA256SUMS.asc", "sd", VERIFY_TIME, True)


def test_checksum_result_lists_up_to_three_unverified_files_in_yellow():
    app = _app()
    app.screen = "gpg-result"
    app.gpg.outcome = Outcome(
        True,
        stages=[
            CommandResult("Signature Verification", 0, "Good signature.\n"),
            CommandResult("SHA256 Check", 0, "binary2950.bin: OK\nbinary50k.bin: OK\n", checksums=True),
        ],
        unverified=["notes.txt", "other.bin", "spare.dat", "extra.log"],
    )
    app.gpg.build_result()
    app.render()
    warning = [row[2] for row in app.gpg.rows if row[4] == WARNING]
    assert all(row[4] == WARNING for row in app.gpg.rows if row[2] in warning)
    assert " ".join(warning).startswith("Other files in the folder were not verified.")
    assert warning[-4:] == ["notes.txt", "other.bin", "spare.dat", "and more..."]
    assert "extra.log" not in warning
    for item in app.texts:
        assert item["box"][0] >= 0 and item["box"][2] <= WIDTH

    app.gpg.outcome.unverified = ["notes.txt", "other.bin", "spare.dat"]
    app.gpg.build_result()
    warning = [row[2] for row in app.gpg.rows if row[4] == WARNING]
    assert warning[-3:] == ["notes.txt", "other.bin", "spare.dat"]
    assert "and more..." not in warning

    app.gpg.outcome.unverified = []
    app.gpg.build_result()
    assert not any(row[4] == WARNING for row in app.gpg.rows)


def test_work_starts_after_the_first_frame_and_completion_starts_a_fresh_input_guard(monkeypatch):
    class ImmediateExecutor:
        def __init__(self, **kwargs):
            pass

        def submit(self, call):
            future = Future()
            future.set_result(call())
            return future

        def shutdown(self, **kwargs):
            pass

    monkeypatch.setattr("concurrent.futures.ThreadPoolExecutor", ImmediateExecutor)
    app = _app()
    _tap(app, "List GPG Keys")
    assert app.screen == "gpg-working" and not app.gpg.backend.calls
    app.render()
    assert not app.gpg.backend.calls
    app.render()
    assert app.gpg.backend.calls == [("list", None)]
    assert app.screen == "gpg-working"
    app.render()
    assert app.screen == "gpg-keys" and app._search_touch_guard
    assert app.frame_presented()


def test_unthreaded_gpg_job_runs_after_the_working_screen_is_shown():
    app = _app()
    app.gpg.backend.threaded = False
    _tap(app, "List GPG Keys")
    assert app.screen == "gpg-working" and not app.gpg.backend.calls
    app.render()
    assert not app.gpg.backend.calls
    app.render()
    assert app.gpg.backend.calls == [("list", None)] and app.screen == "gpg-working"
    app.render()
    assert app.screen == "gpg-keys"


def test_web_emulator_reports_unavailable_commands_without_fabricating_results():
    app = _app()
    app.gpg.backend.supported = False
    _tap(app, "List GPG Keys")
    app.render()
    app.render()
    assert app.screen == "gpg-result" and not app.gpg.outcome.ok
    assert "not available in the web emulator" in app.gpg.outcome.message
    assert not app.gpg.backend.calls


def test_sign_file_follows_the_selected_key_and_warns_before_replacing(monkeypatch):
    import calendar

    signing, encryption = "A" * 40, "B" * 40

    def sub(key_id, fingerprint, capabilities, algo, bits):
        return f"sub:-:{bits}:{algo}:{key_id}:1704067200:0:::::{capabilities}:\nfpr:::::::::{fingerprint}:\n"

    text = (
        f"pub:-:256:19:1111111111111111:1704067200:0:::::c:\nfpr:::::::::{FPR}:\n"
        "uid:-::::::::Certificate Only <cert@example.invalid>:\n"
        + sub("2222222222222222", signing, "s", "22", "255")
        + sub("3333333333333333", encryption, "e", "18", "255")
    )
    app = _app()
    key, = parse_keys(text)
    app.gpg.selected = key
    app.screen = "gpg-key-details"
    app.gpg.build_details()
    app.render()
    labels = [item[1] for item in app.gpg.buttons]
    assert "Sign File" in labels
    assert labels.count("Sign File") == 1
    button = next(item for item in app.gpg.buttons if item[1] == "Sign File")
    assert button[5] is False
    note = next(row[1] for row in app.gpg.rows if row[2].startswith("Signing a file"))
    card = next(card for card in app.gpg.cards if card[1] < button[0] < card[3])
    assert button[0] < note < card[3]
    assert not any(item[1] == "Sign File" and item[0] < note for item in app.gpg.buttons if item is not button)
    key.subkeys[0]["secret"] = True
    key.subkeys[0]["needs_passphrase"] = True
    app.gpg.build_details()
    app.render()
    button = next(item for item in app.gpg.buttons if item[1] == "Sign File")
    assert button[5] is False
    note = next(row[1] for row in app.gpg.rows if row[2].startswith("Signing a file requires a key"))
    card = next(card for card in app.gpg.cards if card[1] < button[0] < card[3])
    assert button[0] < note < card[3]
    assert "gpg-sign-subkey:0" not in {hit["action"] for hit in app.hits}
    key.subkeys[0]["needs_passphrase"] = False
    app.gpg.build_details()
    _reveal(app, "Sign File")
    _tap(app, "Sign File")
    assert app.screen == "camera" and app.camera_purpose == "gpg"
    app.render()
    assert "some signing algorithms" in " ".join(item["text"] for item in app.texts)
    app.camera_frames = [b"one"]
    app.camera_final = b"scene"
    _tap(app, "Capture")
    assert app.gpg.backend.calls[-1][0] == "mix"
    assert app.screen == "gpg-sign-choice"
    sdcard.mount_memory({"dirs": ["packet", "packet/extra"], "files": {
        "readme.txt": "hello\n", "readme.txt.asc": "old",
        "packet/readme.txt": "hello\n", "packet/SHA256SUMS": "old", "packet/extra/skip.txt": "no\n",
    }})
    _tap(app, "Sign a Single File")
    _tap(app, "SD Card")
    _tap(app, "readme.txt")
    assert app.confirm == "gpg-sign-replace"
    assert "readme.txt.asc already exists" in app.gpg.overwrite_message()
    _tap(app, "Confirm")
    assert app.screen == "gpg-sign-time"
    app.gpg.set_date("hour", 3)
    app.gpg.set_date("minute", 4)
    _tap(app, "Sign File")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("sign-file", signing, "readme.txt", "sd", calendar.timegm((2026, 6, 15, 3, 4, 0)))
    app.screen = "gpg-sign-choice"
    _tap(app, "Sign All Files in a Folder")
    _tap(app, "SD Card")
    _tap(app, "packet/")
    _tap(app, "Sign This Folder")
    assert app.confirm == "gpg-sign-subfolders"
    _tap(app, "Confirm")
    assert app.confirm == "gpg-sign-replace"
    _tap(app, "Confirm")
    assert app.screen == "gpg-sign-time"
    _tap(app, "Sign File")
    _settle(app)
    assert app.gpg.backend.calls[-1][0] == "sign-folder"
    assert app.gpg.backend.calls[-1][1] == signing
    assert app.gpg.backend.calls[-1][2] == "packet"
    key.subkeys[0]["algorithm"] = "ECDSA (256 bits)"
    app.screen = "gpg-key-details"
    app.gpg.build_details()
    _reveal(app, "Sign File")
    _tap(app, "Sign File")
    assert app.screen == "camera" and app.camera_purpose == "gpg"
    monkeypatch.setattr("time.time", lambda: 100)
    app.camera_frames = [b"one"]
    app.camera_final = b"scene"
    _tap(app, "Capture")
    assert app.gpg.backend.calls[-1][0] == "mix"
    assert app.screen == "gpg-sign-choice"


def test_encrypt_to_selects_encryption_subkeys_and_names_the_armored_file():
    signing = "A" * 40
    first = "B" * 40
    second = "C" * 40
    primary = PublicKey(fingerprint="D" * 40, user_ids=["Example <e@example.invalid>"], capabilities="sc", subkeys=[
        {"fingerprint": signing, "capabilities": "s", "algorithm": "EdDSA"},
        {"fingerprint": first, "capabilities": "e", "algorithm": "ECDH"},
        {"fingerprint": second, "capabilities": "e", "algorithm": "ECDH"},
    ])
    plain = PublicKey(fingerprint="E" * 40, user_ids=["Signer"], capabilities="s", subkeys=[])
    app = _app(files={"key.asc": "plain", "key.asc.enc.asc": "old"})
    app.gpg.outcome = Outcome(True, keys=[primary, plain])
    app.gpg.build_encrypt_keys()
    actions = [item[2] for item in app.gpg.buttons]
    assert actions == ["gpg-encrypt-toggle:" + first, "gpg-encrypt-toggle:" + second]
    assert not any(signing in item[2] for item in app.gpg.rows)
    app.gpg.backend.calls.clear()
    _tap(app, "Encrypt")
    _tap(app, "Encrypt to GPG Keys")
    _settle(app)
    app.render()
    assert any(hit["label"] == "Select" for hit in app.hits)
    assert not any(hit["label"] == "Continue" for hit in app.hits)
    _tap(app, "Select")
    app.render()
    assert any(hit["label"] == "Selected" for hit in app.hits)
    _tap(app, "Selected")
    app.render()
    assert any(hit["label"] == "Select" for hit in app.hits)
    assert not any(hit["label"] == "Selected" for hit in app.hits)
    _tap(app, "Select")
    _tap(app, "Continue")
    assert app.screen == "storage"
    _tap(app, "SD Card")
    _tap(app, "key.asc")
    assert app.screen == "gpg-encrypt-name"
    assert app.gpg.encrypt_name == "key.asc.enc (1).asc"
    app.gpg.encrypt_name = "key.asc"
    _tap(app, "Encrypt")
    assert app.notice_error
    _tap(app, "Dismiss")
    app.gpg.encrypt_name = "key.asc.enc.asc"
    _tap(app, "Encrypt")
    assert app.confirm == "gpg-encrypt-replace"
    _tap(app, "Confirm")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("encrypt", (SUB_FPR,), "key.asc", "key.asc.enc.asc", "sd")
    assert app.screen == "gpg-result"


def test_aes256_encryption_takes_a_password_or_a_password_file_then_the_camera():
    app = _app(files={
        "note.txt": "hello",
        "secret.txt": "hunter2\n",
        "long.txt": "x" * 256,
        "empty.txt": "",
        "binary.txt": b"\xff",
    })
    _tap(app, "Encrypt")
    app.render()
    assert {hit["label"] for hit in app.hits} >= {"Encrypt to GPG Keys", "Encrypt with AES256"}
    _tap(app, "Encrypt with AES256")
    _tap(app, "SD Card")
    _tap(app, "note.txt")
    assert app.screen == "gpg-aes-password"
    assert app.gpg.encrypt_name == "note.txt.enc.asc"
    _tap(app, "Load from File")
    _tap(app, "SD Card")
    _tap(app, "long.txt")
    assert app.notice == "The password is longer than 255 bytes."
    _tap(app, "Dismiss")
    _tap(app, "empty.txt")
    assert app.notice == "The password file is empty."
    _tap(app, "Dismiss")
    _tap(app, "binary.txt")
    assert app.notice == "The password file is not text."
    _tap(app, "Dismiss")
    _tap(app, "secret.txt")
    assert app.screen == "camera" and app.gpg.camera_for == "aes"
    app.render()
    assert any("AES256" in item["text"] for item in app.texts)
    app.camera_frames = [b"one"]
    app.camera_final = b"scene"
    _tap(app, "Capture")
    _settle(app)
    assert app.gpg.backend.calls[-2][0] == "mix"
    assert app.gpg.backend.calls[-1] == ("encrypt-symmetric", "note.txt", "note.txt.enc.asc", "sd", "hunter2")
    assert app.gpg.encrypt_password == ""

    typed = _app(files={"note.txt": "hello", "note.txt.enc.asc": "old"})
    _tap(typed, "Encrypt")
    _tap(typed, "Encrypt with AES256")
    _tap(typed, "SD Card")
    _tap(typed, "note.txt")
    assert typed.gpg.encrypt_name == "note.txt.enc (1).asc"
    _tap(typed, "Enter Password")
    assert typed.screen == "gpg-aes-type"
    typed.render()
    assert not any(hit["label"] == "Continue" for hit in typed.hits)
    for char in "secret":
        typed._act("passkey-" + char)
    _tap(typed, "Continue")
    assert typed.screen == "camera"
    typed.camera_frames = [b"one"]
    typed.camera_final = b"scene"
    _tap(typed, "Capture")
    _settle(typed)
    assert typed.gpg.backend.calls[-1] == ("encrypt-symmetric", "note.txt", "note.txt.enc (1).asc", "sd", "secret")


def test_decrypt_asks_for_a_password_only_when_the_message_is_symmetric():
    app = _app(files={
        "note.txt.enc.asc": "cipher",
        "key.asc": "locked",
        "plain.txt": "nope",
        "secret.txt": "hunter2\n",
        "long.txt": "x" * 256,
    })
    app.gpg.backend.threaded = False
    app.gpg.backend.kinds = {"note.txt.enc.asc": "symmetric", "key.asc": "key"}
    _tap(app, "Decrypt")
    _tap(app, "SD Card")
    _tap(app, "plain.txt")
    _settle(app)
    assert app.screen == "gpg-result"
    assert "This file is not an encrypted message." in " ".join(item["text"] for item in app.texts)
    _tap(app, "Done")

    _tap(app, "Decrypt")
    _tap(app, "SD Card")
    _tap(app, "note.txt.enc.asc")
    _settle(app)
    assert app.screen == "gpg-decrypt-password"
    assert app.gpg.decrypt_name == "note.txt"
    _tap(app, "Load from File")
    _tap(app, "SD Card")
    _tap(app, "long.txt")
    assert app.notice == "The password is longer than 255 characters."
    _tap(app, "Dismiss")
    _tap(app, "secret.txt")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("decrypt", "note.txt.enc.asc", "note.txt", "sd", "hunter2")
    assert 'The decrypted file "note.txt" was written.' in " ".join(item["text"] for item in app.texts)
    assert app.screen != "camera"

    keyed = _app(files={"key.asc": "locked", "note.txt": "already"})
    keyed.gpg.backend.threaded = False
    keyed.gpg.backend.kinds = {"key.asc": "key"}
    _tap(keyed, "Decrypt")
    _tap(keyed, "SD Card")
    _tap(keyed, "key.asc")
    _settle(keyed)
    assert keyed.screen == "gpg-working"
    _settle(keyed)
    assert keyed.gpg.backend.calls[-1] == ("decrypt", "key.asc", "key", "sd", None)
    assert 'The decrypted file "key" was written.' in " ".join(item["text"] for item in keyed.texts)


def test_gpg_screens_save_screenshots(real_backend):
    from test_ui import ScreenRecord

    backend, root = real_backend
    record = ScreenRecord(Path("artifacts/screenshots/test_gpg_screens_save_screenshots"))
    app = _app(fixture_date=False)
    record.shot(app, "home")
    record.click(app, "menu")
    record.shot(app, "side-menu")
    menu = _app(fixture_date=False)
    menu.gpg.backend = backend
    record.shot(menu, "gpg")
    assert any(item["text"] == backend.version_line() for item in menu.texts)
    record.click(app, "GPG")
    record.click(app, "Verify Signature")
    record.click(app, "Detached Signature")
    record.shot(app, "date")
    record.click(app, "Year")
    record.shot(app, "year-entry")
    record.click(app, "back")
    record.click(app, "back")
    record.click(app, "back")
    record.click(app, "Load GPG Key")
    record.shot(app, "key-source")
    enc = _app(fixture_date=False)
    record.click(enc, "Encrypt")
    record.shot(enc, "encrypt-menu")
    record.click(enc, "Encrypt to GPG Keys")
    record.shot(enc, "encrypt-listing")
    _settle(enc)
    record.shot(enc, "encrypt-keys")
    record.click(enc, "Select")
    record.shot(enc, "encrypt-selected")
    record.click(enc, "Continue")
    record.click(enc, "SD Card")
    record.shot(enc, "encrypt-file")
    record.click(enc, "key.asc")
    record.shot(enc, "encrypt-name")
    record.click(enc, "Encrypt")
    record.shot(enc, "encrypting-file")
    _settle(enc)
    record.shot(enc, "encrypt-result")
    from test_domain import ABANDON

    bip = _app(fixture_date=False)
    record.click(bip, "Load GPG Key")
    record.click(bip, "Load RSA Key from Bitcoin Seed (BIP-85)")
    record.shot(bip, "bip85-no-seed")
    added = bip.session.add_mnemonic(ABANDON.split())
    record.click(bip, "back")
    record.click(bip, "Load RSA Key from Bitcoin Seed (BIP-85)")
    record.shot(bip, "bip85-seed")
    record.click(bip, "gpg-bip85-pick:" + added["fingerprint"].hex())
    record.shot(bip, "bip85-options")
    record.click(bip, "dropdown-gpg-bits")
    record.shot(bip, "bip85-bits")
    record.click(bip, "3072 bits")
    record.click(bip, "Index")
    record.shot(bip, "bip85-index")
    record.click(bip, "back")
    record.click(bip, "Continue")
    record.shot(bip, "bip85-details")
    record.click(bip, "dropdown-gpg-role")
    record.shot(bip, "bip85-role")
    record.click(bip, "Certificate Only")
    record.click(bip, "Name")
    record.shot(bip, "bip85-name")
    bip.gpg.bip85_draft = "Ada Lovelace"
    record.click(bip, "Save")
    record.click(bip, "Email")
    bip.gpg.bip85_draft = "ada@example.invalid"
    record.click(bip, "Save")
    record.shot(bip, "bip85-filled")
    record.click(bip, "Expires")
    record.shot(bip, "bip85-expire")
    record.click(bip, "Set Expiration")
    record.click(bip, "Create Key")
    record.shot(bip, "bip85-working")
    _settle(bip)
    record.shot(bip, "bip85-result")
    record.click(app, "Scan QR Code")
    app.accept_qr(b"test key")
    record.shot(app, "working")
    _settle(app)
    record.shot(app, "key-review")
    app.scroll["gpg-review"] = 10**9
    record.shot(app, "key-review-bottom")
    record.click(app, "Confirm")
    _settle(app)
    record.shot(app, "import-success")
    app.scroll["gpg-result"] = 10**9
    record.shot(app, "import-success-bottom")
    record.click(app, "Done")
    record.shot(app, "gpg-home")
    app = _app()
    record.click(app, "List GPG Keys")
    _settle(app)
    record.shot(app, "gpg-keys")
    record.click(app, "gpg-open:0")
    record.shot(app, "gpg-key")
    _reveal(app, "Add a Subkey")
    record.shot(app, "add-subkey-disabled")
    _reveal(app, "Sign File")
    record.shot(app, "sign-file-disabled")
    _reveal(app, "Export Public Key")
    record.shot(app, "gpg-key-bottom")
    _reveal(app, "Delete")
    record.shot(app, "gpg-key-delete")
    record.click(app, "Delete")
    record.shot(app, "gpg-key-delete-confirm")
    record.click(app, "Cancel")
    record.click(app, "Export Public Key")
    _settle(app)
    record.shot(app, "export-public")
    app = _listed(secret=True)
    record.click(app, "gpg-open:0")
    _reveal(app, "Export Private Encryption Subkey")
    record.shot(app, "gpg-key-private")
    assert "Export Private Encryption Subkey" in {hit["label"] for hit in app.hits}
    _reveal(app, "Export Private Key")
    record.click(app, "Export Private Key")
    _settle(app)
    record.shot(app, "export-private")
    record.click(app, "Show QR Code")
    record.shot(app, "private-key-qr")
    app = _listed(subkey_only=True)
    record.click(app, "gpg-open:0")
    _reveal(app, "Export Private Encryption Subkey")
    record.shot(app, "gpg-subkey-only")
    assert "Export Private Key" not in {hit["label"] for hit in app.hits}
    assert "Export Private Encryption Subkey" in {hit["label"] for hit in app.hits}
    record.click(app, "Export Private Encryption Subkey")
    _settle(app)
    record.shot(app, "export-subkey")
    signing, encryption, authentication = "A" * 40, "B" * 40, "C" * 40

    def sub(key_id, fingerprint, capabilities, algo="22", bits="255"):
        return f"sub:-:{bits}:{algo}:{key_id}:1704067200:0:::::{capabilities}:\nfpr:::::::::{fingerprint}:\n"

    text = (
        f"pub:-:255:22:89ABCDEF01234567:1704067200:1767225600:::::c:\nfpr:::::::::{FPR}:\n"
        "uid:-::::::::BigSigner Test <test@example.invalid>:\n"
        + sub("1111111111111111", signing, "s")
        + sub("2222222222222222", encryption, "e", algo="18")
        + sub("3333333333333333", authentication, "a")
    )
    app = _app()
    key, = parse_keys(text)
    key.secret_available = True
    key.contains_private = True
    for item in key.subkeys:
        item["secret"] = True
        item["contains_private"] = True
    app.gpg.selected = key
    app.screen = "gpg-key-details"
    app.gpg.build_details()
    record.shot(app, "certificate-usage")
    for label, name in (("Export Private Signing Subkey", "signing-subkey"),
                        ("Export Private Encryption Subkey", "encryption-subkey"),
                        ("Export Private Authentication Subkey", "authentication-subkey")):
        _reveal(app, label)
        record.shot(app, name)
        record.click(app, label)
        app.gpg.selected = key
        app.screen = "gpg-key-details"
        app.gpg.build_details()
    _reveal(app, "Add a Subkey")
    record.shot(app, "add-subkey")
    record.click(app, "Add a Subkey")
    record.shot(app, "subkey-camera")
    app.camera_final = b"scene"
    app.camera_frames = [b"scene"]
    record.click(app, "Capture")
    record.shot(app, "subkey-options")
    record.click(app, "Ed25519")
    record.shot(app, "subkey-algorithm")
    record.click(app, "dropdown-pick-gpg-algo-ed25519")
    record.click(app, "Signing")
    record.shot(app, "subkey-usage")
    record.click(app, "dropdown-pick-gpg-usage-sign")
    record.click(app, "No Expiration")
    record.shot(app, "subkey-expire")
    record.click(app, "Set Expiration")
    record.shot(app, "subkey-expires-set")
    record.click(app, "Continue")
    record.shot(app, "subkey-time")
    record.click(app, "Add a Subkey")
    record.shot(app, "adding-subkey")
    _settle(app)
    record.shot(app, "subkey-added")
    signing = "A" * 40
    text = (
        f"pub:-:256:19:1111111111111111:1704067200:0:::::c:\nfpr:::::::::{FPR}:\n"
        "uid:-::::::::BigSigner Test <test@example.invalid>:\n"
        f"sub:-:255:22:2222222222222222:1704067200:0:::::s:\nfpr:::::::::{signing}:\n"
    )
    app = _app()
    sdcard.mount_memory({"dirs": ["packet", "packet/extra"], "files": {
        "readme.txt": "hello\n", "readme.txt.asc": "old signature",
        "packet/readme.txt": "hello\n", "packet/SHA256SUMS": "old", "packet/SHA256SUMS.asc": "old signature",
        "packet/extra/skip.txt": "no\n",
    }})
    key, = parse_keys(text)
    key.subkeys[0]["secret"] = True
    key.subkeys[0]["contains_private"] = True
    key.subkeys[0]["needs_passphrase"] = True
    app.gpg.selected = key
    app.screen = "gpg-key-details"
    app.gpg.build_details()
    _reveal(app, "Sign File")
    record.shot(app, "sign-file-passphrase")
    key.subkeys[0]["needs_passphrase"] = False
    app.gpg.build_details()
    _reveal(app, "Sign File")
    record.shot(app, "sign-file")
    record.click(app, "Sign File")
    record.shot(app, "sign-camera")
    app.camera_final = b"scene"
    app.camera_frames = [b"scene"]
    record.click(app, "Capture")
    record.shot(app, "sign-choice")
    record.click(app, "Sign a Single File")
    record.click(app, "SD Card")
    record.click(app, "readme.txt")
    record.shot(app, "sign-replace")
    record.click(app, "Confirm")
    record.shot(app, "sign-time")
    record.click(app, "Sign File")
    record.shot(app, "signing-file")
    _settle(app)
    record.shot(app, "sign-result")
    app.screen = "gpg-sign-choice"
    record.click(app, "Sign All Files in a Folder")
    record.click(app, "SD Card")
    record.click(app, "packet/")
    record.shot(app, "sign-folder")
    record.click(app, "Sign This Folder")
    record.shot(app, "sign-subfolders")
    record.click(app, "Confirm")
    record.shot(app, "sign-folder-replace")
    record.click(app, "Confirm")
    record.shot(app, "sign-folder-time")
    app = _app()
    record.click(app, "Verify Signature")
    record.shot(app, "verification-formats")
    record.click(app, "Signed Checksum File")
    record.click(app, "Continue")
    record.click(app, "SD Card")
    record.click(app, "SHASUMS.asc")
    _settle(app)
    record.shot(app, "checksum-failure")
    app.scroll["gpg-result"] = 10**9
    record.shot(app, "checksum-failure-bottom")
    app = _review(good=False)
    record.shot(app, "key-error")

    _import(backend)
    for filename, failure in VERIFICATION_FAILURES:
        _prepare_verification_failure(root, filename, failure)
        app = _app(files={filename: (root / filename).read_bytes()})
        app.gpg.backend = backend
        record.click(app, "Verify Signature")
        record.click(app, "Detached Signature" if filename == "release.txt.asc" else "Signed Checksum File")
        record.click(app, "Continue")
        record.click(app, "SD Card")
        record.click(app, filename)
        _settle(app)
        assert app.screen == "gpg-result" and not app.gpg.outcome.ok
        assert "Error" in [item["text"] for item in app.texts]
        if failure == "invalid-signature":
            assert len(app.gpg.outcome.stages) == 1
            assert any("BADSIG" in row[2] and row[4] == INK for row in app.gpg.rows)
            assert any("BAD signature" in row[2] and row[4] == RED for row in app.gpg.rows)
        else:
            assert app.gpg.outcome.stages[0].returncode == 0
            assert any("release.txt: FAILED" in row[2] and row[4] == RED for row in app.gpg.rows)
            assert app.gpg.outcome.stages[-1].stderr
        label = filename.replace(".", "-").lower() + "-" + failure
        record.shot(app, label)
        app.scroll["gpg-result"] = 10**9
        record.shot(app, label + "-bottom")


def test_bip85_load_asks_for_a_seed_and_imports_one_primary_key():
    from test_domain import ABANDON

    app = _app()
    _tap(app, "Load GPG Key")
    _tap(app, "Load RSA Key from Bitcoin Seed (BIP-85)")
    app.render()
    assert "Load a seed before deriving a GPG key." in " ".join(item["text"] for item in app.texts)
    added = app.session.add_mnemonic(ABANDON.split())
    _tap(app, "back")
    _tap(app, "Load RSA Key from Bitcoin Seed (BIP-85)")
    app.render()
    assert any(item["text"] == "Select Seed" for item in app.texts)
    assert added["fingerprint"].hex() in {item["text"] for item in app.texts}
    assert "abandon\u2026" in {item["text"] for item in app.texts}
    _tap(app, "gpg-bip85-pick:" + added["fingerprint"].hex())
    app.render()
    text = " ".join(item["text"] for item in app.texts)
    assert "BigSigner only generates primary keys, not subkeys." in text
    assert any("m/83696968h/828365h/4096h/0h" in item["text"] for item in app.texts)
    _tap(app, "+")
    assert app.gpg.bip85_index == 1
    _tap(app, "dropdown-gpg-bits")
    _tap(app, "3072 bits")
    app.render()
    assert any("m/83696968h/828365h/3072h/1h" in item["text"] for item in app.texts)
    _tap(app, "Continue")
    app.render()
    assert app.screen == "gpg-bip85-details"
    assert "gpg-bip85-create" not in {hit["action"] for hit in app.hits}
    _tap(app, "dropdown-gpg-role")
    _tap(app, "Certificate Only")
    _tap(app, "Name")
    for char in "Ada Lovelace":
        app._act("passkey- " if char == " " else "passkey-" + char)
    _tap(app, "Save")
    app.render()
    assert "gpg-bip85-create" in {hit["action"] for hit in app.hits}
    _tap(app, "Email")
    for char in "ada@example.invalid":
        app._act("passkey-" + char)
    _tap(app, "Save")
    _tap(app, "Expires")
    app.render()
    assert not any(item["text"].startswith("Hour") for item in app.texts)
    assert any(item["text"] == "The time is 00:00:00 UTC." for item in app.texts)
    _tap(app, "Set Expiration")
    assert app.gpg.bip85_expires == dict(year=2026, month=6, day=15)
    _tap(app, "Create Key")
    _settle(app)
    kind, data, _timestamp = app.gpg.backend.calls[-1]
    assert kind == "import"
    body = b"".join(line.strip() for line in data.splitlines() if line and not line.startswith(b"-----"))
    assert b"Ada Lovelace <ada@example.invalid>" in base64.b64decode(body)
    assert app.screen == "gpg-result"


def _on_screen(app):
    for item in list(app.texts) + list(app.hits):
        left, _top, right, bottom = item["box"]
        assert 0 <= left and right <= WIDTH, item.get("text") or item.get("label")
        assert bottom <= HEIGHT, item.get("text") or item.get("label")


def test_add_entropy_mixes_a_camera_capture_or_bip85_raw_entropy():
    from bigsigner.bip85gpg import raw_entropy
    from test_domain import ABANDON

    app = _app()
    app.render()
    _on_screen(app)
    _tap(app, "Add Entropy to OS")
    app.render()
    _on_screen(app)
    assert {hit["label"] for hit in app.hits} >= {"Camera", "Bitcoin Seed Raw Entropy (BIP-85)"}
    _tap(app, "Camera")
    assert app.screen == "camera" and app.gpg.camera_for == "entropy"
    app.render()
    caption = " ".join(item["text"] for item in app.texts)
    assert "This capture is mixed into the OS random number generation entropy" in caption
    app.camera_final = b"picture"
    app.camera_frames = [b"picture"]
    _tap(app, "Capture")
    app.render()
    assert app.screen == "gpg-result"
    mixed = [call for call in app.gpg.backend.calls if call[0] == "mix"]
    assert len(mixed) == 1 and len(mixed[0][1]) == 32
    assert app.gpg.outcome.message == "Entropy was added to the OS."
    assert "".join(row[2] for row in app.gpg.rows).replace(" ", "") == "EntropywasaddedtotheOS."

    app = _app()
    _tap(app, "Add Entropy to OS")
    _tap(app, "Bitcoin Seed Raw Entropy (BIP-85)")
    app.render()
    assert "".join(item["text"] for item in app.texts).replace(" ", "") == "SelectSeedLoadaseedbeforederivingentropy."
    added = app.session.add_mnemonic(ABANDON.split())
    _tap(app, "back")
    _tap(app, "Bitcoin Seed Raw Entropy (BIP-85)")
    _tap(app, "gpg-entropy-pick:" + added["fingerprint"].hex())
    app.render()
    text = " ".join(item["text"] for item in app.texts)
    assert "Choose a unique index that will not be used for other purposes." in text
    assert "number of seconds since 1970-01-01." in text
    assert any(item["text"] == "m/83696968h/128169h/64h/0h" for item in app.texts)
    _on_screen(app)
    _tap(app, "Index")
    _tap(app, "7")
    _tap(app, "Use This Index")
    app.render()
    assert app.gpg.entropy_index == 7
    assert any(item["text"] == "m/83696968h/128169h/64h/7h" for item in app.texts)
    _tap(app, "Add Entropy")
    app.render()
    assert app.screen == "gpg-result"
    seed_mix = [call for call in app.gpg.backend.calls if call[0] == "mix"]
    assert seed_mix[-1][1] == raw_entropy(app.session.fingerprints[added["fingerprint"]].keys[0].root, 7)
    assert app.gpg.outcome.message == "Entropy was added to the OS."
    assert "".join(row[2] for row in app.gpg.rows).replace(" ", "") == "EntropywasaddedtotheOS."

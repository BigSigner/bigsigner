"""GPG menu, date entry, confirmation boundaries, and result rendering."""

from concurrent.futures import Future
from pathlib import Path

import pytest

from bigsigner import sdcard
from bigsigner.gpg import CommandResult, Outcome, parse_keys
from bigsigner.qr import MAX_BYTE_PAYLOAD
from bigsigner.ui.app import QR_BRIGHTNESS_DEFAULT, App
from bigsigner.ui.canvas import HEADER, HEIGHT, INK, MUTED, RED, WARNING, WIDTH, font
from test_gpg import COLONS, FPR, SUB_FPR, VERIFY_TIME, VERIFICATION_FAILURES, _import, _prepare_verification_failure, real_backend
from test_sdcard import _tap


class FakeBackend:
    supported = True

    def __init__(self):
        self.calls = []
        self.good = True
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
            body += "A" * (MAX_BYTE_PAYLOAD + 1) + "\n"
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
    assert {hit["label"] for hit in app.hits} >= {"List GPG Keys", "Load GPG Key", "Verify Signature"}
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
    assert "too large" in " ".join(item["text"] for item in app.texts)


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
    for y, _text, _action, height, inset in app.gpg.buttons:
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


def test_web_emulator_reports_unavailable_commands_without_fabricating_results():
    app = _app()
    app.gpg.backend.supported = False
    _tap(app, "List GPG Keys")
    app.render()
    app.render()
    assert app.screen == "gpg-result" and not app.gpg.outcome.ok
    assert "not available in the web emulator" in app.gpg.outcome.message
    assert not app.gpg.backend.calls


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
    app = _app()
    record.click(app, "List GPG Keys")
    _settle(app)
    record.shot(app, "gpg-keys")
    record.click(app, "gpg-open:0")
    record.shot(app, "gpg-key")
    _reveal(app, "Export Public Key")
    record.shot(app, "gpg-key-bottom")
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

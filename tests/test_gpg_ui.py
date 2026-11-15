"""GPG menu, date entry, confirmation boundaries, and result rendering."""

from concurrent.futures import Future
from pathlib import Path

import pytest

from bigsigner import sdcard
from bigsigner.gpg import CommandResult, Outcome, parse_keys
from bigsigner.qr import MAX_BYTE_PAYLOAD
from bigsigner.ui.app import QR_BRIGHTNESS_DEFAULT, App
from bigsigner.ui.canvas import HEADER, HEIGHT, INK, MUTED, RED, WIDTH, font
from test_gpg import COLONS, FPR, VERIFY_TIME, VERIFICATION_FAILURES, _import, _prepare_verification_failure, real_backend
from test_sdcard import _tap


class FakeBackend:
    supported = True

    def __init__(self):
        self.calls = []
        self.good = True
        self.secret = False
        self.huge = False
        self.fail_export = False
        self.version_text = "gpg (GnuPG) 2.4.8"

    def version_line(self):
        return self.version_text

    def export_key(self, fingerprint, secret=False):
        self.calls.append(("export", fingerprint, secret))
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
        if self.secret:
            keys[0].secret = True
        return Outcome(True, keys=keys, stages=[CommandResult("list", 0, COLONS, "listing diagnostics")])

    def inspect_key(self, data, timestamp=None):
        self.calls.append(("inspect", data, timestamp))
        if not self.good:
            return Outcome(False, "The trusted key could not be read.", [CommandResult("Key Details", 2, "", "gpg: no valid OpenPGP data found.")])
        return Outcome(True, keys=parse_keys(COLONS), stages=[CommandResult("Key Details", 0, COLONS, "key preview diagnostics")])

    def import_key(self, data, timestamp=None):
        self.calls.append(("import", data, timestamp))
        return Outcome(True, stages=[CommandResult("Import Trusted Key", 0, f"[GNUPG:] IMPORT_OK 1 {FPR}\n[GNUPG:] IMPORT_RES 1 0 1", "gpg: public key imported")])

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
        app.gpg.date = dict(year=2025, month=6, day=1, hour=0)
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
    _tap(app, "Load Trusted Key")
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
    assert {hit["label"] for hit in app.hits} >= {"List Trusted Keys", "Load Trusted Key", "Verify Signature"}
    version = next(item for item in app.texts if item["text"] == "gpg (GnuPG) 2.4.8")
    first = next(hit for hit in app.hits if hit["label"] == "List Trusted Keys")
    assert version["box"][3] <= first["box"][1]
    assert version["box"][1] >= HEADER
    assert abs((version["box"][0] + version["box"][2]) / 2 - WIDTH / 2) < 2


def test_gpg_menu_omits_the_version_line_when_gpg_has_no_stdout():
    app = _app()
    app.gpg.backend.version_text = ""
    app.render()
    button = next(hit for hit in app.hits if hit["label"] == "List Trusted Keys")
    assert button["box"][1] == HEADER + 24
    assert not any(item["text"].startswith("gpg (") for item in app.texts)


def test_date_selector_uses_utc_and_numeric_editing_and_clamps_leap_day():
    app = _app(fixture_date=False)
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    assert app.gpg.date == dict(year=2026, month=6, day=15, hour=13)
    assert app.gpg.timestamp() == 1781528400  # 2026-06-15 13:00 UTC.
    _tap(app, "Year")
    for digit in "2024":
        _tap(app, digit)
    _tap(app, "Save")
    app.gpg.set_date("month", 2)
    app.gpg.set_date("day", 29)
    _tap(app, "gpg-date-step:year:1")
    assert app.gpg.date["day"] == 28
    _tap(app, "Hour")
    _tap(app, "2")
    _tap(app, "5")
    _tap(app, "Save")
    assert app.screen == "gpg-number"
    assert "between 0 and 23" in app.gpg.date_error


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


def _listed(*, secret=False):
    app = _app()
    app.gpg.backend.secret = secret
    _tap(app, "List Trusted Keys")
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
    app.scroll["gpg-key-details"] = 10**9
    app.render()
    assert "Export Public Key" in {hit["label"] for hit in app.hits}
    assert "Export Private Key" not in {hit["label"] for hit in app.hits}
    _tap(app, "Export Public Key")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", FPR, False)
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
    app.scroll["gpg-key-details"] = 10**9
    app.render()
    assert any(row[2] == "This key has a private key." for row in app.gpg.rows)
    _tap(app, "Export Private Key")
    _settle(app)
    assert app.gpg.backend.calls[-1] == ("export", FPR, True)
    assert app.gpg.armor.startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    _tap(app, "back")
    app.gpg.backend.huge = True
    _tap(app, "Export Public Key")
    _settle(app)
    app.render()
    assert "gpg-export-qr" not in {hit["action"] for hit in app.hits}
    assert "too large" in " ".join(item["text"] for item in app.texts)


def test_failed_export_shows_the_error_screen():
    app = _listed()
    app.gpg.backend.fail_export = True
    _tap(app, "gpg-open:0")
    app.scroll["gpg-key-details"] = 10**9
    _tap(app, "Export Public Key")
    _settle(app)
    assert app.screen == "gpg-result" and not app.gpg.outcome.ok
    assert any("skipped" in row[2] and row[4] == RED for row in app.gpg.rows)
    _tap(app, "back")
    assert app.screen == "gpg-key-details"


def test_listing_keys_does_not_ask_for_a_date_and_back_returns_to_gpg():
    app = _app()
    _tap(app, "List Trusted Keys")
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
    _tap(app, "List Trusted Keys")
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
    _tap(app, "List Trusted Keys")
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
    _tap(app, "menu")
    record.shot(app, "side-menu")
    menu = _app(fixture_date=False)
    menu.gpg.backend = backend
    record.shot(menu, "gpg")
    assert any(item["text"] == backend.version_line() for item in menu.texts)
    _tap(app, "GPG")
    _tap(app, "Verify Signature")
    _tap(app, "Detached Signature")
    record.shot(app, "date")
    _tap(app, "Year")
    record.shot(app, "year-entry")
    _tap(app, "back")
    _tap(app, "back")
    _tap(app, "back")
    _tap(app, "Load Trusted Key")
    record.shot(app, "key-source")
    _tap(app, "Scan QR Code")
    app.accept_qr(b"test key")
    record.shot(app, "working")
    _settle(app)
    record.shot(app, "key-review")
    app.scroll["gpg-review"] = 10**9
    record.shot(app, "key-review-bottom")
    _tap(app, "Confirm")
    _settle(app)
    record.shot(app, "import-success")
    app.scroll["gpg-result"] = 10**9
    record.shot(app, "import-success-bottom")
    app = _app()
    _tap(app, "List Trusted Keys")
    _settle(app)
    record.shot(app, "trusted-keys")
    _tap(app, "gpg-open:0")
    record.shot(app, "trusted-key")
    app.scroll["gpg-key-details"] = 10**9
    record.shot(app, "trusted-key-bottom")
    _tap(app, "Export Public Key")
    _settle(app)
    record.shot(app, "export-public")
    app = _app()
    _tap(app, "Verify Signature")
    record.shot(app, "verification-formats")
    _tap(app, "Signed Checksum File")
    _tap(app, "Continue")
    _tap(app, "SD Card")
    _tap(app, "SHASUMS.asc")
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
        _tap(app, "Verify Signature")
        _tap(app, "Detached Signature" if filename == "release.txt.asc" else "Signed Checksum File")
        _tap(app, "Continue")
        _tap(app, "SD Card")
        _tap(app, filename)
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

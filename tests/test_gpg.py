"""GnuPG parsing, process status, and real detached/clear-signed test vectors."""

from pathlib import Path
import calendar
import os
import shutil
import struct
import subprocess
import tempfile

import pytest

from bigsigner import sdcard
from bigsigner.gpg import (
    CHECKSUM_NAME, CommandResult, GpgBackend, GpgError, check_manifest_paths, decrypted_filename,
    files_left_unchecked, pgp_encryption_kind,
    looks_like_sha256sums, manifest_filenames, manifest_for_name, mix_kernel_entropy, parse_keys, passphrase_required,
    quick_add_arguments, sha256_manifest, signature_is_deterministic, signature_ok,
)

VECTORS = Path(__file__).parent / "vectors" / "gpg"
VERIFY_TIME = 1748736000  # 2025-06-01 00:00 UTC, within the fixture key's lifetime.
FPR = "0123456789ABCDEF0123456789ABCDEF01234567"
SUB_FPR = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
COLONS = f"pub:-:255:22:89ABCDEF01234567:1704067200:1767225600:::::sc:\nfpr:::::::::{FPR}:\nuid:-::::::::BigSigner\\x3a Test <test@example.invalid>:\nsub:-:255:18:0123456789ABCDEF:1704067200:0:::::e:\nfpr:::::::::{SUB_FPR}:\n"
VERIFICATION_FAILURES = (
    ("SHASUMS.asc", "missing-file"),
    ("CLEAR.asc", "missing-file"),
    ("SHASUMS.asc", "wrong-hash"),
    ("CLEAR.asc", "wrong-hash"),
    ("release.txt.asc", "invalid-signature"),
    ("SHASUMS.asc", "invalid-signature"),
)


def test_an_image_check_keeps_only_that_files_checksum_line():
    digest = b"a" * 64
    other = b"b" * 64
    body = digest + b" *os.img\n" + other + b" *other.bin\n" + b"not a checksum\n"
    assert manifest_for_name(body, "os.img") == digest + b" *os.img\n"
    assert manifest_for_name(body, "other.bin") == other + b" *other.bin\n"
    assert manifest_for_name(body, "missing.img") is None
    with pytest.raises(GpgError):
        manifest_for_name(body, "../os.img")


def test_a_sha256sums_file_is_ascii_lines_of_digests_blanks_or_spaces():
    body = (
        b"f16b96ae65f74e75279c558d35fb4e325df51195cc3f6e19fa00bc2bc3a2af8c *binary2950.bin\n"
        b"\n"
        b"   \n"
        b"E3630883BF967F2689FBAF4ADE9DC4D2A23E32D718C34B69815F13513FD0C628  release.txt\n"
    )
    assert looks_like_sha256sums(body)
    assert looks_like_sha256sums(b"a" * 64 + b" name")
    assert not looks_like_sha256sums(b"\n   \n")
    assert not looks_like_sha256sums(body + b"not a checksum\n")
    assert not looks_like_sha256sums(b"a" * 63 + b" name\n")
    assert not looks_like_sha256sums(b"a" * 64 + b"\n")
    assert not looks_like_sha256sums(b"a" * 64 + b"\tname\n")
    assert not looks_like_sha256sums(body + "café\n".encode())
    assert not looks_like_sha256sums(b"psbt\xff")


def test_checksum_names_omit_the_binary_mode_marker_and_other_folder_files_remain():
    manifest = (
        b"f16b96ae65f74e75279c558d35fb4e325df51195cc3f6e19fa00bc2bc3a2af8c *binary2950.bin\n"
        b"e3630883bf967f2689fbaf4ade9dc4d2a23e32d718c34b69815f13513fd0c628  binary50k.bin\n"
    )
    assert manifest_filenames(manifest) == ["binary2950.bin", "binary50k.bin"]
    present = ["SHA256SUMS", "SHA256SUMS.asc", "binary2950.bin", "binary50k.bin", "notes.txt", "extra.bin"]
    assert files_left_unchecked(present, manifest_filenames(manifest), "SHA256SUMS", "SHA256SUMS.asc") == [
        "notes.txt", "extra.bin",
    ]


def test_colon_keys_preserve_primary_fingerprint_escape_uid_and_parse_subkeys():
    key, = parse_keys(COLONS + "future:ignored:record:\n")
    assert key.fingerprint == FPR
    assert key.user_ids == ["BigSigner: Test <test@example.invalid>"]
    assert key.subkeys[0]["fingerprint"] == SUB_FPR
    assert key.subkeys[0]["expires"] == "Never"
    assert key.capabilities == "sc"
    assert key.subkeys[0]["capabilities"] == "e"
    assert not key.subkeys[0]["secret"]
    assert key.created == "2024-01-01 00:00 UTC"
    assert key.expires == "2026-01-01 00:00 UTC"
    epoch, = parse_keys(COLONS.replace(":1704067200:", ":0:"))
    assert epoch.created == "1970-01-01 00:00 UTC"


def test_missing_primary_fingerprint_and_secret_key_records_are_refused():
    with pytest.raises(GpgError, match="primary fingerprint"):
        parse_keys(COLONS.replace(f"fpr:::::::::{FPR}:\n", ""))
    secret = COLONS.replace("pub:", "sec:", 1).replace("sub:", "ssb:", 1)
    with pytest.raises(GpgError, match="Only public"):
        parse_keys(secret)
    key, = parse_keys(secret, secret=True)
    assert key.secret and key.fingerprint == FPR
    assert key.subkeys[0]["fingerprint"] == SUB_FPR


def _secret_listing(text):
    """Turn a public colon listing into a secret listing whose private keys are present."""
    lines = []
    for line in text.splitlines():
        kind, separator, rest = line.partition(":")
        if kind == "pub":
            kind = "sec"
        elif kind == "sub":
            kind = "ssb"
        line = kind + separator + rest
        if kind in ("sec", "ssb"):
            parts = line.split(":")
            parts += [""] * (15 - len(parts))
            parts[14] = "+"
            line = ":".join(parts)
        lines.append(line)
    return "\n".join(lines)


def test_list_marks_secret_keys_and_export_asks_for_armor(monkeypatch):
    backend = GpgBackend()
    seen = []

    def fake_command(name, args, **kwargs):
        seen.append((name, list(args)))
        if "--list-secret-keys" in args:
            text = _secret_listing(COLONS)
        elif "--export-secret-subkeys" in args:
            text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsubkey\n-----END PGP PRIVATE KEY BLOCK-----\n"
        elif "--export-secret-keys" in args:
            text = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nkey\n-----END PGP PRIVATE KEY BLOCK-----\n"
        elif "--export" in args:
            text = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nkey\n-----END PGP PUBLIC KEY BLOCK-----\n"
        else:
            text = COLONS
        return CommandResult(name, 0, text)

    monkeypatch.setattr(backend, "command", fake_command)
    listed = backend.list_keys()
    assert listed.ok and listed.keys[0].secret_available and listed.keys[0].fingerprint == FPR
    assert listed.keys[0].subkeys[0]["secret"] and listed.keys[0].subkeys[0]["fingerprint"] == SUB_FPR
    assert backend.export_key(FPR, secret=False).ok
    assert backend.export_key(FPR, secret=True).ok
    assert backend.export_key(SUB_FPR, subkey=True).ok
    assert not backend.export_key("zzzz", secret=False).ok
    assert ["--armor", "--export", "--", FPR] in [args for _name, args in seen]
    assert ["--armor", "--export-secret-keys", "--", FPR] in [args for _name, args in seen]
    assert ["--armor", "--export-secret-subkeys", "--", SUB_FPR + "!"] in [args for _name, args in seen]
    assert len(seen) == 5


@pytest.mark.parametrize("status", ["BADSIG", "ERRSIG", "EXPKEYSIG", "EXPSIG", "REVKEYSIG", "FAILURE", "NO_PUBKEY", "NODATA"])
def test_bad_status_refuses_even_a_zero_exit_with_validsig(status):
    result = CommandResult("verify", 0, f"[GNUPG:] VALIDSIG {FPR}\n[GNUPG:] {status}\n")
    assert not signature_ok(result)
    assert not signature_ok(CommandResult("verify", 0))
    assert signature_ok(CommandResult("verify", 0, f"[GNUPG:] VALIDSIG {FPR}\n"))


@pytest.mark.parametrize("name", ["../outside", "/tmp/outside", "sub/../../outside", "-"])
def test_checksums_cannot_read_outside_the_selected_folder(name, tmp_path):
    with pytest.raises(GpgError, match="outside"):
        check_manifest_paths(("0" * 64 + "  " + name + "\n").encode(), tmp_path)


def test_checksum_symlink_escape_is_refused_and_internal_subfolders_are_allowed(tmp_path):
    root = tmp_path / "release"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path)
    with pytest.raises(GpgError):
        check_manifest_paths(("0" * 64 + "  escape/file\n").encode(), root)
    check_manifest_paths(("0" * 64 + " *sub/file\n").encode(), root)
    check_manifest_paths(("\\" + "0" * 64 + "  name\\nwith-newline\n").encode(), root)
    with pytest.raises(GpgError, match="outside"):
        check_manifest_paths(("0" * 64 + " ../outside\n").encode(), root)
    with pytest.raises(GpgError, match="outside"):
        check_manifest_paths(("0" * 64 + "\t*../outside\n").encode(), root)
    with pytest.raises(GpgError, match="unsupported checksum"):
        check_manifest_paths(b"unrecognized format that could name an arbitrary file", root)


def test_inspection_requires_successful_exit_and_a_fingerprint(monkeypatch, tmp_path):
    backend = GpgBackend(tmp_path)
    result = CommandResult("read", 1, COLONS, "bad input")
    monkeypatch.setattr(backend, "command", lambda *args, **kwargs: result)
    assert not backend.inspect_key(b"key", VERIFY_TIME).ok
    result.returncode = 0
    result.stdout = "uid:-::::::::No fingerprint:\n"
    assert not backend.inspect_key(b"key", VERIFY_TIME).ok


def test_import_requires_import_status_not_only_zero_exit(monkeypatch, tmp_path):
    backend = GpgBackend(tmp_path)
    result = CommandResult("import", 0, "", "warning")
    calls = []

    def command(name, args, **kwargs):
        calls.append(args)
        return result

    monkeypatch.setattr(backend, "command", command)
    assert not backend.import_key(b"key", VERIFY_TIME).ok
    result.stdout = "[GNUPG:] IMPORT_RES 0 0 0 0 0\n"
    assert not backend.import_key(b"key", VERIFY_TIME).ok
    result.stdout = "[GNUPG:] IMPORT_RES 1 0 0 0 1\n"
    assert backend.import_key(b"key", VERIFY_TIME).ok  # An unchanged key is fine.
    result.stdout += "[GNUPG:] IMPORT_PROBLEM 1\n"
    assert not backend.import_key(b"key", VERIFY_TIME).ok
    assert calls == [["--status-fd", "1", "--import"]] * 4


def test_delete_runs_secret_then_public_removal(monkeypatch, tmp_path):
    backend = GpgBackend(tmp_path)
    calls = []

    def command(name, args, **kwargs):
        calls.append((name, args, kwargs.get("agent")))
        if name == "Delete Secret Keys":
            return CommandResult(name, 2, "[GNUPG:] DELETE_PROBLEM 1\n", "gpg: key not found")
        return CommandResult(name, 0, "", "")

    monkeypatch.setattr(backend, "command", command)
    assert not backend.delete_key("not-a-fingerprint").ok
    assert calls == []
    deleted = backend.delete_key(FPR)
    assert deleted.ok, deleted
    assert calls == [
        ("Delete Secret Keys", ["--yes", "--status-fd", "1", "--delete-secret-keys", "--", FPR], True),
        ("Delete Keys", ["--yes", "--status-fd", "1", "--delete-keys", "--", FPR], None),
    ]
    calls.clear()

    def refused(name, args, **kwargs):
        calls.append(name)
        return CommandResult(name, 2, "[GNUPG:] FAILURE delete\n", "gpg: delete key failed")

    monkeypatch.setattr(backend, "command", refused)
    failed = backend.delete_key(FPR)
    assert not failed.ok and [stage.name for stage in failed.stages] == ["Delete Secret Keys", "Delete Keys"]
    assert calls == ["Delete Secret Keys", "Delete Keys"]


def test_default_keyring_uses_a_private_ram_directory_separate_from_temporary_files(monkeypatch, tmp_path):
    monkeypatch.setattr(sdcard, "TEMPORARY_ROOT", str(tmp_path / "bigsigner"))
    monkeypatch.setattr(sdcard, "_mounted_filesystems", lambda: [(tmp_path, "tmpfs")])
    backend = GpgBackend()
    assert backend._home() == tmp_path / "bigsigner-gpg"
    assert not (tmp_path / "bigsigner").exists()
    assert backend.home.stat().st_mode & 0o777 == 0o700
    monkeypatch.setattr(sdcard, "_mounted_filesystems", lambda: [(Path("/"), "ext4")])
    with pytest.raises(GpgError, match="RAM filesystem"):
        GpgBackend()._home()


def test_version_line_is_the_first_stdout_line_of_gpg_version():
    if not shutil.which("gpg"):
        pytest.skip("GPG is required")
    env = dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC")
    expected = subprocess.run(["gpg", "--version"], capture_output=True, env=env, check=True).stdout.decode().splitlines()[0]
    backend = GpgBackend()
    assert backend.version_line() == expected
    assert backend.version_line() == expected


def test_version_line_is_empty_when_gpg_cannot_run(monkeypatch):
    monkeypatch.setattr(GpgBackend, "supported", property(lambda self: False))
    assert GpgBackend().version_line() == ""

    def missing(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(GpgBackend, "supported", property(lambda self: True))
    monkeypatch.setattr(subprocess, "run", missing)
    assert GpgBackend().version_line() == ""


def test_prepare_keyring_creates_the_keybox_before_a_listing():
    if not shutil.which("gpg"):
        pytest.skip("GPG is required")
    with tempfile.TemporaryDirectory(prefix="bsgpg-test-") as home:
        backend = GpgBackend(Path(home))
        backend.prepare_keyring()
        assert (backend.home / "pubring.kbx").is_file()
        assert (backend.home / "trustdb.gpg").is_file()
        listed = backend.list_keys()
        assert listed.ok and listed.keys == []
        assert not any("created" in stage.stderr for stage in listed.stages)
        backend.prepare_keyring()


@pytest.fixture
def real_backend(tmp_path, monkeypatch):
    if not shutil.which("gpg") or not shutil.which("sha256sum"):
        pytest.skip("GPG and sha256sum are required for command integration checks")
    root = tmp_path / "files"
    shutil.copytree(VECTORS, root)
    monkeypatch.setattr(sdcard, "native_path", lambda relative, **kwargs: root / relative)
    # GPG's agent socket probe fails on very long pytest paths, even without
    # autostart. The device's /tmp/bigsigner-gpg path is short too.
    with tempfile.TemporaryDirectory(prefix="bsgpg-test-") as home:
        yield GpgBackend(Path(home)), root


def _import(backend):
    content = (VECTORS / "public-key.asc").read_bytes()
    preview = backend.inspect_key(content, VERIFY_TIME)
    assert preview.ok, preview
    result = backend.import_key(content, VERIFY_TIME)
    assert result.ok, result
    return preview.keys[0].fingerprint


def _prepare_verification_failure(root, filename, failure):
    # Keep the signed manifests intact for checksum failures. Changing their
    # contents would fail signature verification before reaching sha256sum.
    for name in ("release.txt", "release.txt.asc", "SHASUMS", "SHASUMS.asc", "CLEAR.asc"):
        shutil.copyfile(VECTORS / name, root / name)
    if failure == "missing-file":
        (root / "release.txt").unlink()
    elif failure == "wrong-hash":
        (root / "release.txt").write_bytes(b"modified release\n")
    elif failure == "invalid-signature":
        # A well-formed signature from the trusted key, but for a different
        # message, must produce BADSIG rather than a malformed-input error.
        other = "SHASUMS.asc" if filename == "release.txt.asc" else "release.txt.asc"
        shutil.copyfile(VECTORS / other, root / filename)
    else:
        raise AssertionError(f"Unknown verification failure: {failure}")


def test_real_public_export_is_armored_and_private_export_is_refused(real_backend):
    backend, _root = real_backend
    fingerprint = _import(backend)
    listed = backend.list_keys(VERIFY_TIME)
    assert listed.ok and listed.keys[0].fingerprint == fingerprint and not listed.keys[0].secret
    assert listed.keys[0].validity == "Unknown"
    ownertrust = subprocess.run(
        ["gpg", "--homedir", str(backend.home), "--export-ownertrust"],
        capture_output=True, env=dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C"),
        stdin=subprocess.DEVNULL,
    )
    assert ownertrust.returncode == 0, ownertrust.stderr.decode()
    assert fingerprint not in ownertrust.stdout.decode()
    public = backend.export_key(fingerprint, secret=False)
    assert public.ok, public
    assert public.stages[0].stdout.lstrip().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" not in public.stages[0].stdout
    private = backend.export_key(fingerprint, secret=True)
    assert not private.ok


def test_real_delete_removes_a_secret_key_with_subkeys_and_a_public_key(real_backend):
    backend, _root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", "Delete <delete@example.invalid>", "ed25519", "cert", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    added = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-add-key", fingerprint, "cv25519", "encrypt", "never"],
        capture_output=True, env=env)
    assert added.returncode == 0, added.stderr.decode()
    listed = backend.list_keys()
    assert listed.ok and listed.keys[0].subkeys and listed.keys[0].secret
    deleted = backend.delete_key(fingerprint)
    assert deleted.ok, deleted
    assert [stage.name for stage in deleted.stages] == ["Delete Secret Keys", "Delete Keys"]
    assert [stage.returncode for stage in deleted.stages] == [0, 0]
    assert backend.list_keys().keys == []
    public = _import(backend)
    removed = backend.delete_key(public)
    assert removed.ok, removed
    assert "DELETE_PROBLEM 1" in removed.stages[0].stdout
    assert removed.stages[1].returncode == 0
    assert backend.list_keys(VERIFY_TIME).keys == []


def test_real_secret_key_exports_an_armored_private_key(real_backend):
    backend, _root = real_backend
    # Key generation starts gpg-agent. The backend's other commands pass
    # --no-autostart, so this one step calls gpg directly in the test keyring.
    script = (
        "%no-protection\n"
        "Key-Type: eddsa\n"
        "Key-Curve: Ed25519\n"
        "Name-Real: BigSigner Export\n"
        "Name-Email: export@example.invalid\n"
        "Expire-Date: 0\n"
        "%commit\n"
    )
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(["gpg", "--batch", "--gen-key"], input=script.encode(), capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    listed = backend.list_keys()
    assert listed.ok and len(listed.keys) == 1 and listed.keys[0].secret
    fingerprint = listed.keys[0].fingerprint
    private = backend.export_key(fingerprint, secret=True)
    public = backend.export_key(fingerprint, secret=False)
    assert private.ok, private
    assert public.ok, public
    assert private.stages[0].stdout.lstrip().startswith("-----BEGIN PGP PRIVATE KEY BLOCK-----")
    assert public.stages[0].stdout.lstrip().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
    assert "-----BEGIN PGP PRIVATE KEY BLOCK-----" not in public.stages[0].stdout


def test_real_subkey_export_leaves_the_certificate_secret_behind(real_backend):
    backend, _root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", "Subkey Export <subkey@example.invalid>", "ed25519", "cert", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    for algo, usage in (("ed25519", "sign"), ("cv25519", "encrypt")):
        added = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-add-key", fingerprint, algo, usage, "never"],
            capture_output=True, env=env)
        assert added.returncode == 0, added.stderr.decode()
    listed = backend.list_keys()
    assert listed.ok and listed.keys[0].secret_available
    signing = next(sub for sub in listed.keys[0].subkeys if "s" in sub["capabilities"] and sub["secret"])
    encryption = next(sub for sub in listed.keys[0].subkeys if "e" in sub["capabilities"] and sub["secret"])
    exported = backend.export_key(signing["fingerprint"], subkey=True)
    assert exported.ok, exported
    with tempfile.TemporaryDirectory(prefix="bsgpg-sub-") as home:
        other = GpgBackend(Path(home))
        imported = other.import_key(exported.stages[0].stdout.encode())
        assert imported.ok, imported
        shown = other.list_keys()
    assert shown.ok and shown.keys[0].secret and not shown.keys[0].secret_available and not shown.keys[0].contains_private
    assert [sub["fingerprint"] for sub in shown.keys[0].subkeys if sub.get("secret")] == [signing["fingerprint"]]
    assert encryption["fingerprint"] not in {sub["fingerprint"] for sub in shown.keys[0].subkeys}


def test_real_key_preview_import_and_listing_use_an_isolated_keyring(real_backend):
    backend, root = real_backend
    assert backend.list_keys(VERIFY_TIME).keys == []
    fingerprint = _import(backend)
    keys = backend.list_keys(VERIFY_TIME)
    assert keys.ok and [key.fingerprint for key in keys.keys] == [fingerprint]
    assert "BigSigner GPG Test: Signer" in keys.keys[0].user_ids[0]
    assert backend.home != Path.home() / ".gnupg"
    assert backend.home.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("filename,checksums,stages", [("release.txt.asc", False, 1), ("SHASUMS.asc", True, 2), ("CLEAR.asc", True, 3)])
def test_real_detached_checksum_and_clear_signed_verification(real_backend, filename, checksums, stages):
    backend, root = real_backend
    _import(backend)
    before = {path.name for path in root.iterdir()}
    result = backend.verify(filename, "sd", VERIFY_TIME, checksums)
    assert result.ok, result
    assert len(result.stages) == stages
    assert "[GNUPG:] VALIDSIG" in result.stages[0].stdout
    assert "not certified with a trusted signature" not in result.stages[0].stderr
    assert result.stages[0].stderr  # Diagnostics survive successful verification.
    if checksums:
        assert "release.txt: OK" in result.stages[-1].stdout
        if filename == "SHASUMS.asc":
            assert result.unverified == ["CLEAR.asc", "public-key.asc", "README.md", "release.txt.asc"]
        else:
            assert result.unverified == ["public-key.asc", "README.md", "release.txt.asc", "SHASUMS", "SHASUMS.asc"]
    else:
        assert result.unverified == []
    assert before == {path.name for path in root.iterdir()}  # No extracted manifest is written.


def test_real_bad_signature_stops_before_checksum_check(real_backend):
    backend, root = real_backend
    _import(backend)
    (root / "SHASUMS").write_text("0" * 64 + "  release.txt\n")
    result = backend.verify("SHASUMS.asc", "sd", VERIFY_TIME, True)
    assert not result.ok and len(result.stages) == 1
    assert result.stages[0].stderr


@pytest.mark.parametrize("filename,stages", [("SHASUMS.asc", 2), ("CLEAR.asc", 3)])
def test_real_good_signature_with_missing_file_reports_failed_checksum(real_backend, filename, stages):
    backend, root = real_backend
    _import(backend)
    _prepare_verification_failure(root, filename, "missing-file")
    result = backend.verify(filename, "sd", VERIFY_TIME, True)
    assert not result.ok and len(result.stages) == stages
    assert all(stage.returncode == 0 for stage in result.stages[:-1])
    assert "[GNUPG:] VALIDSIG" in result.stages[0].stdout
    checked = result.stages[-1]
    assert checked.checksums and checked.returncode != 0
    assert "release.txt: FAILED" in checked.stdout
    assert "release.txt" in checked.stderr and "No such file or directory" in checked.stderr
    assert not (root / "release.txt").exists()
    assert not (root / "CLEAR").exists()


@pytest.mark.parametrize("filename,stages", [("SHASUMS.asc", 2), ("CLEAR.asc", 3)])
def test_real_good_signature_with_bad_file_reports_failed_checksum(real_backend, filename, stages):
    backend, root = real_backend
    _import(backend)
    _prepare_verification_failure(root, filename, "wrong-hash")
    result = backend.verify(filename, "sd", VERIFY_TIME, True)
    assert not result.ok and len(result.stages) == stages
    assert all(stage.returncode == 0 for stage in result.stages[:-1])
    assert "[GNUPG:] VALIDSIG" in result.stages[0].stdout
    checked = result.stages[-1]
    assert checked.checksums and checked.returncode != 0
    assert "release.txt: FAILED" in checked.stdout
    assert "checksum did NOT match" in checked.stderr
    assert "No such file or directory" not in checked.stderr
    assert not (root / "CLEAR").exists()


@pytest.mark.parametrize("filename,checksums", [("release.txt.asc", False), ("SHASUMS.asc", True)])
def test_real_invalid_signature_is_rejected_before_any_checksum_check(real_backend, filename, checksums):
    backend, root = real_backend
    _import(backend)
    _prepare_verification_failure(root, filename, "invalid-signature")
    result = backend.verify(filename, "sd", VERIFY_TIME, checksums)
    assert not result.ok and len(result.stages) == 1
    verified = result.stages[0]
    assert verified.returncode != 0
    assert "[GNUPG:] BADSIG" in verified.stdout
    assert "[GNUPG:] VALIDSIG" not in verified.stdout
    assert "BAD signature" in verified.stderr
    assert not any(stage.checksums for stage in result.stages)


def test_real_expired_key_is_refused_at_the_selected_time(real_backend):
    backend, _root = real_backend
    _import(backend)
    result = backend.verify("release.txt.asc", "sd", 1798761600)
    assert not result.ok
    assert "EXPKEYSIG" in result.stages[0].stdout


def test_quick_add_arguments_name_the_algorithm_usage_and_expiration():
    assert quick_add_arguments(FPR, "ed25519", "sign", "never") == [FPR, "ed25519", "sign", "never"]
    assert quick_add_arguments(FPR, "ed25519", "sign", "20270615T050000") == [FPR, "ed25519", "sign", "20270615T050000"]
    with pytest.raises(GpgError):
        quick_add_arguments(FPR, "ed25519", "sign", "365")


def test_camera_digest_is_mixed_without_claiming_256_bits(monkeypatch):
    seen = {}

    def opener(path, _flags):
        seen["path"] = path
        return 7

    def ioctl(_fd, request, argument):
        seen["request"] = request
        seen["argument"] = bytes(argument)

    monkeypatch.setattr(os, "open", opener)
    monkeypatch.setattr(os, "close", lambda _fd: None)
    monkeypatch.setattr("bigsigner.gpg.fcntl.ioctl", ioctl)
    mix_kernel_entropy(b"\xab" * 32)
    assert seen["path"] == "/dev/random"
    assert seen["request"] == (1 << 30) | (8 << 16) | (ord("R") << 8) | 3
    assert seen["argument"] == struct.pack("ii32s", 0, 32, b"\xab" * 32)
    mix_kernel_entropy(b"\xcd" * 64)
    assert seen["argument"] == struct.pack("ii64s", 0, 64, b"\xcd" * 64)


def test_keyinfo_passphrase_flag_is_only_p():
    assert passphrase_required("S KEYINFO " + "A" * 40 + " D - - - P - - -")
    assert not passphrase_required("S KEYINFO " + "A" * 40 + " D - - - C - - -")
    assert not passphrase_required("S KEYINFO " + "A" * 40 + " D - - - - - - -")


def test_sha256_manifest_lists_only_the_files_in_that_folder(tmp_path):
    folder = tmp_path / "packet"
    nested = folder / "extra"
    nested.mkdir(parents=True)
    (folder / "readme.txt").write_bytes(b"hello\n")
    (nested / "skip.txt").write_bytes(b"no\n")
    (folder / CHECKSUM_NAME).write_bytes(b"old\n")
    manifest = sha256_manifest(folder)
    text = manifest.decode()
    assert "readme.txt" in text
    assert "skip.txt" not in text
    assert CHECKSUM_NAME not in text.split("*", 1)[-1]
    check_manifest_paths(manifest, folder)
    assert signature_is_deterministic("RSA (3072 bits)")
    assert signature_is_deterministic("EdDSA (255 bits)")
    assert not signature_is_deterministic("ECDSA (256 bits)")
    assert not signature_is_deterministic("DSA (2048 bits)")


def test_real_list_marks_a_passphrase_and_leaves_an_empty_one_clear(real_backend):
    backend, _root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    for passphrase, name in (("", "Empty <empty@example.invalid>"), ("correct horse", "Locked <locked@example.invalid>")):
        generated = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", passphrase,
             "--quick-gen-key", name, "ed25519", "sign", "never"],
            capture_output=True, env=env)
        assert generated.returncode == 0, generated.stderr.decode()
    listed = backend.list_keys()
    assert listed.ok, listed
    by_name = {key.user_ids[0]: key for key in listed.keys}
    assert by_name["Empty <empty@example.invalid>"].needs_passphrase is False
    assert by_name["Locked <locked@example.invalid>"].needs_passphrase is True


def test_real_detached_signature_uses_the_named_key_and_typed_time(real_backend):
    backend, root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--faked-system-time", str(calendar.timegm((2019, 6, 1, 0, 0, 0))),
         "--quick-gen-key", "Signer <signer@example.invalid>", "ed25519", "sign", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    folder = root / "packet"
    (folder / "extra").mkdir(parents=True)
    (folder / "readme.txt").write_bytes(b"hello\n")
    (folder / "extra" / "skip.txt").write_bytes(b"no\n")
    stamp = calendar.timegm((2020, 1, 2, 3, 4, 0))
    signed = backend.sign_folder(fingerprint, "packet", "sd", stamp)
    assert signed.ok, signed
    manifest = (folder / "SHA256SUMS").read_text()
    assert "readme.txt" in manifest and "skip.txt" not in manifest
    verified = subprocess.run(
        ["gpg", "--batch", "--status-fd", "1", "--verify", "--", "SHA256SUMS.asc", "SHA256SUMS"],
        capture_output=True, cwd=folder, env=env)
    assert verified.returncode == 0, verified.stderr.decode()
    assert fingerprint in verified.stdout.decode()
    assert str(stamp) in verified.stdout.decode()
    (root / "readme.txt").write_bytes(b"one file\n")
    one = backend.sign_file(fingerprint, "readme.txt", "sd", stamp)
    assert one.ok, one
    assert (root / "readme.txt.asc").is_file()


def test_real_quick_add_key_stamps_the_typed_time(real_backend, monkeypatch):
    backend, _root = real_backend
    monkeypatch.setattr("bigsigner.gpg.mix_kernel_entropy", lambda _digest: None)
    backend.mix_entropy(b"\x11" * 32)
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--faked-system-time", str(calendar.timegm((2019, 6, 1, 0, 0, 0))),
         "--quick-gen-key", "Add Subkey <add@example.invalid>", "ed25519", "cert", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    stamp = calendar.timegm((2020, 1, 2, 3, 4, 0))
    added = backend.add_subkey(fingerprint, "ed25519", "auth", "20210304T050000", stamp)
    assert added.ok, added
    listed = next(key for key in added.keys if key.fingerprint == fingerprint)
    assert listed.validity == "Ultimate"
    created = next(sub for sub in listed.subkeys if "a" in sub["capabilities"].lower())
    from datetime import datetime, timezone
    moment = datetime.fromtimestamp(stamp, timezone.utc)
    assert created["created"] == moment.strftime("%Y-%m-%d %H:%M UTC")
    assert created["expires"] == "2021-03-04 05:00 UTC"


def test_encrypt_file_rejects_a_fingerprint_that_is_not_hex(tmp_path, monkeypatch):
    root = tmp_path / "sd"
    root.mkdir()
    (root / "note.txt").write_bytes(b"hi")
    monkeypatch.setattr(sdcard, "native_path", lambda relative, **kwargs: root / relative)
    with pytest.raises(GpgError, match="fingerprint"):
        GpgBackend(tmp_path / "gpg").encrypt_file(["not-a-key"], "note.txt", "note.txt.enc.asc", "sd")


def test_real_encrypt_file_uses_the_exact_subkey(real_backend):
    backend, root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", "Encrypt <enc@example.invalid>", "ed25519", "cert", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    for _repeat in range(2):
        added = subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-add-key", fingerprint, "cv25519", "encrypt", "never"],
            capture_output=True, env=env)
        assert added.returncode == 0, added.stderr.decode()
    listed = backend.list_keys()
    assert listed.ok, listed
    subkeys = [sub["fingerprint"] for sub in listed.keys[0].subkeys if "e" in sub["capabilities"].lower()]
    assert len(subkeys) == 2
    chosen, other = subkeys
    (root / "note.txt").write_bytes(b"hello airgap\n")
    encrypted = backend.encrypt_file([chosen], "note.txt", "note.txt.enc.asc", "sd")
    assert encrypted.ok, encrypted
    armor = (root / "note.txt.enc.asc").read_text()
    assert armor.lstrip().startswith("-----BEGIN PGP MESSAGE-----")
    packets = subprocess.run(["gpg", "--list-packets", str(root / "note.txt.enc.asc")], capture_output=True, env=env)
    shown = packets.stdout.decode().lower() + packets.stderr.decode().lower()
    assert chosen[-16:].lower() in shown
    assert other[-16:].lower() not in shown
    decrypted = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--decrypt", str(root / "note.txt.enc.asc")],
        capture_output=True, env=env)
    assert decrypted.returncode == 0, decrypted.stderr.decode()
    assert decrypted.stdout == b"hello airgap\n"


def test_real_symmetric_encryption_uses_aes256(real_backend):
    backend, root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    (root / "note.txt").write_bytes(b"hello airgap\n")
    encrypted = backend.encrypt_symmetric("note.txt", "note.txt.enc.asc", "sd", "secret")
    assert encrypted.ok, encrypted
    assert 'The encrypted file "note.txt.enc.asc" was written.' in encrypted.stages[0].stdout
    assert not (backend.home / "aes-passphrase").exists()
    packets = subprocess.run(["gpg", "--list-packets", str(root / "note.txt.enc.asc")], capture_output=True, env=env)
    shown = packets.stdout.decode() + packets.stderr.decode()
    assert "AES256" in shown
    decrypted = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "secret", "--decrypt", str(root / "note.txt.enc.asc")],
        capture_output=True, env=env)
    assert decrypted.returncode == 0, decrypted.stderr.decode()
    assert decrypted.stdout == b"hello airgap\n"


def test_encryption_kind_reads_the_leading_session_key_packet():
    symmetric = bytes([0xC3, 4, 4, 0, 0, 0])
    keyed = bytes([0xC1, 4, 3, 0, 0, 0])
    armor = b"-----BEGIN PGP MESSAGE-----\n\n" + __import__("base64").b64encode(symmetric) + b"\n-----END PGP MESSAGE-----\n"
    assert pgp_encryption_kind(symmetric) == "symmetric"
    assert pgp_encryption_kind(armor) == "symmetric"
    assert pgp_encryption_kind(keyed) == "key"
    assert decrypted_filename("note.txt.enc.asc") == "note.txt"
    assert decrypted_filename("note.txt.gpg") == "note.txt"
    assert decrypted_filename("photo.bin") == "photo.bin.dec"
    with pytest.raises(GpgError, match="not an encrypted message"):
        pgp_encryption_kind(b"hello")


def test_real_decrypt_uses_a_password_only_for_symmetric_messages(real_backend):
    backend, root = real_backend
    env = dict(os.environ, GNUPGHOME=str(backend.home), LC_ALL="C", LANG="C", TZ="UTC")
    (root / "note.txt").write_bytes(b"hello airgap\n")
    encrypted = backend.encrypt_symmetric("note.txt", "note.txt.enc.asc", "sd", "secret")
    assert encrypted.ok, encrypted
    assert backend.encryption_kind("note.txt.enc.asc", "sd") == "symmetric"
    (root / "note.txt").unlink()
    opened = backend.decrypt_file("note.txt.enc.asc", "note.txt", "sd", "secret")
    assert opened.ok, opened
    assert 'The decrypted file "note.txt" was written.' in opened.stages[0].stdout
    assert (root / "note.txt").read_bytes() == b"hello airgap\n"
    assert not (backend.home / "aes-passphrase").exists()

    generated = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-gen-key", "Decrypt <dec@example.invalid>", "ed25519", "cert", "never"],
        capture_output=True, env=env)
    assert generated.returncode == 0, generated.stderr.decode()
    fingerprint = backend.list_keys().keys[0].fingerprint
    added = subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
         "--quick-add-key", fingerprint, "cv25519", "encrypt", "never"],
        capture_output=True, env=env)
    assert added.returncode == 0, added.stderr.decode()
    recipient = next(sub["fingerprint"] for sub in backend.list_keys().keys[0].subkeys if "e" in sub["capabilities"].lower())
    (root / "secret.txt").write_bytes(b"keyed\n")
    locked = backend.encrypt_file([recipient], "secret.txt", "secret.txt.enc.asc", "sd")
    assert locked.ok, locked
    assert backend.encryption_kind("secret.txt.enc.asc", "sd") == "key"
    (root / "secret.txt").unlink()
    opened = backend.decrypt_file("secret.txt.enc.asc", "secret.txt", "sd", None)
    assert opened.ok, opened
    assert (root / "secret.txt").read_bytes() == b"keyed\n"

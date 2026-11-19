"""OpenPGP.js in the emulator, checked against GnuPG on this machine."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from bigsigner.gpg import GpgBackend
from bigsigner.openpgp_subkey import secret_subkey_armor

ROOT = Path(__file__).resolve().parents[1]
LIBRARY = ROOT / "web" / "external-assets" / "openpgp" / "openpgp.min.mjs"
SCRIPT = Path(__file__).with_name("openpgp_roundtrip.mjs")


def _gpg(home: Path, args, input_bytes=None):
    env = dict(os.environ, GNUPGHOME=str(home), LC_ALL="C", LANG="C", TZ="UTC")
    return subprocess.run(
        ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", *args],
        input=input_bytes, capture_output=True, env=env,
        stdin=None if input_bytes is not None else subprocess.DEVNULL,
    )


def test_secret_subkey_armor_removes_the_primary_secret():
    if not shutil.which("gpg"):
        pytest.skip("gpg is not installed")
    with tempfile.TemporaryDirectory(prefix="bsgpg-patch-") as source_home, tempfile.TemporaryDirectory(prefix="bsgpg-stub-") as other_home:
        source = Path(source_home)
        generated = _gpg(source, ["--quick-gen-key", "Patch <patch@example.invalid>", "ed25519", "cert", "never"])
        assert generated.returncode == 0, generated.stderr.decode()
        backend = GpgBackend(source)
        primary = backend.list_keys().keys[0].fingerprint
        for algo, usage in (("ed25519", "sign"), ("cv25519", "encrypt")):
            added = _gpg(source, ["--quick-add-key", primary, algo, usage, "never"])
            assert added.returncode == 0, added.stderr.decode()
        listed = backend.list_keys()
        signing = next(sub["fingerprint"] for sub in listed.keys[0].subkeys if "s" in sub["capabilities"])
        encryption = next(sub["fingerprint"] for sub in listed.keys[0].subkeys if "e" in sub["capabilities"])
        full = _gpg(source, ["--armor", "--export-secret-keys", primary])
        assert full.returncode == 0, full.stderr.decode()
        patched = secret_subkey_armor(full.stdout.decode(), primary, signing)
        other = GpgBackend(Path(other_home))
        imported = other.import_key(patched.encode())
        assert imported.ok, imported
        shown = other.list_keys()
        assert shown.keys[0].secret and not shown.keys[0].secret_available and not shown.keys[0].contains_private
        assert [sub["fingerprint"] for sub in shown.keys[0].subkeys if sub.get("secret")] == [signing]
        assert encryption not in {sub["fingerprint"] for sub in shown.keys[0].subkeys}
        note = source / "note.bin"
        note.write_bytes(b"hello airgap\n")
        signed = _gpg(Path(other_home), ["--local-user", f"{signing}!", "--armor", "--detach-sign", "--output", str(source / "sub.asc"), str(note)])
        assert signed.returncode == 0, signed.stderr.decode()
        refused = _gpg(Path(other_home), ["--local-user", f"{primary}!", "--armor", "--detach-sign", "--output", str(source / "primary.asc"), str(note)])
        assert refused.returncode != 0


def test_openpgpjs_roundtrip_matches_gnupg():
    if not shutil.which("gpg") or not shutil.which("node"):
        pytest.skip("gpg and node are required")
    if not LIBRARY.is_file():
        pytest.skip("OpenPGP.js is not downloaded")
    from embit.bip32 import HDKey
    from embit.bip39 import mnemonic_to_seed

    from bigsigner.bip85gpg import secret_armor

    abandon = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    work = Path(tempfile.mkdtemp(prefix="bsopenpgp-"))
    try:
        (work / "bip85.asc").write_text(secret_armor(
            HDKey.from_seed(mnemonic_to_seed(abandon)), 3072, 0,
            "Ada Lovelace", "ada@example.invalid", signing=False,
        ))
        ran = subprocess.run(["node", str(SCRIPT), str(work)], capture_output=True, text=True)
        assert ran.returncode == 0, ran.stderr or ran.stdout
        meta = json.loads((work / "meta.json").read_text())
        patched = secret_subkey_armor((work / "private-full.asc").read_text(), meta["primary"], meta["signing"])
        with tempfile.TemporaryDirectory(prefix="bsgpg-js-") as home:
            other = GpgBackend(Path(home))
            imported = other.import_key(patched.encode())
            assert imported.ok, imported
            shown = other.list_keys()
            assert shown.keys[0].secret and not shown.keys[0].secret_available and not shown.keys[0].contains_private
            assert [sub["fingerprint"] for sub in shown.keys[0].subkeys if sub.get("secret")] == [meta["signing"]]
            assert meta["encryption"] not in {sub["fingerprint"] for sub in shown.keys[0].subkeys}
        with tempfile.TemporaryDirectory(prefix="bsgpg-bip-") as home:
            loaded = _gpg(Path(home), ["--import", str(work / "bip85.asc")])
            assert loaded.returncode == 0, loaded.stderr.decode()
            listed = _gpg(Path(home), ["--with-colons", "--with-fingerprint", "--list-keys"])
            assert listed.returncode == 0, listed.stderr.decode()
            fingerprint = next(line.split(":")[9] for line in listed.stdout.decode().splitlines() if line.startswith("fpr:"))
        assert meta["bip85"]["fingerprint"] == fingerprint
        assert "c" in meta["bip85"]["capabilities"]
    finally:
        shutil.rmtree(work, ignore_errors=True)

"""BIP-85 RSA primary keys stay fixed when the certificate signature changes."""

from pathlib import Path
import shutil
import tempfile

import pytest
from embit.bip32 import HDKey
from embit.bip39 import mnemonic_to_seed

from bigsigner.bip85gpg import armor, derive_rsa, drng_bytes, entropy_for, entropy_path, raw_entropy, secret_packets
from bigsigner.gpg import GpgBackend

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
# Published BIP85-DRNG-SHAKE256 sample for the m/83696968'/0'/0' entropy.
_DRNG_ENTROPY = bytes.fromhex(
    "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f0"
    "0b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"
)
_DRNG_80 = (
    "b78b1ee6b345eae6836c2d53d33c64cdaf9a696487be81b03e822dc84b3f1cd8"
    "83d7559e53d175f243e4c349e822a957bbff9224bc5dde9492ef54e8a439f6bc"
    "8c7355b87a925a37ee405a7502991111"
)
# Abandon, 512 bits, index 0. The product offers 3072 and 4096; this locks the same prime walk.
_ABANDON_512 = int(
    "84a49b3ae4d147c205afe5a4520f92ec9cb57460b66dbc4baa5a5e8604eeb427"
    "6c60ff8dd363cc343935e5c58b4b9708949ec59c733251125509f5246d5988f1",
    16,
)


def _abandon():
    return HDKey.from_seed(mnemonic_to_seed(ABANDON))


def test_the_drng_matches_the_bip85_vector():
    assert drng_bytes(_DRNG_ENTROPY, 80).hex() == _DRNG_80


def test_raw_entropy_is_64_bytes_from_the_bip85_entropy_application():
    root = _abandon()
    assert entropy_path(7) == "m/83696968h/128169h/64h/7h"
    first = raw_entropy(root, 0)
    assert first == raw_entropy(root, 0)
    assert len(first) == 64
    assert first.hex() == (
        "379f3ff670bf391ca62e6fbd62359a753e89c46bcb02751066ee5897c292487a"
        "ccbfb091d2b59002086eb13d0f9d6746e7ab74d4a60a5f4998cfba3d3687f89a"
    )
    assert raw_entropy(root, 1) != first
    with pytest.raises(ValueError):
        raw_entropy(root, 0x80000000)


def test_the_abandon_seed_recreates_one_rsa_modulus():
    root = _abandon()
    assert entropy_for(root, 512, 0).hex().startswith("727c09e9f060aa68")
    first = derive_rsa(root, 512, 0)
    second = derive_rsa(root, 512, 0)
    assert first.n == second.n == _ABANDON_512
    assert first.d == second.d
    assert derive_rsa(root, 512, 1).n != first.n


def test_name_email_and_expiration_do_not_change_the_private_key():
    key = derive_rsa(_abandon(), 512, 0)
    certificate = secret_packets(key, "Ada Lovelace", "ada@example.invalid", signing=False, expires_on=None)
    signed = secret_packets(
        key, "Grace Hopper", "grace@example.invalid", signing=True, expires_on=(2030, 1, 2),
    )
    assert certificate != signed
    modulus = key.n.to_bytes((key.n.bit_length() + 7) // 8, "big")
    secret = key.d.to_bytes((key.d.bit_length() + 7) // 8, "big")
    assert modulus in certificate and modulus in signed
    assert secret in certificate and secret in signed
    assert b"Ada Lovelace <ada@example.invalid>" in certificate
    assert b"Grace Hopper <grace@example.invalid>" in signed
    with pytest.raises(ValueError, match="before this key was created"):
        secret_packets(key, "Ada", "ada@example.invalid", signing=False, expires_on=(2009, 1, 3))


def test_gpg_imports_the_same_fingerprint_for_either_signature():
    if not shutil.which("gpg"):
        pytest.skip("GPG is required")
    key = derive_rsa(_abandon(), 512, 0)
    certificate = armor(secret_packets(key, "Ada Lovelace", "ada@example.invalid", signing=False, expires_on=None))
    signed = armor(secret_packets(
        key, "Grace Hopper", "grace@example.invalid", signing=True, expires_on=(2030, 1, 2),
    ))
    with tempfile.TemporaryDirectory(prefix="bsgpg-bip85-") as home:
        backend = GpgBackend(Path(home))
        imported = backend.import_key(certificate.encode())
        assert imported.ok, imported
        listed = backend.list_keys()
        assert listed.ok, listed
        cert = listed.keys[0]
    with tempfile.TemporaryDirectory(prefix="bsgpg-bip85-") as home:
        backend = GpgBackend(Path(home))
        imported = backend.import_key(signed.encode())
        assert imported.ok, imported
        listed = backend.list_keys()
        both = listed.keys[0]
    assert cert.fingerprint == both.fingerprint
    assert cert.secret_available and both.secret_available
    assert "s" not in cert.capabilities.lower()
    assert "c" in cert.capabilities.lower()
    assert "s" in both.capabilities.lower()
    assert "ada@example.invalid" in cert.user_ids[0]
    assert "grace@example.invalid" in both.user_ids[0]
    assert both.expires.startswith("2030-01-02")
    assert cert.expires == "Never"

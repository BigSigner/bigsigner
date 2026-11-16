"""Compare a hardware-wallet QR with the extended key being loaded."""

from bigsigner.parse import parse_key_expression, verify_key_qr
from bigsigner.paths import format_path
from bigsigner.slip132 import display_form, to_canonical
from test_domain import ABANDON, LEGAL, expression, root_of


def _key(path="m/84h/0h/0h", network="main", words=ABANDON):
    text = expression(words, path)
    if network != "main":
        body, suffix = text.split("]", 1)
        extended, suffix = suffix.split("/", 1)
        text = f"{body}]{to_canonical(extended, network)}/{suffix}"
    return parse_key_expression(text, network)


def _qr(key, extended=None, fingerprint=None, path=None):
    fingerprint = key.fingerprint.hex() if fingerprint is None else fingerprint
    path = format_path(list(key.path))[2:] if path is None else path
    extended = key.canonical if extended is None else extended
    return f"[{fingerprint}/{path}]{extended}"


def test_a_matching_key_expression_succeeds():
    key = _key()
    verdict = verify_key_qr(_qr(key), key, "main")
    assert verdict.status == "success"
    assert verdict.message == "The key expression matches."
    assert verdict.scanned == ""
    assert verdict.expected == ""


def test_apostrophe_paths_and_fingerprint_case_still_match():
    key = _key()
    text = _qr(key, fingerprint=key.fingerprint.hex().upper(), path="84'/0'/0'")
    assert verify_key_qr(f"  {text}\n", key, "main").status == "success"
    assert verify_key_qr(_qr(key, path="84H/0H/0H"), key, "main").status == "success"


def test_a_slip132_spelling_of_the_same_key_matches():
    single = _key()
    zpub = display_form(single.canonical, "main", single.role)
    assert verify_key_qr(_qr(single, extended=zpub), single, "main").status == "success"
    multi = _key("m/48h/0h/0h/2h")
    Zpub = display_form(multi.canonical, "main", multi.role)
    assert Zpub.startswith("Zpub")
    assert verify_key_qr(_qr(multi, extended=Zpub), multi, "main").status == "success"
    test = _key("m/84h/1h/0h", network="test")
    vpub = display_form(test.canonical, "test", test.role)
    assert verify_key_qr(_qr(test, extended=vpub), test, "test").status == "success"


def test_a_missing_fingerprint_is_a_warning():
    key = _key()
    verdict = verify_key_qr(_qr(key, fingerprint="m"), key, "main")
    assert verdict.status == "warning"
    assert "happens on some hardware wallets" in verdict.message
    assert verify_key_qr(_qr(key, fingerprint="M", path="m/84h/0h/0h"), key, "main").status == "warning"


def test_a_bare_extended_key_reports_the_missing_path_only_when_the_key_matches():
    key = _key()
    missing = verify_key_qr(f"\n{key.canonical} ", key, "main")
    assert missing.status == "error"
    assert missing.message == (
        "The extended public key is correct, but the derivation path is missing and must be verified."
    )
    other = _key(words=LEGAL).canonical
    mismatch = verify_key_qr(other, key, "main")
    assert mismatch.status == "error"
    assert mismatch.message == "The extended public key does not match."
    assert mismatch.scanned == other
    assert mismatch.expected == key.canonical


def test_a_different_extended_key_is_reported_before_the_path():
    key = _key()
    other = _key(words=LEGAL)
    zpub = display_form(other.canonical, "main", other.role)
    verdict = verify_key_qr(_qr(key, extended=zpub, path="84h/0h/9h"), key, "main")
    assert verdict.status == "error"
    assert verdict.message == "The extended public key does not match."
    assert verdict.scanned == zpub
    assert verdict.expected == display_form(key.canonical, "main", key.role)


def test_a_different_path_shows_both_paths():
    key = _key()
    verdict = verify_key_qr(_qr(key, path="84'/0'/1'", fingerprint="ffffffff"), key, "main")
    assert verdict.status == "error"
    assert verdict.message == "The derivation path does not match."
    assert verdict.scanned == "84'/0'/1'"
    assert verdict.expected == "m/84h/0h/0h"
    broken = verify_key_qr(_qr(key, path="nope"), key, "main")
    assert broken.scanned == "nope"
    assert broken.expected == "m/84h/0h/0h"


def test_a_different_fingerprint_shows_both_values():
    key = _key()
    verdict = verify_key_qr(_qr(key, fingerprint="00112233"), key, "main")
    assert verdict.status == "error"
    assert verdict.message == "The fingerprint does not match."
    assert verdict.scanned == "00112233"
    assert verdict.expected == key.fingerprint.hex()


def test_an_unrecognized_code_does_not_match_a_format():
    key = _key()
    for text in (
        "",
        "hello",
        _qr(key) + "/<0;1>/*",
        f"wpkh({_qr(key)}/<0;1>/*)",
        f"[{key.fingerprint.hex()}]{key.canonical}",
        f"[abcd/84h/0h/0h]{key.canonical}",
    ):
        verdict = verify_key_qr(text, key, "main")
        assert verdict.status == "error"
        assert verdict.message == "The format could not be detected."
        assert verdict.scanned == ""

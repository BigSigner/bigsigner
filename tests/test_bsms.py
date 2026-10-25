from pathlib import Path

import pytest

from bigsigner.bsms import descriptor_from_bsms
from bigsigner.parse import ParseError
from bigsigner.ui.app import App
from test_domain import expression
from test_sdcard import _tap

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SAMPLE = Path("emulator-sdcard/My SeedSigner Trezor Wallet.bsms")


def _lines():
    return SAMPLE.read_text(encoding="utf-8").splitlines()


def _finish_wallet_wizard(app):
    for _ in range(16):
        if app.screen == "external-review":
            _tap(app, "external-next")
        elif app.screen == "external-details":
            _tap(app, "external-continue")
        elif app.screen == "wallet-import-note":
            _tap(app, "wallet-import-continue")
        else:
            return
    raise AssertionError(app.screen)


def test_the_seedsigner_bsms_file_loads_a_multisig_wallet(monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", "emulator-sdcard")
    app = App()
    app.screen = "wallets"
    _tap(app, "plus")
    _tap(app, "Load descriptor from SD card")
    _tap(app, "My SeedSigner Trezor Wallet.bsms")
    _finish_wallet_wizard(app)
    assert app.screen == "wallet"
    assert len(app.session.wallets) == 1
    wallet = app.session.wallets[0]
    assert wallet.multisig
    assert wallet.threshold == 2
    assert len(wallet.fingerprints) == 2
    assert "multisig" in app.notice.lower()


def test_a_bsms_multisig_on_the_keys_page_offers_the_wallet_or_one_key(monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", "emulator-sdcard")
    app = App()
    app.screen = "keys"
    _tap(app, "plus")
    _tap(app, "Load from SD card")
    _tap(app, "My SeedSigner Trezor Wallet.bsms")
    assert app.screen == "descriptor-choice"
    assert app.notice == ""
    assert app.session.wallets == []
    assert "Bitcoin Wallets" not in app._descriptor_choice_message()
    assert app.descriptor_choice["labels"] == [
        "f992cf24 xpub6EUL99...",
        "7e930c45 xpub6FAoRw...",
    ]
    _tap(app, "dropdown-descriptor-key")
    _tap(app, "dropdown-pick-descriptor-key-0")
    _tap(app, "Load Selected Key")
    assert app.screen == "external-review"
    assert app.wallet_plan is None
    assert app.pending_external.fingerprint.hex() == "f992cf24"
    assert app.session.wallets == []

    both = App()
    both.screen = "keys"
    _tap(both, "plus")
    _tap(both, "Load from SD card")
    _tap(both, "My SeedSigner Trezor Wallet.bsms")
    _tap(both, "Both Wallet And All Keys")
    _finish_wallet_wizard(both)
    assert both.screen == "wallet"
    assert both.session.wallets[0].multisig
    assert len(both.session.wallets[0].fingerprints) == 2


def test_a_changed_first_address_is_refused():
    lines = _lines()
    lines[3] = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    with pytest.raises(ParseError, match="first address"):
        descriptor_from_bsms("\n".join(lines), "main")


def test_a_receive_only_path_line_does_not_match_both_branches():
    lines = _lines()
    lines[2] = "/0/*"
    with pytest.raises(ParseError, match="derivation paths"):
        descriptor_from_bsms("\n".join(lines), "main")


def test_another_bsms_version_is_refused():
    lines = _lines()
    lines[0] = "BSMS 2.0"
    with pytest.raises(ParseError, match="version"):
        descriptor_from_bsms("\n".join(lines), "main")


def test_an_unsupported_script_is_refused():
    text = "\n".join(
        [
            "BSMS 1.0",
            "sh(wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*))",
            "/0/*,/1/*",
            "bc1qjrty0sv9587x4v3rl07vj560q8azt5ftww9cna2a8wf23m3ep7gq3k9pqc",
        ]
    )
    with pytest.raises(ParseError, match="does not support"):
        descriptor_from_bsms(text, "main")


def test_a_singlesig_bsms_file_is_a_descriptor(tmp_path, monkeypatch):
    from embit.descriptor import Descriptor
    from embit.networks import NETWORKS

    descriptor = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    address = Descriptor.from_string(descriptor).derive(0, branch_index=0).address(network=NETWORKS["main"])
    text = "\n".join(["BSMS 1.0", descriptor, "/0/*,/1/*", address])
    assert descriptor_from_bsms(text, "main") == descriptor
    (tmp_path / "single.bsms").write_text(text + "\n", encoding="utf-8")
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    app = App()
    app.screen = "wallets"
    _tap(app, "plus")
    _tap(app, "Load descriptor from SD card")
    _tap(app, "single.bsms")
    _finish_wallet_wizard(app)
    assert app.screen == "wallet"
    assert len(app.session.wallets) == 1
    assert not app.session.wallets[0].multisig

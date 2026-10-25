"""Wallet descriptor import, including descriptors that list the same keys differently."""

from pathlib import Path

from embit.descriptor.checksum import checksum

from bigsigner.session import Session
from bigsigner.slip132 import display_form
from bigsigner.ui.app import App
from test_domain import ABANDON, LEGAL, expression, root_of
from test_ui import ScreenRecord


def _wrapped(body: str) -> str:
    return f"{body}#{checksum(body)}"


def _multisig(*keys, threshold=2) -> str:
    return _wrapped(f"wsh(sortedmulti({threshold},{','.join(keys)}))")


def _single(key: str, kind="wpkh") -> str:
    return _wrapped(f"{kind}({key})")


def test_reordered_multisig_descriptors_are_the_same_wallet():
    session = Session()
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/7h/2h")
    original = _multisig(first, second)
    session.add_text(original)
    swapped = _multisig(second, first)
    assert swapped != original
    left = session.plan_wallet_import(original)
    right = session.plan_wallet_import(swapped)
    assert left["existing"] is session.wallets[0]
    assert right["existing"] is session.wallets[0]
    assert left["new_keys"] == []
    assert right["new_keys"] == []
    assert session.wallet_identity_text(
        left["parsed"].role, left["parsed"].threshold, [key.fingerprint for key in left["parsed"].keys]
    ) == session.wallet_identity_text(
        right["parsed"].role, right["parsed"].threshold, [key.fingerprint for key in right["parsed"].keys]
    )


def test_account_order_apostrophe_and_zpub_do_not_make_a_second_wallet():
    session = Session()
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    session.add_text(_multisig(first, second))
    other_account = expression(LEGAL, "m/48h/0h/4h/2h")
    path, bracket, rest = other_account.partition("]")
    other_account = path.replace("h", "'") + bracket + rest
    zpub_key = expression(ABANDON, "m/48h/0h/9h/2h")
    canonical = zpub_key.split("]")[1].split("/")[0]
    zpub = display_form(canonical, "main", "multisig_native")
    zpub_key = zpub_key.replace(canonical, zpub)
    plan = session.plan_wallet_import(_multisig(other_account, zpub_key))
    assert plan["existing"] is session.wallets[0]
    assert len(plan["new_keys"]) == 2
    assert [key.account for key in plan["new_keys"]] == [4, 9]
    session.apply_wallet_plan(plan)
    assert len(session.wallets) == 1
    wallet = session.wallets[0]
    assert wallet.accounts[root_of(ABANDON).my_fingerprint] == 9
    assert wallet.accounts[root_of(LEGAL).my_fingerprint] == 4


def test_a_different_threshold_or_member_is_a_different_wallet():
    from embit.bip39 import mnemonic_from_bytes

    session = Session()
    third = mnemonic_from_bytes(bytes([3]) + b"\x3c" * 15)
    keys = [
        expression(ABANDON, "m/48h/0h/0h/2h"),
        expression(LEGAL, "m/48h/0h/0h/2h"),
        expression(third, "m/48h/0h/0h/2h"),
    ]
    session.add_text(_multisig(keys[0], keys[1], keys[2], threshold=2))
    three = session.plan_wallet_import(_multisig(keys[2], keys[0], keys[1], threshold=3))
    pair = session.plan_wallet_import(_multisig(keys[1], keys[0], threshold=2))
    assert three["existing"] is None
    assert pair["existing"] is None


def test_single_sig_script_types_stay_distinct():
    session = Session()
    session.add_text(_single(expression(ABANDON, "m/84h/0h/0h")))
    taproot = session.plan_wallet_import(_single(expression(ABANDON, "m/86h/0h/0h"), kind="tr"))
    native = session.plan_wallet_import(_single(expression(ABANDON, "m/84h/0h/3h")))
    assert taproot["existing"] is None
    assert native["existing"] is session.wallets[0]
    assert session.wallet_short_name_of(session.wallets[0]).endswith("Native-Segwit")
    assert session.wallet_short_name_of(session.wallets[0]).startswith(
        session.fingerprints[root_of(ABANDON).my_fingerprint].nickname
    )


def test_a_suspicious_descriptor_key_stops_the_import():
    session = Session()
    session.add_mnemonic(ABANDON.split())
    forged = expression(LEGAL, "m/84h/0h/0h").replace(
        root_of(LEGAL).my_fingerprint.hex(),
        root_of(ABANDON).my_fingerprint.hex(),
        1,
    )
    app = App()
    app.session.add_mnemonic(ABANDON.split())
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_single(forged))
    assert app.screen == "load-error"
    assert app.load_error_home == "wallets"
    assert app.load_error.startswith("The key claims to belong to a previously-imported seed (named ")
    assert "winning the lottery" in app.load_error
    assert app.session.wallets == []
    app._act("load-error-ok")
    assert app.screen == "wallets"


def test_a_new_descriptor_is_verified_then_opened_with_wallets_behind_it():
    app = App()
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_single(expression(ABANDON, "m/84h/0h/0h")))
    assert app.screen == "external-review"
    assert "wallet owner" in app._wallet_key_warning()
    assert app.back == ["wallets"]
    assert app.session.wallets == []
    app._act("external-next")
    assert app.screen == "external-details"
    app._act("external-continue")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    assert len(app.session.fingerprints) == 1
    app.back_one()
    assert app.screen == "wallets"


def test_two_new_multisig_keys_are_verified_in_order():
    app = App()
    app.screen = "scan"
    app.scan_kind = "descriptor"
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/1h/2h")
    app.accept_qr(_multisig(first, second))
    assert app.screen == "external-review"
    assert app._wallet_key_warning().endswith("extended public keys (xpubs) are indeed theirs.")
    app.render()
    assert any(hit["label"] == "Show Extended Public Key Details" for hit in app.hits)
    assert app.pending_external.fingerprint == root_of(ABANDON).my_fingerprint
    app._act("external-next")
    assert app.screen == "external-details"
    app._act("external-continue")
    assert app.screen == "external-details"
    assert app.pending_external.fingerprint == root_of(LEGAL).my_fingerprint
    app._act("external-continue")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    wallet = app.session.wallets[0]
    assert wallet.accounts[root_of(ABANDON).my_fingerprint] == 0
    assert wallet.accounts[root_of(LEGAL).my_fingerprint] == 1
    assert app.session.wallet_short_name_of(wallet) == (
        f"2-of-2 {root_of(ABANDON).my_fingerprint.hex()},{root_of(LEGAL).my_fingerprint.hex()}"
    )


def test_multisig_wallet_import_verifies_each_new_key_saves_screenshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/1h/2h")
    (tmp_path / "wallet.txt").write_text(_multisig(first, second) + "\n")
    app = App()
    app.screen = "wallets"
    record = ScreenRecord(
        Path("artifacts/screenshots") / "test_multisig_wallet_import_verifies_each_new_key_saves_screenshots"
    )
    record.note("A new 2-of-2 descriptor is loaded from the SD card. Neither key is stored yet.")
    record.click(app, "plus")
    record.click(app, "Load descriptor from SD card")
    record.click(app, "wallet.txt")
    assert app.screen == "external-review"
    assert app._wallet_key_warning().endswith("extended public keys (xpubs) are indeed theirs.")
    assert app.session.wallets == []
    record.shot(app, "warning")
    record.click(app, "Show Extended Public Key Details")
    assert app.screen == "external-details"
    assert app.pending_external.fingerprint == root_of(ABANDON).my_fingerprint
    record.shot(app, "first-key")
    record.click(app, "Continue")
    assert app.screen == "external-details"
    assert app.pending_external.fingerprint == root_of(LEGAL).my_fingerprint
    record.shot(app, "second-key")
    record.click(app, "Continue")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    record.shot(app, "wallet")


def test_an_existing_wallet_reports_descriptor_accounts_without_adding_another(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/7h/2h")
    app = App()
    app.session.add_text(_multisig(first, second))
    swapped = _multisig(second, first)
    (tmp_path / "wallet.txt").write_text(swapped + "\n")
    app.screen = "wallets"
    record = ScreenRecord(
        __import__("pathlib").Path("artifacts/screenshots")
        / "test_an_existing_wallet_reports_descriptor_accounts_without_adding_another"
    )
    record.note("The same multisig was loaded from the SD card with its keys in the other order.")
    app.render()
    record.click(app, "plus")
    record.click(app, "Load descriptor from SD card")
    record.click(app, "wallet.txt")
    record.shot(app, "already-loaded")
    assert app.screen == "wallet-import-note"
    assert app.wallet_plan["new_keys"] == []
    assert len(app.session.wallets) == 1
    # Stored order is abandon, then legal. The swapped descriptor does not change that.
    assert app._wallet_import_accounts() == "account-indexes (0 (default),7 (non-default))"
    record.click(app, "wallet-import-continue")
    assert app.screen == "wallet"
    assert app.back == ["wallets"]
    assert len(app.session.wallets) == 1
    wallet = app.session.wallets[0]
    assert wallet.accounts[root_of(ABANDON).my_fingerprint] == 0
    assert wallet.accounts[root_of(LEGAL).my_fingerprint] == 7


def test_new_accounts_on_an_existing_wallet_are_announced_after_verification():
    app = App()
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    app.session.add_text(_multisig(first, second))
    fresh = expression(LEGAL, "m/48h/0h/8h/2h")
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_multisig(first, fresh))
    assert app.screen == "external-review"
    assert len(app.wallet_plan["new_keys"]) == 1
    app._act("external-next")
    app._act("external-continue")
    assert app.screen == "wallet-import-note"
    assert app._wallet_import_accounts() == "account-indexes (0 (default),8 (non-default))"
    assert len(app.session.fingerprints[root_of(LEGAL).my_fingerprint].keys) == 1
    app._act("wallet-import-continue")
    assert len(app.session.fingerprints[root_of(LEGAL).my_fingerprint].keys) == 2
    assert app.session.wallets[0].accounts[root_of(LEGAL).my_fingerprint] == 8
    assert app.screen == "wallet"
    assert app.back == ["wallets"]


def _account_dropdowns(app) -> list[str]:
    app.render()
    return [hit["action"] for hit in app.hits if hit["action"].startswith("dropdown-acct-")]


def test_the_wallet_screen_keeps_the_descriptor_fingerprint_order():
    legal = root_of(LEGAL).my_fingerprint
    abandon = root_of(ABANDON).my_fingerprint
    app = App()
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_multisig(expression(LEGAL, "m/48h/0h/1h/2h"), expression(ABANDON, "m/48h/0h/4h/2h")))
    app._act("external-next")
    app._act("external-continue")
    app._act("external-next")
    app._act("external-continue")
    wallet = app.session.wallets[0]
    assert wallet.fingerprints == (legal, abandon)
    app.render()
    assert _account_dropdowns(app) == []

    # The same keys, written the other way around, with accounts that are already stored.
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_multisig(expression(ABANDON, "m/48h/0h/4h/2h"), expression(LEGAL, "m/48h/0h/1h/2h")))
    assert app.screen == "wallet-import-note"
    assert app._wallet_import_accounts() == "account-indexes (1 (non-default),4 (non-default))"
    app._act("wallet-import-continue")
    assert app.session.wallets[0].fingerprints == (legal, abandon)
    assert _account_dropdowns(app) == []


def test_a_repeated_fingerprint_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    repeated = _multisig(
        expression(ABANDON, "m/48h/0h/0h/2h"),
        expression(ABANDON, "m/48h/0h/3h/2h"),
    )
    (tmp_path / "twice.txt").write_text(repeated + "\n")
    app = App()
    app.screen = "wallets"
    app._act("toggle-add")
    app._act("wallet-sd")
    app._act("sd-read:twice.txt")
    assert app.screen == "load-error"
    assert "same fingerprint more than once" in app.load_error
    assert "one account index for each fingerprint" in app.load_error
    assert app.session.wallets == []


def test_an_already_loaded_wallet_names_the_default_account():
    app = App()
    text = _single(expression(ABANDON, "m/84h/0h/0h"))
    app.session.add_text(text)
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(text)
    assert app.screen == "wallet-import-note"
    assert app._wallet_import_message() == (
        'Wallet "Grateful Ivory Impala 0A Native-Segwit" was already loaded. '
        "This descriptor points to account-index 0 (default)."
    )


def test_an_already_loaded_wallet_marks_a_nonzero_account_non_default():
    app = App()
    text = _single(expression(ABANDON, "m/84h/0h/3h"))
    app.session.add_text(text)
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(text)
    assert app._wallet_import_message() == (
        'Wallet "Grateful Ivory Impala 0A Native-Segwit" was already loaded. '
        "This descriptor points to account-index 3 (non-default)."
    )

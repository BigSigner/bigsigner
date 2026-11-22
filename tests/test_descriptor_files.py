"""Specter Desktop JSON, Specter DIY addwallet commands, multisig setup files, and Bitcoin Core descriptor files."""

import json

import pytest

from bigsigner.descriptor_files import (
    descriptor_from_bitcoin_core,
    descriptor_from_multisig_setup,
    descriptor_from_specter_desktop,
    descriptor_from_specter_diy,
)
from bigsigner.parse import ParseError, parse_wallet
from bigsigner.scan import classify_content
from bigsigner.sdcard import mount_memory, unmount_memory
from bigsigner.ui.app import App
from test_domain import ABANDON, expression

COMBINED = "wpkh([42c649e1/84h/1h/0h]tpubDDXW5F39TjUR2qLLjGZ41JhLyg7rdEedhE9UbPG3NqXbbTWXhkmknFrY1hyeYg3Q2YRFsYcBW6mSKhziPf8LWZW2ffaLH5PraJkiHcNmcfB/<0;1>/*)#rffa5cvk"
RECEIVE = "wpkh([42c649e1/84h/1h/0h]tpubDDXW5F39TjUR2qLLjGZ41JhLyg7rdEedhE9UbPG3NqXbbTWXhkmknFrY1hyeYg3Q2YRFsYcBW6mSKhziPf8LWZW2ffaLH5PraJkiHcNmcfB/0/*)#4aejxaxy"
CHANGE = "wpkh([42c649e1/84h/1h/0h]tpubDDXW5F39TjUR2qLLjGZ41JhLyg7rdEedhE9UbPG3NqXbbTWXhkmknFrY1hyeYg3Q2YRFsYcBW6mSKhziPf8LWZW2ffaLH5PraJkiHcNmcfB/1/*)#yfunmgku"
CORE = f"""# Receive and change descriptor:
{COMBINED}


# Receive descriptor:
{RECEIVE}

# Change descriptor:
{CHANGE}
"""


def _specter(descriptor, **extra):
    payload = {"label": "Test", "blockheight": 800000, "descriptor": descriptor}
    payload.update(extra)
    return json.dumps(payload)


def _tap(app, label):
    app.render()
    for hit in app.hits:
        if hit["label"] == label or hit["action"] == label:
            left, top, right, bottom = hit["box"]
            app.tap((left + right) // 2, (top + bottom) // 2)
            return
    raise AssertionError(label)


def test_a_specter_desktop_object_is_the_descriptor_string():
    assert descriptor_from_specter_desktop(_specter(COMBINED)) == COMBINED
    pretty = """
    {
      "descriptor": "wpkh([aa/84h/0h/0h]xpub/<0;1>/*)",
      "blockheight": 1,
      "label": "Cold"
    }
    """
    assert descriptor_from_specter_desktop(pretty) == "wpkh([aa/84h/0h/0h]xpub/<0;1>/*)"
    assert classify_content(_specter(COMBINED), "test").text == COMBINED
    assert classify_content(_specter(COMBINED), "test").kind == "descriptor"


def test_specter_json_that_is_not_the_export_is_left_alone():
    assert descriptor_from_specter_desktop(_specter(COMBINED, devices=[])) is None
    assert descriptor_from_specter_desktop(json.dumps({"label": "Test", "descriptor": COMBINED})) is None
    assert descriptor_from_specter_desktop(json.dumps({
        "label": "Test",
        "blockheight": 1,
        "descriptor": ["not", "a", "string"],
    })) is None
    assert descriptor_from_specter_desktop("{not json") is None
    assert descriptor_from_specter_desktop(COMBINED) is None
    assert classify_content(_specter(COMBINED, devices=[]), "main").kind == "unknown"


DIY = (
    "addwallet 2-of-2 Abandon,Example account-indexes 1,2&"
    "wsh(sortedmulti(2,"
    "[42c649e1/48h/1h/1h/2h]tpubDFTvq7adqjwbgrqRpJBapZa47wMmaEaDBAp9hseHF2GFjnHA2c8EAVcxmkdE21sZc823NbGxUFpN6H5BEy7f8kSdwg14fGkrmPD17qfds5S,"
    "[73c5da0a/48h/1h/2h/2h]tpubDEPGZXGPF2v3uNGTWHteRSQnZdEFfMvh6Dcp3DykkBE48hTA6pe3Es6nWH5dAThPyvqmZGmZqQhTw5kxqgR5uJW6Ei2VWyAAN92yLcYBvzV))"
)
DIY_DESCRIPTOR = DIY.split("&", 1)[1]


def test_a_specter_diy_command_keeps_the_descriptor_and_drops_the_name():
    assert descriptor_from_specter_diy(DIY) == DIY_DESCRIPTOR
    assert descriptor_from_specter_diy(f"addwallet A & B&{COMBINED}") == COMBINED
    assert descriptor_from_specter_diy(f"\naddwallet\tCold&{COMBINED}\n") == COMBINED
    parsed = classify_content(DIY, "test")
    assert parsed.kind == "descriptor"
    assert parsed.text == DIY_DESCRIPTOR
    assert descriptor_from_specter_diy(f"addwallet {COMBINED}") is None
    assert descriptor_from_specter_diy(f"addwalletname&{COMBINED}") is None
    assert descriptor_from_specter_diy(f"Addwallet Cold&{COMBINED}") is None
    assert descriptor_from_specter_diy("addwallet Cold&") is None
    assert classify_content(f"addwallet {COMBINED}", "test").kind == "unknown"


def _multisig_setup(header, *, mark="'", policy="2 of 2", script="P2WSH", derivation_label="Derivation"):
    return (
        f"{header}\n#\n"
        "Name: Account #1\n"
        f"Policy: {policy}\n"
        f"Format: {script}\n\n"
        f"{derivation_label}: m/48{mark}/1{mark}/1{mark}/2{mark}\n"
        "42C649E1: tpubDFTvq7adqjwbgrqRpJBapZa47wMmaEaDBAp9hseHF2GFjnHA2c8EAVcxmkdE21sZc823NbGxUFpN6H5BEy7f8kSdwg14fGkrmPD17qfds5S\n\n"
        f"{derivation_label}: m/48{mark}/1{mark}/2{mark}/2{mark}\n"
        "73C5DA0A: tpubDEPGZXGPF2v3uNGTWHteRSQnZdEFfMvh6Dcp3DykkBE48hTA6pe3Es6nWH5dAThPyvqmZGmZqQhTw5kxqgR5uJW6Ei2VWyAAN92yLcYBvzV\n"
    )


def test_coldcard_bluewallet_and_keystone_multisig_files_are_one_descriptor():
    headers = (
        "# Coldcard Multisig setup file (created by Sparrow)",
        "# BlueWallet Vault Multisig setup file (created by Sparrow)",
        "# Keystone Multisig setup file (created by Sparrow)",
    )
    descriptors = [descriptor_from_multisig_setup(_multisig_setup(header)) for header in headers]
    assert descriptors[0] == descriptors[1] == descriptors[2]
    hardened = descriptor_from_multisig_setup(_multisig_setup(headers[0], mark="h"))
    named = descriptor_from_multisig_setup(_multisig_setup(headers[0]).replace("Account #1", "Other name"))
    legacy = descriptor_from_multisig_setup(_multisig_setup(headers[0], derivation_label="# derivation"))
    folded = descriptor_from_multisig_setup(_multisig_setup(headers[0]).replace("Policy:", "policy:").replace("Format: P2WSH", "format: p2wsh"))
    for text in (descriptors[0], hardened, named, legacy, folded):
        parsed = parse_wallet(text, "test")
        assert parsed.threshold == 2
        assert [key.fingerprint.hex() for key in parsed.keys] == ["42c649e1", "73c5da0a"]
        assert [key.account for key in parsed.keys] == [1, 2]
        assert [key.branch_note for key in parsed.keys] == ["both", "both"]
    assert descriptor_from_multisig_setup("Name: Account #1\n") is None
    assert classify_content(_multisig_setup(headers[0]), "test").kind == "descriptor"


def test_a_multisig_setup_file_refuses_another_format_or_a_policy_that_does_not_match():
    header = "# Coldcard Multisig setup file (created by Sparrow)"
    with pytest.raises(ParseError, match="does not use P2WSH"):
        descriptor_from_multisig_setup(_multisig_setup(header, script="P2SH"))
    with pytest.raises(ParseError, match="policy of 2 of 3, but contains 2 keys"):
        descriptor_from_multisig_setup(_multisig_setup(header, policy="2 of 3"))
    repeated = _multisig_setup(header) + "Policy: 2 of 2\n"
    with pytest.raises(ParseError, match="policy could not be read"):
        descriptor_from_multisig_setup(repeated)
    early = _multisig_setup(header).replace(
        "Derivation: m/48'/1'/1'/2'\n42C649E1:",
        "42C649E1:",
        1,
    )
    with pytest.raises(ParseError, match="key before its derivation"):
        descriptor_from_multisig_setup(early)
    with pytest.raises(Exception, match="does not use P2WSH"):
        classify_content(_multisig_setup(header, script="P2WSH-P2SH"), "test")


def test_a_multisig_setup_file_loads_the_wallet():
    app = App()
    app.session.set_network("test")
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(_multisig_setup("# Keystone Multisig setup file (created by Sparrow)"))
    assert app.screen == "external-review"
    keys = app.wallet_plan["parsed"].keys
    assert [key.fingerprint.hex() for key in keys] == ["42c649e1", "73c5da0a"]
    assert [key.account for key in keys] == [1, 2]
    assert app.wallet_plan["parsed"].threshold == 2


def test_a_specter_diy_command_loads_the_descriptor():
    app = App()
    app.session.set_network("test")
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(DIY)
    assert app.screen == "external-review"
    keys = app.wallet_plan["parsed"].keys
    assert [key.fingerprint.hex() for key in keys] == ["42c649e1", "73c5da0a"]
    assert [key.account for key in keys] == [1, 2]
    assert app.wallet_plan["parsed"].threshold == 2


def test_a_bitcoin_core_file_keeps_the_combined_descriptor():
    assert descriptor_from_bitcoin_core(CORE) == COMBINED
    swapped = "\n".join(["# Change descriptor:", CHANGE, "# Receive descriptor:", RECEIVE, COMBINED])
    assert descriptor_from_bitcoin_core("\r\n".join([
        "# Receive and change descriptor:",
        COMBINED,
        RECEIVE,
        CHANGE,
    ])) == COMBINED
    assert descriptor_from_bitcoin_core(swapped) is None
    only_receive = "\n".join(["# Receive and change descriptor:", COMBINED, "", RECEIVE])
    assert descriptor_from_bitcoin_core(only_receive) == COMBINED
    assert classify_content(CORE, "test").text == COMBINED


def test_a_bitcoin_core_file_replaces_every_branch():
    first = "wsh(sortedmulti(2,xpubA/<0;1>/*,xpubB/<0;1>/*))"
    text = "\n".join([
        first,
        first.replace("<0;1>", "0"),
        first.replace("<0;1>", "1"),
    ])
    assert descriptor_from_bitcoin_core(text) == first
    broken = "\n".join([first, first.replace("<0;1>", "0"), "wsh(sortedmulti(2,xpubA/0/*,xpubB/2/*))"])
    assert descriptor_from_bitcoin_core(broken) is None
    assert descriptor_from_bitcoin_core(COMBINED) is None


def test_a_bitcoin_core_checksum_is_checked_after_the_shape_matches():
    bad = CORE.replace("#4aejxaxy", "#aaaaaaaa")
    with pytest.raises(ParseError, match="checksum does not match"):
        descriptor_from_bitcoin_core(bad)
    with pytest.raises(Exception, match="checksum does not match"):
        classify_content(bad, "test")


def test_specter_and_bitcoin_core_files_load_as_the_combined_descriptor():
    specter = _specter(COMBINED)
    core_app = App()
    core_app.session.set_network("test")
    mount_memory({"files": {"core.txt": CORE, "specter.txt": specter, "extra.txt": _specter(COMBINED, devices=[])}})
    try:
        core_app.screen = "wallets"
        _tap(core_app, "plus")
        _tap(core_app, "Load from File")
        _tap(core_app, "SD Card")
        _tap(core_app, "core.txt")
        assert core_app.screen == "external-review"
        assert core_app.wallet_plan["parsed"].keys[0].branch_note == "both"

        specter_file = App()
        specter_file.session.set_network("test")
        specter_file.screen = "wallets"
        _tap(specter_file, "plus")
        _tap(specter_file, "Load from File")
        _tap(specter_file, "SD Card")
        _tap(specter_file, "specter.txt")
        assert specter_file.screen == "external-review"
        assert specter_file.wallet_plan["parsed"].keys[0].branch_note == "both"

        refused = App()
        refused.session.set_network("test")
        refused.screen = "wallets"
        _tap(refused, "plus")
        _tap(refused, "Load from File")
        _tap(refused, "SD Card")
        _tap(refused, "extra.txt")
        assert refused.screen == "load-error"
        assert refused.load_error == "That file is not a wallet descriptor."
    finally:
        unmount_memory()

    scanned = App()
    scanned.session.set_network("test")
    scanned.screen = "scan"
    scanned.scan_kind = "descriptor"
    scanned.accept_qr(specter)
    assert scanned.screen == "external-review"
    assert scanned.wallet_plan["parsed"].keys[0].branch_note == "both"

    core_qr = App()
    core_qr.session.set_network("test")
    core_qr.screen = "scan"
    core_qr.scan_kind = "descriptor"
    core_qr.accept_qr(CORE)
    assert core_qr.screen == "external-review"
    assert core_qr.wallet_plan["parsed"].keys[0].branch_note == "both"


def test_a_mainnet_descriptor_file_uses_the_same_reader():
    key = expression(ABANDON, "m/84h/0h/0h")
    from embit.descriptor.checksum import add_checksum

    combined = add_checksum(f"wpkh({key})")
    text = "\n".join([
        "# Receive and change descriptor:",
        combined,
        "# Receive descriptor:",
        add_checksum(combined.split("#", 1)[0].replace("<0;1>", "0")),
        "# Change descriptor:",
        add_checksum(combined.split("#", 1)[0].replace("<0;1>", "1")),
    ])
    app = App()
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(json.dumps({"blockheight": None, "label": 1, "descriptor": combined}))
    assert app.screen == "external-review"
    assert app.wallet_plan["parsed"].keys[0].branch_note == "both"
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(text)
    assert app.screen == "external-review"
    assert app.wallet_plan["parsed"].keys[0].branch_note == "both"

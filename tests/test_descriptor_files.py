"""Specter-DIY JSON exports and Bitcoin Core descriptor files."""

import json

import pytest

from bigsigner.descriptor_files import descriptor_from_bitcoin_core, descriptor_from_specter
from bigsigner.parse import ParseError
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


def test_a_specter_object_is_the_descriptor_string():
    assert descriptor_from_specter(_specter(COMBINED)) == COMBINED
    pretty = """
    {
      "descriptor": "wpkh([aa/84h/0h/0h]xpub/<0;1>/*)",
      "blockheight": 1,
      "label": "Cold"
    }
    """
    assert descriptor_from_specter(pretty) == "wpkh([aa/84h/0h/0h]xpub/<0;1>/*)"
    assert classify_content(_specter(COMBINED), "test").text == COMBINED
    assert classify_content(_specter(COMBINED), "test").kind == "descriptor"


def test_specter_json_that_is_not_the_export_is_left_alone():
    assert descriptor_from_specter(_specter(COMBINED, devices=[])) is None
    assert descriptor_from_specter(json.dumps({"label": "Test", "descriptor": COMBINED})) is None
    assert descriptor_from_specter(json.dumps({
        "label": "Test",
        "blockheight": 1,
        "descriptor": ["not", "a", "string"],
    })) is None
    assert descriptor_from_specter("{not json") is None
    assert descriptor_from_specter(COMBINED) is None
    assert classify_content(_specter(COMBINED, devices=[]), "main").kind == "unknown"


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

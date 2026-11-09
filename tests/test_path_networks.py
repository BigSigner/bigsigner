"""Name both networks only when the coin type is the sole invalid path part."""

import json

import pytest
from embit.descriptor import Descriptor
from embit.descriptor.checksum import checksum
from embit.networks import NETWORKS
from embit.psbt import DerivationPath, OutputScope, PSBT
from embit.script import p2tr, p2wpkh
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.bsms import bsms_text
from bigsigner.message_sign import native_sign_path
from bigsigner.parse import ParseError, parse_key_expression, parse_wallet
from bigsigner.paths import PathError, classify_path, parse_path, path_network_mismatch
from bigsigner.psbt_check import check_loaded_psbt
from bigsigner.psbt_review import ReviewError, review_psbt
from bigsigner.session import Session
from bigsigner.ui.app import App
from bigsigner.ur import descriptor_ur
from test_domain import ABANDON, LEGAL, root_of

MAIN_TO_TEST = "The currently selected network is mainnet, but the derivation path belongs to testnet or regtest."
TEST_TO_MAIN = "The currently selected network is testnet, but the derivation path belongs to mainnet."
REGTEST_TO_MAIN = "The currently selected network is regtest, but the derivation path belongs to mainnet."
MISMATCHES = [("main", "test", MAIN_TO_TEST), ("test", "main", TEST_TO_MAIN),
              ("regtest", "main", REGTEST_TO_MAIN)]


def _path(network, purpose=84):
    coin = 0 if network == "main" else 1
    return f"m/{purpose}h/{coin}h/0h" + ("/2h" if purpose == 48 else "")


def _expression(words, network, purpose=84):
    root = root_of(words)
    path = _path(network, purpose)
    public = root.derive(path).to_public().to_base58(version=NETWORKS[network]["xpub"])
    return f"[{root.my_fingerprint.hex()}/{path[2:]}]{public}/<0;1>/*"


def _descriptor(network, purpose=84):
    key = _expression(ABANDON, network, purpose)
    if purpose == 48:
        return f"wsh(sortedmulti(2,{key},{_expression(LEGAL, network, purpose)}))"
    return f"{'tr' if purpose == 86 else 'wpkh'}({key})"


def _session(network, purpose=84):
    session = Session()
    session.set_network(network)
    session.add_mnemonic(ABANDON.split())
    session.add_text(_descriptor(network, purpose))
    return session


def _psbt(network, purpose=84):
    root = root_of(ABANDON)
    path = parse_path(_path(network, purpose) + "/0/7")
    key = root.derive(path).to_public().key
    script = p2tr(key) if purpose == 86 else p2wpkh(key)
    derived = None
    if purpose == 48:
        derived = Descriptor.from_string(_descriptor(network, purpose)).derive(7, branch_index=0)
        script = derived.script_pubkey()
    psbt = PSBT(Transaction(
        version=2, vin=[TransactionInput(b"\x51" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[TransactionOutput(90_000, script)],
    ))
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script)
    origin = DerivationPath(root.my_fingerprint, path)
    if purpose == 86:
        psbt.inputs[0].taproot_bip32_derivations[key] = ([], origin)
    else:
        psbt.inputs[0].bip32_derivations[key] = origin
    if derived is not None:
        psbt.inputs[0].witness_script = derived.witness_script()
        other = root_of(LEGAL)
        other_key = other.derive(path).to_public().key
        psbt.inputs[0].bip32_derivations[other_key] = DerivationPath(other.my_fingerprint, path)
    return psbt


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_valid_account_origins_name_selected_and_path_networks(selected, belonging, message, purpose):
    path = parse_path(_path(belonging, purpose))
    with pytest.raises(PathError) as error:
        classify_path(path, selected)
    assert str(error.value) == message
    assert path_network_mismatch(path + [1, 120], selected, address=True) == message
    assert classify_path(path, belonging)[1] == 0


@pytest.mark.parametrize("path,address", [
    ("m/44h/1h/0h", False), ("m/84h/1h/0", False), ("m/84h/1/0h", False),
    ("m/84h/2h/0h", False), ("m/84h/1h", False), ("m/84h/1h/0h/0", False),
    ("m/48h/1h/0h/1h", False), ("m/48h/1h/0h/3h", False),
    ("m/84h/1h/0h/2/0", True), ("m/84h/1h/0h/0h/0", True),
    ("m/84h/1h/0h/0/0h", True), ("m/84h/1h/0h/0/0/1", True),
    ("m/84h/1h/0/0/0", True), ("m/48h/1h/0h/1h/0/0", True),
])
def test_other_invalid_path_parts_keep_their_existing_errors(path, address):
    steps = parse_path(path)
    assert path_network_mismatch(steps, "main", address=address) is None
    if not address:
        with pytest.raises(PathError) as error:
            classify_path(steps, "main")
        assert "currently selected network" not in str(error.value)


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_key_expressions_and_descriptors_preserve_the_network_explanation(selected, belonging, message, purpose):
    with pytest.raises(ParseError) as error:
        parse_key_expression(_expression(ABANDON, belonging, purpose), selected)
    assert str(error.value) == message
    with pytest.raises(ParseError) as error:
        parse_wallet(_descriptor(belonging, purpose), selected)
    assert str(error.value) == message


@pytest.mark.parametrize("selected,belonging,_message", MISMATCHES)
@pytest.mark.parametrize("suffix", ["/2/*", "/0h/*"])
def test_invalid_key_suffixes_do_not_report_only_a_network_mismatch(selected, belonging, _message, suffix):
    key = _expression(ABANDON, belonging).replace("/<0;1>/*", suffix)
    with pytest.raises(ParseError) as error:
        parse_key_expression(key, selected)
    assert str(error.value) == "The key expression uses an address suffix that is not supported."


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_psbt_inputs_name_both_networks_in_checks_review_and_error_screen(selected, belonging, message, purpose):
    session = _session(selected, purpose)
    psbt = _psbt(belonging, purpose)
    for check in (check_loaded_psbt, review_psbt):
        with pytest.raises(ReviewError) as error:
            check(session, 0, psbt.serialize())
        assert str(error.value) == message
    app = App()
    app.session = session
    app.wallet_index = 0
    app._accept_psbt_text(psbt.serialize(), "file")
    assert app.screen == "psbt-error"
    app.render()
    text = " ".join(mark["text"] for mark in app.texts)
    assert message in text
    button = next(hit for hit in app.hits if hit["label"] == "OK")
    assert all(mark["box"][3] < button["box"][1] for mark in app.texts)


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
def test_wrong_network_on_an_owned_psbt_output_is_not_swallowed(selected, belonging, message):
    session = _session(selected)
    psbt = _psbt(selected)
    foreign = _psbt(belonging)
    origin = foreign.inputs[0]
    scope = OutputScope(vout=TransactionOutput(90_000, origin.witness_utxo.script_pubkey))
    scope.bip32_derivations.update(origin.bip32_derivations)
    psbt.outputs[0] = scope
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(session, 0, psbt)
    assert str(error.value) == message


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
@pytest.mark.parametrize("payload_kind", ["key", "descriptor", "bsms", "specter", "core", "ur"])
def test_import_error_screens_keep_the_network_explanation(selected, belonging, message, payload_kind):
    descriptor = _descriptor(belonging)
    if payload_kind == "key":
        payload = _expression(ABANDON, belonging)
    elif payload_kind == "bsms":
        payload = bsms_text(descriptor, belonging)
    elif payload_kind == "specter":
        payload = json.dumps({"label": "Test", "blockheight": 0, "descriptor": descriptor})
    elif payload_kind == "core":
        lines = [descriptor, descriptor.replace("<0;1>", "0"), descriptor.replace("<0;1>", "1")]
        payload = "\n".join(f"{line}#{checksum(line)}" for line in lines)
    elif payload_kind == "ur":
        payload = descriptor_ur(_session(belonging), 0)
    else:
        payload = descriptor
    app = App()
    app.session.set_network(selected)
    app.screen = "scan"
    app.scan_kind = "key" if payload_kind == "key" else "descriptor"
    app.accept_qr(payload)
    assert app.screen == "load-error"
    assert message in app.load_error
    assert not app.session.wallets and not app.session.fingerprints
    app.render()
    assert message in " ".join(mark["text"] for mark in app.texts)


@pytest.mark.parametrize("selected", ["test", "regtest"])
@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_testnet_and_regtest_share_coin_type_one_without_a_network_error(selected, purpose):
    steps = parse_path(_path("test", purpose))
    assert classify_path(steps, selected)[1] == 0
    assert path_network_mismatch(steps, selected) is None
    assert path_network_mismatch(steps + [0, 120], selected, address=True) is None
    parse_wallet(_descriptor("test", purpose), selected)


@pytest.mark.parametrize("network", ["main", "test", "regtest"])
@pytest.mark.parametrize("purpose", [84, 86, 48])
def test_matching_network_psbts_still_load(network, purpose):
    session = _session(network, purpose)
    psbt = _psbt(network, purpose)
    assert check_loaded_psbt(session, 0, psbt).serialize() == psbt.serialize()


@pytest.mark.parametrize("selected,belonging,message", MISMATCHES)
def test_message_signing_commands_name_both_networks(selected, belonging, message):
    with pytest.raises(ValueError) as error:
        native_sign_path(_path(belonging) + "/0/120", selected, 0)
    assert str(error.value) == message


def test_psbt_with_another_bad_path_part_does_not_blame_the_network():
    session = _session("main")
    psbt = _psbt("test")
    origin = next(iter(psbt.inputs[0].bip32_derivations.values()))
    origin.derivation[-2] = 2
    with pytest.raises(ReviewError) as error:
        check_loaded_psbt(session, 0, psbt)
    assert "would not derive" in str(error.value)
    assert "currently selected network" not in str(error.value)


def test_network_mismatch_errors_saves_screenshots():
    from pathlib import Path

    from test_ui import ScreenRecord

    record = ScreenRecord(Path("artifacts/screenshots/test_network_mismatch_errors_saves_screenshots"))
    for selected, belonging, _ in MISMATCHES:
        app = App()
        app.session = _session(selected)
        app.wallet_index = 0
        app._accept_psbt_text(_psbt(belonging).serialize(), "file")
        record.shot(app, f"psbt-{selected}-selected-{belonging}-path")
    for kind, purpose in (("key", 86), ("descriptor", 48)):
        app = App()
        app.screen = "scan"
        app.scan_kind = kind
        text = _expression(ABANDON, "test", purpose) if kind == "key" else _descriptor("test", purpose)
        app.accept_qr(text)
        record.shot(app, f"{kind}-main-selected-test-path")

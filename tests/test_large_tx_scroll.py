"""A native-segwit transaction large enough to scroll, still under the standard weight.

Committed binaries live in ``tests/vectors/``. Rebuild them with
``write_psbt_vectors`` when the builders below change.

Laptop headless scroll timing (``.venv`` on the desktop):

```bash
cd /path/to/bigsigner
PYTHONPATH=src:tests .venv/bin/pytest tests/test_large_tx_scroll.py -k hundred -v
```

To drive the same PSBT on the Raspberry Pi panel, use
``tests/panel_show_hundred_psbt.py``. Steps are in ``tests/vectors/README.md``.
"""

import time
from hashlib import sha256
from pathlib import Path
from random import Random

from embit.psbt import DerivationPath, OutputScope, PSBT
from embit.script import Script, address_to_scriptpubkey
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from bigsigner.psbt_check import (
    MAX_PSBT_INPUTS,
    MAX_PSBT_OUTPUTS,
    MAX_STANDARD_TX_WEIGHT,
    check_loaded_psbt,
)
from bigsigner.psbt_review import ReviewError, _tx_weight
from bigsigner.psbt_view import describe_psbt
from bigsigner.session import Session
from bigsigner.ui.app import App
from bigsigner.ui.canvas import HEADER, HEIGHT, WIDTH
from test_domain import LEGAL
from test_psbt_load import _child, _native, _psbt
from test_psbt_view import _pay_this_wallet
from test_ui import ScreenRecord

COUNT = 100
MEDIUM_INPUTS = 100
# First receive address of the LEGAL test mnemonic. Not an Abandon address.
EXTERNAL_P2WPKH = "bc1qgkju4yvvtuz0s8vqn837q396jezu2h8ex7gk98"
# 100 inputs × 100000 sats, fee 10000 sats (0.0001 BTC).
MEDIUM_INPUT_SATS = 100_000
MEDIUM_FEE_SATS = 10_000
MEDIUM_EXTERNAL_SATS = 9_000_000
MEDIUM_CHANGE_SATS = (
    MEDIUM_INPUTS * MEDIUM_INPUT_SATS - MEDIUM_EXTERNAL_SATS - MEDIUM_FEE_SATS
)
VECTORS = Path(__file__).resolve().parent / "vectors"
MEDIUM_VECTOR = VECTORS / "native_segwit_100_in_1_external_1_change.psbt"
HUNDRED_VECTOR = VECTORS / "native_segwit_100_in_100_out.psbt"
COMBINED_WARNINGS_VECTOR = VECTORS / "native_segwit_combined_warnings.psbt"
# Change address #120 has no derivation in the PSBT. Search windows are 50
# addresses wide, so 0–49 and 50–99 miss and 100–149 finds it.
HIDDEN_CHANGE_INDEX = 120
HIDDEN_CHANGE_VECTOR = VECTORS / "native_segwit_hidden_change_120.psbt"
# Sequences for the combined-warnings vector: RBF-enabled, RBF-disabled,
# block relative locktimes, and time relative locktimes (including the max).
COMBINED_SEQUENCES = (
    0xFFFFFFFD,
    0xFFFFFFFD,
    0xFFFFFFFE,
    0xFFFFFFFE,
    1,
    144,
    0x00400002,
    0x0040FFFF,
)
# The panel logs a frame of 500 ms or more as slow.
SCROLL_FRAME_S = 0.5


def _prev_txids(count: int, *, label: str) -> list[bytes]:
    """Distinct fake previous txids. Seeded so committed vectors stay stable.

    ``index.to_bytes(32, "little")`` made the first input all zeros; these are
    drawn from a PRNG instead and never the zero hash.
    """
    rng = Random(int.from_bytes(sha256(label.encode()).digest()[:8], "big"))
    zero = b"\x00" * 32
    seen = set()
    out = []
    while len(out) < count:
        txid = bytes(rng.getrandbits(8) for _ in range(32))
        if txid == zero or txid in seen:
            continue
        seen.add(txid)
        out.append(txid)
    return out


def _legal_receive_scripts(count: int) -> list:
    """Native-segwit scripts for LEGAL receive addresses 0 .. ``count`` - 1."""
    from embit import bip32, bip39
    from embit.descriptor.checksum import checksum

    legal = Session()
    legal.add_mnemonic(LEGAL.split())
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(LEGAL))
    public = root.derive("m/84h/0h/0h").to_public()
    key = f"[{root.my_fingerprint.hex()}/84h/0h/0h]{public.to_string()}/<0;1>/*"
    legal.add_text(f"wpkh({key})#{checksum('wpkh(' + key + ')')}")
    addresses = legal.addresses(0, 0, 0, count)
    assert addresses[0] == EXTERNAL_P2WPKH
    assert len(set(addresses)) == count
    return [address_to_scriptpubkey(address) for address in addresses]


def _native_bulk(session, count: int):
    """``count`` native-segwit inputs; ``count`` outputs with one change.

    ``count - 1`` outputs are 50000 sats each to distinct LEGAL receive
    addresses (indexes 0 .. count-2). The last is change to this wallet's
    change address #0. Most inputs match that amount; the first carries an
    extra 50000 sats so the fee stays under the 100000-sat high-fee warning.
    """
    fingerprint, child, path = _child(session, branch=0, index=0)
    _fp, change_child, change_path = _child(session, branch=1, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    change = address_to_scriptpubkey(session.addresses(0, 1, 0, 1)[0])
    destinations = _legal_receive_scripts(count - 1)
    per_out = 50_000
    fee = 50_000
    vins = [
        TransactionInput(txid, 0, sequence=0xFFFFFFFD)
        for txid in _prev_txids(count, label=f"native-bulk-{count}")
    ]
    vouts = [TransactionOutput(per_out, destination) for destination in destinations]
    vouts.append(TransactionOutput(per_out, change))
    tx = Transaction(version=2, vin=vins, vout=vouts)
    psbt = PSBT(tx)
    for index, inp in enumerate(psbt.inputs):
        amount = per_out + (fee if index == 0 else 0)
        inp.witness_utxo = TransactionOutput(amount, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        inp.sighash_type = SIGHASH.ALL
    change_scope = psbt.outputs[-1]
    change_scope.bip32_derivations[change_child.key] = DerivationPath(fingerprint, change_path)
    return psbt


def _native_many_outputs(session, inputs: int, outputs: int):
    """``inputs`` native-segwit inputs paying ``outputs`` equal external amounts."""
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    per_out = 50_000
    per_in = ((outputs * per_out) // inputs) + 1
    vins = [
        TransactionInput(txid, 0, sequence=0xFFFFFFFD)
        for txid in _prev_txids(inputs, label=f"native-outs-{inputs}-{outputs}")
    ]
    vouts = [TransactionOutput(per_out, destination) for _ in range(outputs)]
    tx = Transaction(version=2, vin=vins, vout=vouts)
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(per_in, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        inp.sighash_type = SIGHASH.ALL
    return psbt


def _native_medium(session):
    """``MEDIUM_INPUTS`` inputs, one real external payment, and one change output."""
    fingerprint, receive_child, receive_path = _child(session, branch=0, index=0)
    _fp, change_child, change_path = _child(session, branch=1, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    change = address_to_scriptpubkey(session.addresses(0, 1, 0, 1)[0])
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    assert MEDIUM_CHANGE_SATS > 0
    vins = [
        TransactionInput(txid, 0, sequence=0xFFFFFFFD)
        for txid in _prev_txids(MEDIUM_INPUTS, label="native-medium")
    ]
    tx = Transaction(
        version=2,
        vin=vins,
        vout=[
            TransactionOutput(MEDIUM_EXTERNAL_SATS, destination),
            TransactionOutput(MEDIUM_CHANGE_SATS, change),
        ],
    )
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(MEDIUM_INPUT_SATS, script)
        inp.bip32_derivations[receive_child.key] = DerivationPath(fingerprint, receive_path)
        inp.sighash_type = SIGHASH.ALL
    change_scope = psbt.outputs[1]
    change_scope.bip32_derivations[change_child.key] = DerivationPath(fingerprint, change_path)
    return psbt


def _op_return(payload: bytes, amount: int = 0) -> OutputScope:
    if len(payload) <= 75:
        raw = bytes([0x6A, len(payload)]) + payload
    else:
        raw = bytes([0x6A, 0x4C, len(payload)]) + payload
    return OutputScope(vout=TransactionOutput(amount, Script(raw)))


def _combined_warnings(session):
    """Abandon native-segwit spend that surfaces every Transaction Signing warning.

    Eight inputs of the Abandon receive address #0 use the sequence kinds that
    produce RBF-disabled and relative-locktime notes. The absolute locktime is
    a timestamp. Outputs are one payment to the LEGAL receive address #0, change
    to Abandon change #0, a second change on Abandon receive #1, and a paid
    OP_RETURN. The fee is intentionally huge.
    """
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    vins = [
        TransactionInput(bytes([index + 1]) * 32, 0, sequence=sequence)
        for index, sequence in enumerate(COMBINED_SEQUENCES)
    ]
    tx = Transaction(version=2, vin=vins, vout=[TransactionOutput(40_000, destination)])
    tx.locktime = 1_700_000_000
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(200_000, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        inp.sighash_type = SIGHASH.ALL
    _pay_this_wallet(psbt, session, branch=1, index=0, amount=40_000)
    _pay_this_wallet(psbt, session, branch=0, index=1, amount=40_000)
    psbt.outputs.append(_op_return(b"meta", 1_000))
    return psbt


def _hidden_change(session):
    """Abandon spends to an external address and to its own change address #120.

    The change output is only a script pubkey. No derivation is stored, so the
    signing screen treats it as external until Search for Address in Loaded
    Wallets reaches indexes 100–149.
    """
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    change = address_to_scriptpubkey(session.addresses(0, 1, HIDDEN_CHANGE_INDEX, 1)[0])
    tx = Transaction(
        version=2,
        vin=[TransactionInput(b"\x31" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[
            TransactionOutput(50_000, destination),
            TransactionOutput(40_000, change),
        ],
    )
    psbt = PSBT(tx)
    inp = psbt.inputs[0]
    inp.witness_utxo = TransactionOutput(100_000, script)
    inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    inp.sighash_type = SIGHASH.ALL
    assert not psbt.outputs[1].bip32_derivations
    return psbt


def write_psbt_vectors(folder: Path | None = None) -> list[Path]:
    """Write the committed PSBT binaries. Returns the paths that were written."""
    folder = VECTORS if folder is None else folder
    folder.mkdir(parents=True, exist_ok=True)
    session = _native()
    written = []
    for path, psbt in (
        (folder / MEDIUM_VECTOR.name, _native_medium(session)),
        (folder / HUNDRED_VECTOR.name, _native_bulk(session, COUNT)),
        (folder / COMBINED_WARNINGS_VECTOR.name, _combined_warnings(session)),
        (folder / HIDDEN_CHANGE_VECTOR.name, _hidden_change(session)),
    ):
        path.write_bytes(psbt.serialize())
        written.append(path)
    return written


def test_a_transaction_over_100000_vb_is_refused(monkeypatch):
    session = _native()
    small = _psbt(session)
    assert _tx_weight(small.tx, session.wallets[0]) <= MAX_STANDARD_TX_WEIGHT
    assert check_loaded_psbt(session, 0, small).tx.version == 2
    monkeypatch.setattr(
        "bigsigner.psbt_check._tx_weight",
        lambda *args, **kwargs: MAX_STANDARD_TX_WEIGHT + 1,
    )
    try:
        check_loaded_psbt(session, 0, small)
    except ReviewError as exc:
        assert "400000 weight units" in str(exc)
    else:
        raise AssertionError("weight")


def test_more_than_100_inputs_is_refused():
    session = _native()
    heavy = _native_bulk(session, MAX_PSBT_INPUTS + 1)
    try:
        check_loaded_psbt(session, 0, heavy)
    except ReviewError as exc:
        assert f"more than {MAX_PSBT_INPUTS} inputs" in str(exc)
    else:
        raise AssertionError("inputs")


def test_more_than_100_outputs_is_refused():
    session = _native()
    heavy = _native_many_outputs(session, inputs=1, outputs=MAX_PSBT_OUTPUTS + 1)
    try:
        check_loaded_psbt(session, 0, heavy)
    except ReviewError as exc:
        assert f"more than {MAX_PSBT_OUTPUTS} outputs" in str(exc)
    else:
        raise AssertionError("outputs")


def test_the_committed_psbt_vectors_match_the_builders():
    session = _native()
    assert MEDIUM_VECTOR.is_file(), f"missing {MEDIUM_VECTOR}"
    assert HUNDRED_VECTOR.is_file(), f"missing {HUNDRED_VECTOR}"
    assert COMBINED_WARNINGS_VECTOR.is_file(), f"missing {COMBINED_WARNINGS_VECTOR}"
    assert HIDDEN_CHANGE_VECTOR.is_file(), f"missing {HIDDEN_CHANGE_VECTOR}"
    assert MEDIUM_VECTOR.read_bytes() == _native_medium(session).serialize()
    assert HUNDRED_VECTOR.read_bytes() == _native_bulk(session, COUNT).serialize()
    assert COMBINED_WARNINGS_VECTOR.read_bytes() == _combined_warnings(session).serialize()
    assert HIDDEN_CHANGE_VECTOR.read_bytes() == _hidden_change(session).serialize()


def test_a_hidden_change_address_is_found_in_addresses_100_to_149():
    from bigsigner.psbt_view import SEARCH_WINDOW, search_address

    session = _native()
    psbt = PSBT.parse(HIDDEN_CHANGE_VECTOR.read_bytes())
    assert not psbt.outputs[1].bip32_derivations
    checked = check_loaded_psbt(session, 0, psbt)
    view = describe_psbt(session, 0, checked)
    address = session.addresses(0, 1, HIDDEN_CHANGE_INDEX, 1)[0]
    assert view["outputs"][1]["address"] == address
    assert view["outputs"][1]["owned"] is None
    assert view["change_outputs"] == []
    assert search_address(session, 0, address, 0, SEARCH_WINDOW) is None
    assert search_address(session, 0, address, 50, SEARCH_WINDOW) is None
    found = search_address(session, 0, address, 100, SEARCH_WINDOW)
    assert found["branch"] == 1
    assert found["index"] == HIDDEN_CHANGE_INDEX
    assert found["place"] == f"Change Address #{HIDDEN_CHANGE_INDEX}"


def test_the_combined_warnings_vector_loads_every_warning():
    session = _native()
    psbt = PSBT.parse(COMBINED_WARNINGS_VECTOR.read_bytes())
    view = describe_psbt(session, 0, check_loaded_psbt(session, 0, psbt))
    texts = [item["text"] for item in view["warnings"]]
    assert any("non-zero amount" in text for text in texts)
    assert any(text == "This transaction uses an extremely high fee." for text in texts)
    assert any(text.startswith("This transaction uses a timestamp locktime.") for text in texts)
    assert any(text.startswith("Some inputs use a relative locktime.") for text in texts)
    assert any("additional requirement" in text for text in texts)
    assert any(text.startswith("Some inputs are marked as Replace-by-Fee") for text in texts)
    assert any(text.startswith("This transaction has more than one change output.") for text in texts)
    assert any("receive address instead of a change address" in text for text in texts)
    places = [card["place"] for card in view["change_outputs"]]
    assert places == ["Change Address #0", "Receive Address #1"]
    assert view["outputs"][0]["address"] == EXTERNAL_P2WPKH


def test_a_hundred_inputs_with_change_load_and_describe():
    session = _native()
    raw = MEDIUM_VECTOR.read_bytes()
    psbt = PSBT.parse(raw)
    wallet = session.wallets[0]
    weight = _tx_weight(psbt.tx, wallet)
    assert weight <= MAX_STANDARD_TX_WEIGHT
    assert len(psbt.inputs) == MEDIUM_INPUTS
    assert len(psbt.tx.vout) == 2
    total_in = MEDIUM_INPUTS * MEDIUM_INPUT_SATS
    assert total_in - MEDIUM_EXTERNAL_SATS - MEDIUM_CHANGE_SATS == MEDIUM_FEE_SATS
    owned = set(session.addresses(0, 0, 0, 20)) | set(session.addresses(0, 1, 0, 20))
    assert EXTERNAL_P2WPKH not in owned
    checked = check_loaded_psbt(session, 0, psbt)
    view = describe_psbt(session, 0, checked)
    assert len(view["inputs"]) == MEDIUM_INPUTS
    assert len(view["outputs"]) == 1
    assert view["outputs"][0]["address"] == EXTERNAL_P2WPKH
    assert view["outputs"][0]["change"] is False
    assert view["outputs"][0]["owned"] is None
    assert len(view["change_outputs"]) == 1
    assert view["change_outputs"][0]["place"] == "Change Address #0"
    assert view["fee"] == MEDIUM_FEE_SATS


def test_a_hundred_native_segwit_payments_scroll_smoothly():
    record = ScreenRecord(
        Path("artifacts/screenshots") / "test_a_hundred_native_segwit_payments_scroll_smoothly"
    )
    session = _native()
    psbt = PSBT.parse(HUNDRED_VECTOR.read_bytes())
    wallet = session.wallets[0]
    weight = _tx_weight(psbt.tx, wallet)
    record.note(
        f"Native-segwit, {COUNT} inputs, {COUNT - 1} external outputs and 1 change, "
        f"{weight} weight units. Scroll frames that reuse the cached parts must stay under "
        f"{int(SCROLL_FRAME_S * 1000)} ms."
    )
    assert weight <= MAX_STANDARD_TX_WEIGHT
    checked = check_loaded_psbt(session, 0, psbt)
    app = App()
    app.session = session
    app.wallet_index = 0
    app.psbt_checked = checked
    app.psbt_view = describe_psbt(session, 0, checked)
    app.psbt_outputs_open = True
    app.psbt_inputs_open = True
    app.psbt_change_open = True
    app._psbt_heights = {}
    app._psbt_sheet = None
    app.screen = "psbt-yaml"
    assert len(app.psbt_view["outputs"]) == COUNT - 1
    assert len(app.psbt_view["change_outputs"]) == 1
    assert app.psbt_view["change_outputs"][0]["place"] == "Change Address #0"
    assert len(app.psbt_view["inputs"]) == COUNT
    out_addresses = [card["address"] for card in app.psbt_view["outputs"]]
    assert len(set(out_addresses)) == COUNT - 1
    assert out_addresses[0] == EXTERNAL_P2WPKH

    # Closed sections put the Inputs row at the bottom of a long column. The
    # row is one part, so the label stays with the chevron.
    app.psbt_outputs_open = False
    app.psbt_inputs_open = False
    app.psbt_txid_open = False
    app._psbt_sheet = None
    app.scroll["psbt-yaml"] = 10**9
    closed = app.render()
    inputs = next(hit for hit in app.hits if hit["action"] == "psbt-toggle-inputs")
    assert inputs["label"] == "100 Inputs"
    box = inputs["box"]
    label_ink = sum(
        1
        for y in range(max(HEADER, box[1]), min(HEIGHT, box[3]))
        for x in range(box[0] + 40, min(WIDTH, box[0] + 220))
        if closed.getpixel((x, y))[0] < 100
    )
    assert label_ink > 200, f"Inputs label missing beside chevron ({label_ink} ink)"

    app.psbt_outputs_open = True
    app.psbt_inputs_open = True
    app._psbt_sheet = None
    app.scroll["psbt-yaml"] = 0
    started = time.perf_counter()
    record.shot(app, "top")
    first_ms = (time.perf_counter() - started) * 1000
    # Warm the parts past the target, then measure a small move back that stays
    # inside the cached window so the frame is a blit, not a rebuild.
    mid = min(app.scroll_max.get("psbt-yaml", 0), 40_000)
    app.scroll["psbt-yaml"] = mid + 200
    record.shot(app, "mid-warm")
    scrolls = []
    app.scroll["psbt-yaml"] = mid + 80
    started = time.perf_counter()
    record.shot(app, "mid-drag")
    scrolls.append(("mid-drag", (time.perf_counter() - started) * 1000))
    app.scroll["psbt-yaml"] = 10**9
    record.shot(app, "bottom-warm")
    app.scroll["psbt-yaml"] = max(0, app.scroll.get("psbt-yaml", 0) - 80)
    started = time.perf_counter()
    record.shot(app, "near-bottom")
    scrolls.append(("near-bottom", (time.perf_counter() - started) * 1000))
    slow = [item for item in scrolls if item[1] > SCROLL_FRAME_S * 1000]
    assert not slow, f"first frame {first_ms:.0f} ms, scroll {scrolls}"

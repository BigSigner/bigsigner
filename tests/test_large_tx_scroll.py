"""A native-segwit transaction large enough to scroll, still under the standard weight.

Run it on the panel's computer the same way as the other tests. It saves stills
and checks that a scroll frame stays under half a second. Set nothing special
for a laptop. On the Pi, run pytest there after the app tree is copied over.

Committed binaries for the built PSBTs live in ``tests/vectors/``. Rebuild them
with ``write_psbt_vectors`` when the builders below change.
"""

import time
from hashlib import sha256
from pathlib import Path
from random import Random

from embit.psbt import DerivationPath, PSBT
from embit.script import address_to_scriptpubkey
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from bigsigner.psbt_check import MAX_STANDARD_TX_WEIGHT, check_loaded_psbt
from bigsigner.psbt_review import ReviewError, _tx_weight
from bigsigner.psbt_view import describe_psbt
from bigsigner.ui.app import App
from test_psbt_load import _child, _native, _psbt
from test_ui import ScreenRecord

COUNT = 1000
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
THOUSAND_VECTOR = VECTORS / "native_segwit_1000_in_1000_out.psbt"
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


def _native_bulk(session, count: int):
    """``count`` native-segwit inputs spending to ``count`` external outputs."""
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    vins = [
        TransactionInput(txid, 0, sequence=0xFFFFFFFD)
        for txid in _prev_txids(count, label=f"native-bulk-{count}")
    ]
    vouts = [TransactionOutput(50_000, destination) for _ in range(count)]
    tx = Transaction(version=2, vin=vins, vout=vouts)
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(100_000, script)
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


def write_psbt_vectors(folder: Path | None = None) -> list[Path]:
    """Write the committed PSBT binaries. Returns the paths that were written."""
    folder = VECTORS if folder is None else folder
    folder.mkdir(parents=True, exist_ok=True)
    session = _native()
    written = []
    for path, psbt in (
        (folder / MEDIUM_VECTOR.name, _native_medium(session)),
        (folder / THOUSAND_VECTOR.name, _native_bulk(session, COUNT)),
    ):
        path.write_bytes(psbt.serialize())
        written.append(path)
    return written


def _weight(session, count: int) -> int:
    destination = address_to_scriptpubkey(EXTERNAL_P2WPKH)
    vins = [
        TransactionInput(txid, 0)
        for txid in _prev_txids(count, label=f"native-weight-{count}")
    ]
    vouts = [TransactionOutput(50_000, destination) for _ in range(count)]
    tx = Transaction(version=2, vin=vins, vout=vouts)
    return _tx_weight(tx, session.wallets[0])


def test_a_transaction_over_100000_vb_is_refused():
    session = _native()
    small = _psbt(session)
    assert _tx_weight(small.tx, session.wallets[0]) <= MAX_STANDARD_TX_WEIGHT
    assert check_loaded_psbt(session, 0, small).tx.version == 2

    count = COUNT
    while _weight(session, count) <= MAX_STANDARD_TX_WEIGHT:
        count += 50
    heavy = _native_bulk(session, count)
    try:
        check_loaded_psbt(session, 0, heavy)
    except ReviewError as exc:
        assert "400000 weight units" in str(exc)
    else:
        raise AssertionError("weight")


def test_the_committed_psbt_vectors_match_the_builders():
    session = _native()
    assert MEDIUM_VECTOR.is_file(), f"missing {MEDIUM_VECTOR}"
    assert THOUSAND_VECTOR.is_file(), f"missing {THOUSAND_VECTOR}"
    assert MEDIUM_VECTOR.read_bytes() == _native_medium(session).serialize()
    assert THOUSAND_VECTOR.read_bytes() == _native_bulk(session, COUNT).serialize()


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


def test_a_thousand_native_segwit_payments_scroll_smoothly():
    record = ScreenRecord(Path("artifacts/screenshots") / "test_a_thousand_native_segwit_payments_scroll_smoothly")
    session = _native()
    psbt = PSBT.parse(THOUSAND_VECTOR.read_bytes())
    wallet = session.wallets[0]
    weight = _tx_weight(psbt.tx, wallet)
    record.note(
        f"Native-segwit to external native-segwit, {COUNT} inputs and {COUNT} outputs, "
        f"{weight} weight units. Scroll frames must stay under {int(SCROLL_FRAME_S * 1000)} ms."
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
    app.screen = "psbt-yaml"
    assert len(app.psbt_view["outputs"]) == COUNT
    assert len(app.psbt_view["inputs"]) == COUNT

    app.scroll["psbt-yaml"] = 0
    started = time.perf_counter()
    record.shot(app, "top")
    first_ms = (time.perf_counter() - started) * 1000
    scrolls = []
    for name, offset in (("outputs", 80_000), ("inputs", 10**9)):
        app.scroll["psbt-yaml"] = offset
        started = time.perf_counter()
        record.shot(app, name)
        scrolls.append((name, (time.perf_counter() - started) * 1000))
    slow = [item for item in scrolls if item[1] > SCROLL_FRAME_S * 1000]
    assert not slow, f"first frame {first_ms:.0f} ms, scroll {scrolls}"

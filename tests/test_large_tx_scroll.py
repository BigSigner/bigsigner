"""A native-segwit transaction large enough to scroll, still under the standard weight.

Run it on the panel's computer the same way as the other tests. It saves stills
and checks that a scroll frame stays under half a second. Set nothing special
for a laptop. On the Pi, run pytest there after the app tree is copied over.
"""

import time
from pathlib import Path

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
# The panel logs a frame of 500 ms or more as slow.
SCROLL_FRAME_S = 0.5


def _native_bulk(session, count: int):
    """``count`` native-segwit inputs spending to ``count`` native-segwit outputs."""
    fingerprint, child, path = _child(session, branch=0, index=0)
    script = address_to_scriptpubkey(session.addresses(0, 0, 0, 1)[0])
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    vins = [
        TransactionInput(index.to_bytes(32, "little"), 0, sequence=0xFFFFFFFD)
        for index in range(count)
    ]
    vouts = [TransactionOutput(50_000, destination) for _ in range(count)]
    tx = Transaction(version=2, vin=vins, vout=vouts)
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(100_000, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        inp.sighash_type = SIGHASH.ALL
    return psbt


def _weight(session, count: int) -> int:
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    vins = [TransactionInput(index.to_bytes(32, "little"), 0) for index in range(count)]
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


def test_a_thousand_native_segwit_payments_scroll_smoothly():
    record = ScreenRecord(Path("artifacts/screenshots") / "test_a_thousand_native_segwit_payments_scroll_smoothly")
    session = _native()
    psbt = _native_bulk(session, COUNT)
    wallet = session.wallets[0]
    weight = _tx_weight(psbt.tx, wallet)
    record.note(
        f"Native-segwit to native-segwit, {COUNT} inputs and {COUNT} outputs, "
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

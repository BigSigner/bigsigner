# PSBT test vectors

Binary PSBTs used by the large-transaction tests and by the panel load demos.
Rebuild them from the builders in `tests/test_large_tx_scroll.py` when those
builders change:

```bash
cd /path/to/bigsigner
PYTHONPATH=src:tests .venv/bin/python - <<'PY'
from pathlib import Path
from test_large_tx_scroll import write_psbt_vectors
print(write_psbt_vectors(Path("tests/vectors")))
PY
```

## Run the 100-to-100 example

`native_segwit_100_in_100_out.psbt` is 100 Abandon native-segwit inputs paying
100 times to the LEGAL seed's first receive address. BigSigner refuses more
than 100 inputs or 100 outputs.

### Headless scroll timing (laptop)

Uses the desktop `.venv` (same Python stack you develop against). It does not
drive the panel; it paints frames in memory and checks that a scroll blit stays
under 500 ms.

```bash
cd /path/to/bigsigner
PYTHONPATH=src:tests .venv/bin/pytest tests/test_large_tx_scroll.py -k hundred -v
```

Screenshots go to
`artifacts/screenshots/test_a_hundred_native_segwit_payments_scroll_smoothly/`.

### Live panel on the Raspberry Pi

`seedsigner stop` frees the panel, then this script *is* the panel process
(framebuffer + touch). Only one process may own touch. After the auto-scroll it
prints that the test finished and leaves Transaction Signing interactive so you
can tap and scroll. Ctrl-C quits and runs `seedsigner start` (a fresh normal
app). That is on the device; it has nothing to do with the desktop `.venv`.

The demo loads the Abandon test mnemonic only. Do not sign with a real seed.

`docs/scripts/rsync-to-seedsigner.sh` (in the sibling `bigsigner-os` repo) copies
the app to `/mnt/data/seedsigner` but **excludes** `tests/`. Sync the app, copy
the demo files, stop the normal service, then run the demo.

```bash
# From bigsigner-os — copies src/ and restarts the panel.
docs/scripts/rsync-to-seedsigner.sh --restart ~/private_workspace/bigsigner

# Open the shared SSH session (host key file: ~/.ssh/seedsigner_known_hosts).
docs/scripts/ssh-seedsigner.sh true

# tests/ was not in the app rsync — copy the vector and the live-panel demo.
rsync -avz \
  -e 'ssh -o ControlPath=/tmp/seedsigner-ssh.sock -o UserKnownHostsFile='"$HOME"'/.ssh/seedsigner_known_hosts -o LogLevel=ERROR' \
  ~/private_workspace/bigsigner/tests/panel_show_hundred_psbt.py \
  ~/private_workspace/bigsigner/tests/vectors \
  root@seedsigner.local:/mnt/data/seedsigner/tests/

# Free the framebuffer, then run the demo.
docs/scripts/ssh-seedsigner.sh \
  'seedsigner stop; killall python3 2>/dev/null || true; sleep 1'
docs/scripts/ssh-seedsigner.sh \
  'cd /mnt/data/seedsigner && PYTHONPATH=src:tests PYTHONUNBUFFERED=1 \
   python3 tests/panel_show_hundred_psbt.py'
```

Watch `dmesg | grep bigsigner` for progress and slow-frame lines while it loads.

| File | Contents |
|------|----------|
| `native_segwit_100_in_1_external_1_change.psbt` | 100 Abandon native-segwit inputs, one payment to the LEGAL seed's first receive address, one change output back to Abandon, fee 10000 sats (0.0001 BTC). Previous txids are distinct seeded-random 32-byte values (never the zero hash). |
| `native_segwit_100_in_100_out.psbt` | 100 Abandon native-segwit inputs paying 100 times to the LEGAL seed's first receive address (50000 sats each). The first input is 100000 sats and the rest are 50000, so the fee is 50000 sats (under the high-fee warning). Previous txids are distinct seeded-random values as above. |

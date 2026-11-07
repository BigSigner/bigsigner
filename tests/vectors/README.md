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

| File | Contents |
|------|----------|
| `native_segwit_100_in_1_external_1_change.psbt` | 100 Abandon native-segwit inputs, one payment to the LEGAL seed's first receive address, one change output back to Abandon, fee 10000 sats (0.0001 BTC). Previous txids are distinct seeded-random 32-byte values (never the zero hash). |
| `native_segwit_1000_in_1000_out.psbt` | 1000 Abandon native-segwit inputs paying 1000 times to the LEGAL seed's first receive address. Previous txids are distinct seeded-random values as above. |

# PSBT test vectors

Binary PSBTs used by the large-transaction tests, output-security tests, and
panel load demos. Rebuild them from `tests/test_large_tx_scroll.py` and
`tests/psbt_output_vectors.py` when their builders change:

```bash
cd /path/to/bigsigner
PYTHONPATH=src:tests .venv/bin/python - <<'PY'
from pathlib import Path
from test_large_tx_scroll import write_psbt_vectors
from psbt_output_vectors import write_multisig_payment_vectors, write_spoofed_change_vectors
print(write_psbt_vectors(Path("tests/vectors")))
print(write_spoofed_change_vectors(Path("tests/vectors")))
print(write_multisig_payment_vectors(Path("tests/vectors")))
PY
```

## Run the 100-to-100 example

`native_segwit_100_in_100_out.psbt` is 100 Abandon native-segwit inputs paying
99 distinct LEGAL receive addresses (indexes 0–98) and one change output back
to Abandon. BigSigner refuses more than 100 inputs or 100 outputs.

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
can tap and scroll. Type `r` and Enter to quit and run `seedsigner start` (a
fresh normal app). Ctrl-C on the laptop often kills only SSH and leaves the
demo running on the device — prefer `r`. That is on the device; it has nothing
to do with the desktop `.venv`.

The demo loads the Abandon test mnemonic only. Do not sign with a real seed.

`docs/scripts/rsync-to-seedsigner.sh` (in the sibling `bigsigner-os` repo) copies
the app to `/mnt/data/seedsigner` but **excludes** `tests/`. Sync the app, copy
the demo files, stop the normal service, then run the demo with a TTY so `r`
reaches the process.

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

# Free the framebuffer, then run the demo (-t keeps stdin for "r").
docs/scripts/ssh-seedsigner.sh \
  'seedsigner stop; killall python3 2>/dev/null || true; sleep 1'
ssh -t \
  -o ControlPath=/tmp/seedsigner-ssh.sock \
  -o UserKnownHostsFile="$HOME/.ssh/seedsigner_known_hosts" \
  -o LogLevel=ERROR \
  root@seedsigner.local \
  'cd /mnt/data/seedsigner && PYTHONPATH=src:tests PYTHONUNBUFFERED=1 \
   python3 -u tests/panel_show_hundred_psbt.py'
```

Without a TTY, `docs/scripts/rpc.sh r` also quits the demo (same `r` line).

Watch `dmesg | grep bigsigner` for progress and slow-frame lines while it loads.

| File | Contents |
|------|----------|
| `native_segwit_100_in_1_external_1_change.psbt` | 100 Abandon native-segwit inputs, one payment to the LEGAL seed's first receive address, one change output back to Abandon, fee 10000 sats (0.0001 BTC). Previous txids are distinct seeded-random 32-byte values (never the zero hash). |
| `native_segwit_100_in_100_out.psbt` | 100 Abandon native-segwit inputs paying 99 distinct LEGAL receive addresses (indexes 0–98) and one change output to Abandon change address #0 (50000 sats each). The first input is 100000 sats and the rest are 50000, so the fee is 50000 sats (under the high-fee warning). Previous txids are distinct seeded-random values as above. |
| `native_segwit_combined_warnings.psbt` | Abandon native-segwit spend that surfaces every Transaction Signing warning together: paid OP_RETURN, high fee, timestamp locktime, relative locktimes (block and time, including `0x0040FFFF`), RBF-disabled inputs, more than one change output, and change on a receive address. Eight inputs at Abandon receive #0; payment to LEGAL receive #0; change to Abandon change #0 and receive #1. |
| `native_segwit_hidden_change_120.psbt` | One Abandon native-segwit input (receive #0, with its derivation) paying the LEGAL seed's first receive address and Abandon change address #120. The second output has no derivation metadata. Address Search finds Change Address #120 in account 0. Fee is 10000 sats. |
| `native_segwit_hidden_account3_receive_120.psbt` | The same input and first output as the hidden-change vector. The second output pays 40000 sats to Abandon Native-Segwit SingleSig account 3, receive address #120 (`m/84h/0h/3h/0/120`), with no derivation metadata. Include account 3 in the search range. Fee is 10000 sats. |
| `native_segwit_hidden_taproot_receive_120.psbt` | The same native-segwit input and first output as the hidden-change vector. The second output pays 40000 sats to Abandon Taproot SingleSig account 0, receive address #120 (`m/86h/0h/0h/0/120`), with no derivation metadata. Load both Abandon Native-Segwit and Taproot SingleSig wallets to find it. Fee is 10000 sats. |
| `native_segwit_spoofed_change.psbt` | Malicious SingleSig change claim: the second output supplies Abandon's genuine account-0 Receive #120 public key, fingerprint, and path, but pays LEGAL's Receive #120 address instead. Must fail validation. |
| `native_segwit_spoofed_account1_receive_120.psbt` | Spends from Abandon Native-Segwit SingleSig account 0, while the second output supplies Abandon's genuine account-1 Receive #120 public key, fingerprint, and path. The actual destination is LEGAL's account-0 Receive #120 address. Must show the spoofing error with (on a different account). |
| `native_segwit_multisig_2of3_spoofed_change.psbt` | Malicious 2-of-3 MultiSig change claim: the second output supplies the genuine Abandon/LEGAL/ZOO public keys, fingerprints, account-0 Receive #120 paths, and witness script, but pays a different 2-of-3 wallet instead. Must fail validation. |
| `native_segwit_multisig_2of3_to_abandon.psbt` | Unsigned spend from the shared 2-of-3 wallet: one 100000-sat Receive #0 input pays 50000 sats to Abandon Native-Segwit SingleSig account-0 Receive #0 and returns 40000 sats to MultiSig Change #0. Fee is 10000 sats. Full origins and witness scripts are supplied. |
| `native_segwit_multisig_2of3_to_abandon_signed_by_legal.psbt` | The same transaction and metadata as the unsigned vector, with one valid SIGHASH_ALL partial signature from LEGAL (`b8688df1`). One additional participant signature is required. Abandon can supply it. |

## Shared 2-of-3 MultiSig wallet

All 2-of-3 MultiSig vectors use the same wallet. Load the Abandon test seed and import
[this complete wallet descriptor](native_segwit_multisig_2of3_descriptor.txt).
It is `wsh(sortedmulti(2,...))`, with three distinct participants at
`m/48h/0h/0h/2h`, all on account 0:

| Participant | Fingerprint | Test mnemonic, without a passphrase |
| --- | --- | --- |
| Abandon | `73c5da0a` | `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about` |
| LEGAL | `b8688df1` | `legal winner thank year wave sausage worth useful legal winner thank yellow` |
| ZOO | `3f635a63` | `zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong` |


## MultiSig payments to Abandon

Select the shared MultiSig wallet with all participant accounts set to 0.
Both payment vectors spend 100000 sats from its Receive Address #0
(`m/48h/0h/0h/2h/0/0` on every participant), then create:

- Output 0: 50000 sats to Abandon Native-Segwit SingleSig account 0, Receive
  Address #0 (`m/84h/0h/0h/0/0`), address
  `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`.
- Output 1: 40000 sats back to the shared MultiSig wallet, account sequence
  `0, 0, 0`, Change Address #0 (`m/48h/0h/0h/2h/1/0` on every participant),
  address `bc1qc6p3lpt2e2wv0vukgyykx3ca8fhy6pvlfg7sgv8e3qej473jjmxs29860y`.

The fee is 10000 sats. Both outputs include their genuine public keys,
fingerprints, and derivation paths. The input and change output include the
MultiSig witness script. Only output 1 belongs in Change Outputs, even though
Abandon also participates in the spending wallet. Loading Abandon's SingleSig
wallet lets output 0 show its wallet and Receive address details.

The unsigned vector has no signatures. The signed-by-LEGAL variant differs
only by LEGAL's partial signature for its input key at
`[b8688df1/48h/0h/0h/2h/0/0]`. It is not fully signed: its 2-of-3 policy still
needs one more participant. With only the Abandon seed loaded, BigSigner
shows one available signer and can add that second signature to complete the
transaction. The ZOO seed is not required for that flow.

These are synthetic mainnet test transactions with placeholder previous
transaction ids, for reviewing and signing tests.

## Malicious change claims

All spoofed-change vectors are mainnet PSBTs with one genuine account-0 Receive #0 input
of 100000 sats, an external output of 50000 sats, a forged change claim of
40000 sats, and a fee of 10000 sats. Their second outputs claim Receive
addresses: either branch is allowed as change only after proving ownership.
All must be refused. For a claim on the spending account, the error is:

> An output claims to belong to this wallet, but its address does not match the supplied derivation path. This may be an attempt to spoof a change output.

For the SingleSig vector, load Abandon's Native-Segwit SingleSig wallet at
account 0. The claimed second-output path is `[73c5da0a/84h/0h/0h/0/120]`.
It would derive `bc1qf3pezulgknrzdcqjplgkuxuexm8luls0nnqwqt`, but the actual
output is `bc1q54s4c2r84y22gmf5cdk5vlvgteunu3na0lk0dj`.

The account-1 SingleSig variant uses the same account-0 input, amounts, and
actual destinations. Its second output supplies fingerprint `73c5da0a` and
the genuine public key for `m/84h/0h/1h/0/120`. Load the Abandon Native-Segwit
SingleSig wallet with account 0 selected. That path would derive
`bc1qs400nup03z5xnhac44m8nhy2xvjreshlay7mvc`, but the actual output remains
`bc1q54s4c2r84y22gmf5cdk5vlvgteunu3na0lk0dj`. The mismatched address must trigger:

> An output claims to belong to this wallet (on a different account), but its address does not match the supplied derivation path. This may be an attempt to spoof a change output.

It must not merely be treated as a payment to another account. A genuine matching account-1 address would instead remain
under Outputs with account-1 address information.

The MultiSig spoofing vector uses the shared wallet described above.

The second output claims `/0/120` on all three keys. Its genuine wallet
address would be
`bc1qxduc9wusy09qfq0z48jzl2au070ujkmycx872xzl03wc7zzlsm2s8tg5up`,
but the actual output is
`bc1qkypqx2vnhfk93jz665j4494nrd2yx2x2vvam97snhvdr7w8fs0as5nz52g`.
That address belongs to a different 2-of-3 wallet using LEGAL, ZOO, and
fingerprint `e6157603` (the test mnemonic
`bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal century`).
It excludes Abandon. The supplied output public keys and paths are genuine
for the selected wallet; comparing them alone is insufficient. The locking
script must match too. None of these test mnemonics should hold real funds.

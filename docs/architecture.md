# Architecture

BigSigner is one Python package in `src/bigsigner`. The browser emulator and the Raspberry Pi panel both drive `ui.app.App`. Keys and wallets live in a `Session` and are not written to disk. Nothing is stored unless the user explicitly exports a file.

`SPEC.md` says what the product does. This page says where that behavior lives.

## How it starts

`src/main.py` is the file BigSigner OS runs. It calls `bigsigner.__main__.main`. That runs `hardware.panel.run_panel` when `/dev/fb0` is present. The panel copies each 480×800 image to the framebuffer and reads evdev. After a tap action, the display host calls `App.frame_presented` once the resulting image has reached the display. The panel then drains queued digitizer bytes with `flush_touch` and starts a fixed 250 ms guard using the current monotonic clock. Ignored input and scroll redraws do not restart it. Deferred work (Searching addresses, Signing…, and PSBT loading) also guards its final result. The browser waits for image decoding and paint, starts the same guard, and drops queued pointer events captured against the previous frame. Headless tests can call `frame_presented` explicitly to test display timing without adding real waits to ordinary screen tests.

`BIGSIGNER_RPC` is a pipe of command lines. The panel creates `/tmp/bigsigner-rpc` and listens when it starts. `off` disables that. Each line starts with a command word. `addseed`, for example, is followed by the mnemonic. A 13th, 19th, or 25th word is the passphrase. A seed that is already loaded is left as it is. `tap x y` is a finger down and a finger up. `tapdown`, `tapmove`, and `tapup` are those phases, each followed by `x y`. The panel runs that command when the line arrives and checks an `addseed` line there. `python -m bigsigner.rpc` writes the line as it was typed. On a dev board, bigsigner-os `docs/scripts/rpc.sh` sends it through SSH to the running panel. Do not enable it on a device that holds real funds.

`web/index.html` is the browser front. `python -m bigsigner.bundle` writes `web/bundle.json`, a copy of `src/` with `.DS_Store` and bytecode left out, and downloads the pinned Pyodide runtime, Pillow, embit, and qrcode into `web/external-assets`. Neither is committed. Serve the `web/` directory, then reload the page after each new bundle. The worker loads Pyodide, Pillow, embit, and qrcode from their folders there, unpacks the bundle, and drives the same `App`. The bundle command is what checks each file's SHA-256. `render` paints the picture. Taps call the same pointer methods the panel uses. The hash is a query string: `seed` is the mnemonic, commas count as spaces, `descriptor` is the wallet descriptor, and `network` is `mainnet`, `testnet`, or `regtest`. `seed` is applied as `BIGSIGNER_INITIAL_SEED` inside the page. `network` is applied when the boot screen ends, before the seed and the descriptor. Without it, the network is mainnet. `descriptor` is loaded after that. The SD Card section stores files in the browser. `mount_memory` in `sdcard.py` makes Load from File read them. On the panel, with no memory card, those helpers use the FAT volume at `/mnt/microsd` instead.

## Session

`session.py` is the in-memory model.

- A fingerprint maps to one `FingerprintRecord`. The record holds the keys that share it.
- A key is a BIP39 seed, a seed plus passphrase, or a watch-only key expression (singlesig native SegWit, singlesig Taproot, or native-SegWit multisig).
- `key_counter` increases each time a key is added. Seed cards on Bitcoin Keys follow that number. External keys are one card each, grouped into SingleSig External Keys and MultiSig External Keys, and sorted by fingerprint nickname, then Native-Segwit before Taproot, then account.
- Passphrases are remembered as text mapped to a number, so two seeds that share a passphrase show the same number.
- Adding a seed compares it with keys already stored for that fingerprint. A different seed with the same fingerprint is refused. A watch-only key that the new seed can derive is dropped as redundant. A watch-only key whose extended key does not match the seed is refused.
- `prepare_external_key` checks a key expression and does not store it. `commit_external_key` stores it after the review screens.

Wallets are descriptors built from those keys. Changing the network drops wallets and watch-only keys. Seeds stay.

## Naming, parsing, and Bitcoin operations

| Module | Role |
| --- | --- |
| `names.py` | Fingerprint name. See [fingerprint-names.md](fingerprint-names.md). |
| `parse.py` | Key expressions and wallet descriptors. A multisig `wsh(sortedmulti(...))` accepts 2 through 15 keys (`MAX_MULTISIG_KEYS`); m-of-15 is the maximum. |
| `paths.py` | The three supported derivation templates and the network coin type. `path_network_mismatch` names both networks only after validating the rest of the account or address path; import, PSBT, and message-signing checks preserve that explanation. |
| `slip132.py` | `zpub`, `Zpub`, `vpub`, and `Vpub`, converted to `xpub` or `tpub` before comparison. |
| `bsms.py` | A BSMS 1.0 file, reduced to its descriptor. |
| `descriptor_files.py` | A Specter-DIY JSON export or a Bitcoin Core descriptor file, reduced to its descriptor. |
| `scan.py` | One scanned or loaded string: mnemonic, SeedQR, key expression, or descriptor. |
| `seedqr.py` | Standard and compact SeedQR. |
| `entropy.py` | Dice, coin, and camera entropy, following SeedSigner. |
| `psbt_load.py` | Read a PSBT from base64, base43, the BIP 174 binary file, Specter parts, UR, or BBQr. |
| `psbt_check.py` | Refuse a PSBT this signer will not sign, including more than 100 inputs or outputs and over-weight transactions. |
| `psbt_view.py` | The Transaction Signing text: amounts, warnings, outputs, fee, locktime, and inputs. |
| `address_search.py` | Plan account combinations, enforce the 512-branch limit, cache account/branch public keys, and search one branch descriptor per step. |
| `ui/psbt_screen.py` | Transaction Signing layout. Scroll keeps a few screen-tall tiles around the finger; a chevron toggle rebuilds them. |
| `psbt_qr.py` | QR parts for a signed PSBT: Animated UR, Static UR, base64, Specter Animated, and BBQr. |
| `psbt_review.py` | Check a PSBT against one loaded wallet, then sign with a seed that is in memory. |
| `sdcard.py` | Shared file operations select `storage="sd"` or `storage="temporary"`. SD uses `/mnt/microsd`, which must be a mount (an explicit `BIGSIGNER_SDCARD_PATH` permits a development directory). Temporary FS creates `/tmp/bigsigner` on the panel's RAM rootfs and survives app restarts until reboot. Linux hosts can fall back to `/dev/shm/bigsigner`; persistent backing is refused. Other hosts and the browser use Python memory. Virtual storage has a simulated 64 MiB capacity. Disk usage uses `statvfs`, or system RAM usage for unbounded ramfs/rootfs. Only SD writes reach browser card snapshots and persistence. |
| `licenses.py` | Notices shown from About → Licenses. |

`psbt_check._input_paths` retains all input origins for ownership diagnostics while keeping only the selected wallet’s origins for derivation and signing checks. Supported origins from an unavailable wallet report This transaction does not belong to this wallet; a matching loaded wallet is named. Invalid paths and network mismatches retain their own diagnostics.

Every input passes participant and account checks. The account mapping includes fingerprints and is independent of the order of origins. `_matches_psbt` derives one trusted descriptor per input and reuses its public keys to compare every participant's supplied key, as well as the locking script. MultiSig origins must share a branch and address index within each input; duplicate fingerprints cannot hide a missing participant. `_scripts` checks supplied witness scripts and Taproot internal-key metadata against that descriptor, and fills missing MultiSig witness scripts before signing. The older `psbt_review` entry point shares these input checks.

`_input_utxo` requires and returns the witness UTXO on every input. A full previous transaction is optional and cannot replace it. When the full transaction is present its txid and output index are checked, and its amount and script must match the witness UTXO. Ownership checks, amount display, and signing use the witness UTXO.

`psbt_check.output_ownership` is shared by output validation, `psbt_view`, and the older review entry point. It derives the complete wallet descriptor, compares the locking script and every participant public key, and checks supplied witness scripts and Taproot metadata. All participants must have consistent branches and address indexes. It tries all candidate policies, including different MultiSig thresholds with the same participants. Only a proven match to the spending wallet and complete selected account mapping qualifies as change; either branch can qualify. A complete but false wallet claim refuses the PSBT, while partial or unavailable origins remain external. A spending-wallet script mismatch uses `SPOOFED_CHANGE`, explaining that the address does not match the supplied path and may be an attempt to spoof a change output. Its `account_note` is (on a different account) when the claimed fingerprint-to-account mapping differs from the captured spending mapping. The checker, review, and output display pass that mapping explicitly so later wallet-selection changes do not alter the diagnosis.

Bitcoin operations go through embit 0.8.0, the release SeedSigner pins. Pillow draws the screen. `qr.py` builds the codes the device displays: through libqrencode when the image has it (milliseconds on a Pi Zero), otherwise through the pure-Python qrcode package (seconds). Each payload is built once and cached. A QR drawn for another device's camera has a Brightness control. It scales every pixel on that screen, including the title bar and the buttons, so the panel does not blind the camera. Black stays black.

## Screens

`ui/app.py` is the screen machine: a current screen name, a back stack, and the open menus. `ui/canvas.py` is the drawing surface, the palette, the fonts, and the button hit boxes.

The side menu reaches Bitcoin Keys, Bitcoin Wallets, Settings, and About. Every other screen has a back button. Scroll offset is stored per screen, and the title bar stays put.

Scan QR Code and Load from File buttons use the bundled Font Awesome camera and file icons before their labels. `Frame.button` draws them on full-width buttons; `_speed_dial` reserves the same icon width and gap in the plus menus. Every Load from File and export route opens the `storage` choice before the shared `sd` browser. SD Card uses the mounted card; Temporary FS uses separate RAM storage. Export browsers pin a single `Used: <used> / <total> Free: <free>` line above the directory name, with one decimal place and IEC units (KiB, MiB, GiB). Its font starts at 24px and shrinks to fit the page width. The New File button stays fixed below the list.

Seed Key (`key`) uses one row of Show and Export buttons for seeds without a passphrase. Show uses the existing privacy confirmation before `seed-show`; Export opens `seed-backup` directly and returns to the key after saving. Seeds with a passphrase retain the Show/Export button and `show-export` choice screen, including Show Passphrase.

Addresses (`addresses`) keeps a window of derived receive or change rows and drops rows far from the scroll position. Address (`address`) shows the QR, a Brightness control below it, the address in groups of four, and the derivation path starting with the fingerprint. The address sheet reserves space for the live control, so brightness changes reuse the cached QR and body while updating the control bounds and disabled states. The common brightness transform applies to the whole frame, including its fixed title bar; Back resets the setting. Verify Address searches ranges of 100 through `normalize_address_text` and `find_address`.

Transaction Signing opens Address Search (`address-search`) for an output whose derivation is unknown. The account range defaults from the lowest selected account; `Session.account_options` supplies either a seed's whole range or an external key's loaded accounts. `AddressSearch` filters by embit's decoded script type and plans every participant combination before deriving anything. It prepares public branch descriptors ending in `/*`, with the master fingerprint and full branch origin attached, so each address check derives only the final child. Supplying that origin avoids embit’s extra `child(0)` call when deriving a descriptor key without one. The regression test counts `HDKey.child` calls, including calls made internally by embit. The panel polls evdev between calls to `_advance_psbt_search`; the browser worker advances once per frame request and keeps input enabled. Unchanged steps skip painting and PNG encoding; address-index progress repaints at most every 100 ms. Stop saves the engine’s last checked index, closes the generator, and frees the cached descriptors. The screen centers the current or last searched index below a label sized to fit one row. Changing either account-range value or starting another search clears the saved index. Back closes the search before returning.

A match stays on Address Search with `psbt-found`. The pending hit holds an `output_info` scope containing public keys and full origins, separate from the PSBT. OK calls `_confirm_psbt_search`, accumulating that scope in `psbt_output_info` by output index and reloading the current PSBT through `_accept_psbt_text` with the captured `psbt_accounts`. Both synchronous and deferred hosts rerun the entire checker and rebuild the review only after success. `output_scope` fills missing participant origins, checks their binding to the actual output script, and preserves every PSBT-supplied origin and script claim. Complete PSBT origins take precedence; partial MultiSig origins can be completed by a search. Validation derives the keys and script again; the extra information is not an ownership flag. New imports clear the map, and signed-result restoration retains it. For a match in the spending wallet and account sequence, `_found_address_message` appends `: #<address_index>` to the Receive/Change notice. The hit's `index` identifies the PSBT output; `address_index` identifies the derived address. `psbt_view._output_card` classifies change only for a proven match to the spending wallet and its captured account mapping. Other recognized accounts or wallets stay in Outputs with their address information. The popup and the finished validation are guarded against queued touches.

A seed key opens Derive Key (`derive`) for one of the three supported paths. The screen derives the extended key in memory with `_public_for` and does not store it. Single-signature derivations can create or open the wallet at the selected account. Multisig derivation only shows the key. Derive a BIP85 Child Seed opens `bip85`. `session.bip85_mnemonic` asks embit for the English mnemonic at `m/83696968h/39h/0h/{12 or 24}h/{index}h`. The child is stored with `add_mnemonic`, and the back stack is replaced with Bitcoin Keys.

`scan.classify_content` names a QR payload or an SD card file: an address, a seed, a compact seed, a numeric seed, a BSMS file, a wallet descriptor, a Specter-DIY JSON export, a Bitcoin Core descriptor file, a key expression, or a transaction. The Specter and Bitcoin Core files are reduced to the descriptor they contain. The screen that asked for one kind refuses the others by that name.

Load External Key is two screens, `external-review` and `external-details`. A failed QR or SD import uses `load-error`. While a PSBT is checked, `psbt-progress` shows status text and a bar with no title. The panel sets `flush_display` so those frames appear before the check returns. The browser sets `defer_psbt_progress` so each `delay` 0 frame advances the check and paints the bar (mid-tick worker paints never show). A PSBT that fails a check uses `psbt-error`. A file that is not a PSBT stays a popup. The license list is `licenses`, and one notice is `license`.

On the Pi, `camera_preview_box` is the viewfinder rectangle for the scan and camera screens. `hardware/camera.py` fills it from picamera2 when that is installed, otherwise from the legacy picamera that bigsigner-os ships, and reads QR codes with pyzbar. Those packages come from the device image. They are not imported on a machine that is not capturing, and the emulator does not use that module. The emulator page shows the computer's camera above the panel.

## What is bundled

Fonts and icons are in `src/bigsigner/resources/`: DejaVu, Font Awesome Free, and the SeedSigner icon font. The adjective, color, and animal lists are copied into `names.py`. Their license texts are in `licenses.py` and `LICENSE`, and on the About screen.

# Architecture

BigSigner is one Python package in `src/bigsigner`. The browser emulator and the Raspberry Pi panel both drive `ui.app.App`. Keys and wallets live in a `Session` and are not written to disk. Nothing is stored unless the user explicitly exports a file.

`SPEC.md` says what the product does. This page says where that behavior lives.

## How it starts

`src/main.py` is the file BigSigner OS runs. It calls `bigsigner.__main__.main`. That runs `hardware.panel.run_panel` when `/dev/fb0` is present. The panel copies each 480×800 image to the framebuffer and reads evdev.

`BIGSIGNER_RPC` is a pipe of command lines. The panel creates `/tmp/bigsigner-rpc` and listens when it starts. `off` disables that. Each line starts with a command word. `addseed`, for example, is followed by the mnemonic. A 13th, 19th, or 25th word is the passphrase. A seed that is already loaded is left as it is. `tap x y` is a finger down and a finger up. `tapdown`, `tapmove`, and `tapup` are those phases, each followed by `x y`. The panel runs that command when the line arrives and checks an `addseed` line there. `python -m bigsigner.rpc` writes the line as it was typed. On a dev board, bigsigner-os `docs/scripts/rpc.sh` sends it through SSH to the running panel. Do not enable it on a device that holds real funds.

`web/index.html` is the browser front. `python -m bigsigner.bundle` writes `web/bundle.json`, a copy of `src/` with `.DS_Store` and bytecode left out, and downloads the pinned Pyodide runtime, Pillow, embit, and qrcode into `web/external-assets`. Neither is committed. Serve the `web/` directory, then reload the page after each new bundle. The worker loads Pyodide, Pillow, embit, and qrcode from their folders there, unpacks the bundle, and drives the same `App`. The bundle command is what checks each file's SHA-256. `render` paints the picture. Taps call the same pointer methods the panel uses. The hash is a query string: `seed` is the mnemonic, commas count as spaces, `descriptor` is the wallet descriptor, and `network` is `mainnet`, `testnet`, or `regtest`. `seed` is applied as `BIGSIGNER_INITIAL_SEED` inside the page. `network` is applied when the boot screen ends, before the seed and the descriptor. Without it, the network is mainnet. `descriptor` is loaded after that. The SD Card section stores files in the browser. `mount_memory` in `sdcard.py` makes Load from SD Card read them.

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
| `parse.py` | Key expressions and wallet descriptors. |
| `paths.py` | The three supported derivation templates and the network coin type. |
| `slip132.py` | `zpub`, `Zpub`, `vpub`, and `Vpub`, converted to `xpub` or `tpub` before comparison. |
| `bsms.py` | A BSMS 1.0 file, reduced to its descriptor. |
| `descriptor_files.py` | A Specter-DIY JSON export or a Bitcoin Core descriptor file, reduced to its descriptor. |
| `scan.py` | One scanned or loaded string: mnemonic, SeedQR, key expression, or descriptor. |
| `seedqr.py` | Standard and compact SeedQR. |
| `entropy.py` | Dice, coin, and camera entropy, following SeedSigner. |
| `psbt_load.py` | Read a PSBT from base64, base43, the BIP 174 binary file, Specter parts, UR, or BBQr. |
| `psbt_check.py` | Refuse a PSBT this signer will not sign. |
| `psbt_view.py` | The Transaction Signing text: amounts, warnings, outputs, fee, locktime, and inputs. |
| `psbt_qr.py` | QR parts for a signed PSBT: Animated UR, Static UR, base64, Specter Animated, and BBQr. |
| `psbt_review.py` | Check a PSBT against one loaded wallet, then sign with a seed that is in memory. |
| `sdcard.py` | The SD card kept in memory. The browser page and the tests mount that card. |
| `licenses.py` | Notices shown from About → Licenses. |

Bitcoin operations go through embit 0.8.0, the release SeedSigner pins. Pillow draws the screen. `qr.py` builds the codes the device displays: through libqrencode when the image has it (milliseconds on a Pi Zero), otherwise through the pure-Python qrcode package (seconds). Each payload is built once and cached. A QR drawn for another device's camera has a Brightness control. It scales every pixel on that screen, including the title bar and the buttons, so the panel does not blind the camera. Black stays black.

## Screens

`ui/app.py` is the screen machine: a current screen name, a back stack, and the open menus. `ui/canvas.py` is the drawing surface, the palette, the fonts, and the button hit boxes.

The side menu reaches Bitcoin Keys, Bitcoin Wallets, Settings, and About. Every other screen has a back button. Scroll offset is stored per screen, and the title bar stays put.

Addresses (`addresses`) keeps a window of derived receive or change rows and drops rows far from the scroll position. Address (`address`) shows the QR, the address in groups of four, and the derivation path starting with the fingerprint. Verify Address searches ranges of 100 through `normalize_address_text` and `find_address`.

A seed key opens Derive Key (`derive`) for one of the three supported paths. The screen derives the extended key in memory with `_public_for` and does not store it. Single-signature derivations can create or open the wallet at the selected account. Multisig derivation only shows the key. Derive a BIP85 Child Seed opens `bip85`. `session.bip85_mnemonic` asks embit for the English mnemonic at `m/83696968h/39h/0h/{12 or 24}h/{index}h`. The child is stored with `add_mnemonic`, and the back stack is replaced with Bitcoin Keys.

`scan.classify_content` names a QR payload or an SD card file: an address, a seed, a compact seed, a numeric seed, a BSMS file, a wallet descriptor, a Specter-DIY JSON export, a Bitcoin Core descriptor file, a key expression, or a transaction. The Specter and Bitcoin Core files are reduced to the descriptor they contain. The screen that asked for one kind refuses the others by that name.

Load External Key is two screens, `external-review` and `external-details`. A failed QR or SD import uses `load-error`. A PSBT that fails a check uses `psbt-error`. A file that is not a PSBT stays a popup. The license list is `licenses`, and one notice is `license`.

On the Pi, `camera_preview_box` is the viewfinder rectangle for the scan and camera screens. `hardware/camera.py` fills it from picamera2 when that is installed, otherwise from the legacy picamera that bigsigner-os ships, and reads QR codes with pyzbar. Those packages come from the device image. They are not imported on a machine that is not capturing, and the emulator does not use that module. The emulator page shows the computer's camera above the panel.

## What is bundled

Fonts and icons are in `src/bigsigner/resources/`: DejaVu, Font Awesome Free, and the SeedSigner icon font. The adjective, color, and animal lists are copied into `names.py`. Their license texts are in `licenses.py` and `LICENSE`, and on the About screen.

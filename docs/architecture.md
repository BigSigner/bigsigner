# Architecture

BigSigner is one Python package in `src/bigsigner`. The browser emulator and the Raspberry Pi panel both drive `ui.app.App`. Keys and wallets live in a `Session` and are not written to disk. Nothing is stored unless the user explicitly exports a file.

`SPEC.md` says what the product does. This page says where that behavior lives.

## How it starts

`src/main.py` is the file BigSigner OS runs. It calls `bigsigner.__main__.main`. That runs `hardware.panel.run_panel` when `/dev/fb0` is present. The panel copies each 480×800 image to the framebuffer and reads evdev.

`web/index.html` is the browser front. `python -m bigsigner.bundle` writes `web/bundle.json`, a copy of `src/` with `.DS_Store` and bytecode left out. That file is not committed. Serve the `web/` directory, then reload the page after each new bundle. The page loads Pyodide, checks the SHA-256 of the embit archive and the qrcode wheel, unpacks the bundle, and drives the same `App`. `render` paints the picture. Taps call the same pointer methods the panel uses. The hash is a query string: `seed` is the mnemonic, commas count as spaces, and `descriptor` is the wallet descriptor. Those replace `BIGSIGNER_INITIAL_SEED` and `BIGSIGNER_INITIAL_WALLET_DESCRIPTOR` on that page. The SD Card section stores files in the browser. `mount_memory` in `sdcard.py` makes Load from SD Card read them. The page does not use `BIGSIGNER_SDCARD_PATH`.

## Session

`session.py` is the in-memory model.

- A fingerprint maps to one `FingerprintRecord`. The record holds the keys that share it.
- A key is a BIP39 seed, a seed plus passphrase, or a watch-only key expression (single-sig native SegWit, single-sig Taproot, or native-SegWit multisig).
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
| `scan.py` | One scanned or loaded string: mnemonic, SeedQR, key expression, or descriptor. |
| `seedqr.py` | Standard and compact SeedQR. |
| `entropy.py` | Dice, coin, and camera entropy, following SeedSigner. |
| `psbt_review.py` | Check a PSBT against one loaded wallet, then sign with a seed that is in memory. |
| `sdcard.py` | Read the microSD card. A process uses the `BIGSIGNER_SDCARD_PATH` folder. The browser page mounts the card kept beside the picture. |
| `licenses.py` | Notices shown from About → Licenses. |

Bitcoin operations go through embit 0.8.0, the release SeedSigner pins. Pillow draws the screen. `qr.py` builds the codes the device displays: through libqrencode when the image has it (milliseconds on a Pi Zero), otherwise through the pure-Python qrcode package (seconds). Each payload is built once and cached.

## Screens

`ui/app.py` is the screen machine: a current screen name, a back stack, and the open menus. `ui/canvas.py` is the drawing surface, the palette, the fonts, and the button hit boxes.

The side menu reaches Bitcoin Keys, Bitcoin Wallets, Settings, and About. Every other screen has a back button. Scroll offset is stored per screen, and the title bar stays put.

A seed key opens Derive Key (`derive`) for one of the three supported paths. The screen derives the extended key in memory with `_public_for` and does not store it. Single-signature derivations can create or open the wallet at the selected account. Multisig derivation only shows the key.

Load External Key is two screens, `external-review` and `external-details`. A failed QR or SD import uses `load-error`. The license list is `licenses`, and one notice is `license`.

On the Pi, `camera_preview_box` is the viewfinder rectangle for the scan and camera screens. `hardware/camera.py` fills it from picamera2 when that is installed, otherwise from the legacy picamera that bigsigner-os ships, and reads QR codes with pyzbar. Those packages come from the device image. They are not imported on a machine that is not capturing, and the emulator does not use that module. The emulator page shows the computer's camera above the panel.

## What is bundled

Fonts and icons are in `src/bigsigner/resources/`: DejaVu, Font Awesome Free, and the SeedSigner icon font. The adjective, color, and animal lists are copied into `names.py`. Their license texts are in `licenses.py` and `LICENSE`, and on the About screen.

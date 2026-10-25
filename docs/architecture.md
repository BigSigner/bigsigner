# Architecture

BigSigner is one Python package in `src/bigsigner`. The browser emulator and the Raspberry Pi panel both drive `ui.app.App`. Keys and wallets live in a `Session` and are not written to disk. Nothing is stored unless the user explicitly exports a file.

`SPEC.md` says what the product does. This page says where that behavior lives.

## How it starts

`src/main.py` is the file BigSigner OS runs. It calls `bigsigner.__main__.main`. `__main__.py` chooses the front end. `BIGSIGNER_EMULATOR=1`, or a machine with no `/dev/fb0`, starts `emulator.server.serve`. The default port is 8765. Otherwise `hardware.panel.run_panel` opens the HDMI framebuffer and the touchscreen. In the emulator's terminal, `r` replaces the process with `python -m bigsigner` on the same port, so the new session imports the code from disk. The environment variables stay.

Both fronts call the same `App`. `render` paints a 480×800 image. `tap` hits the buttons recorded during that paint. The emulator serves that image and posts taps back. The panel copies the image to `/dev/fb0` and reads evdev.

## Session

`session.py` is the in-memory model.

- A fingerprint maps to one `FingerprintRecord`. The record holds the keys that share it.
- A key is a BIP39 seed, a seed plus passphrase, or a watch-only key expression (single-sig native SegWit, single-sig Taproot, or native-SegWit multisig).
- `key_counter` increases each time a key is added. The Bitcoin Keys screen sorts cards by that number inside Seeds and inside External Keys.
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
| `sdcard.py` | Read the microSD card. The emulator uses the `BIGSIGNER_SDCARD_PATH` folder. |
| `licenses.py` | Notices shown from About → Licenses. |

Bitcoin operations go through embit 0.8.0, the release SeedSigner pins. Pillow draws the screen. qrcode builds the codes the device displays.

## Screens

`ui/app.py` is the screen machine: a current screen name, a back stack, and the open menus. `ui/canvas.py` is the drawing surface, the palette, the fonts, and the button hit boxes.

The side menu reaches Bitcoin Keys, Bitcoin Wallets, Settings, and About. Every other screen has a back button. Scroll offset is stored per screen, and the title bar stays put.

A seed key opens Derive Key (`derive`) for one of the three supported paths. The screen derives the extended key in memory with `_public_for` and does not store it. Single-signature derivations can create or open the wallet at the selected account. Multisig derivation only shows the key.

Load External Key is two screens, `external-review` and `external-details`. A failed QR or SD import uses `load-error`. The license list is `licenses`, and one notice is `license`.

On the Pi, `camera_preview_box` is the viewfinder rectangle for the scan and camera screens. `hardware/camera.py` fills it from picamera2 and reads QR codes with pyzbar. Those packages come from the device image. They are not imported on a machine that is not capturing, and the emulator does not use that module. The emulator page shows the computer's camera above the panel.

## What is bundled

Fonts and icons are in `src/bigsigner/resources/`: DejaVu, Font Awesome Free, and the SeedSigner icon font. The adjective, color, and animal lists are copied into `names.py`. Their license texts are in `licenses.py` and `LICENSE`, and on the About screen.

# BigSigner

BigSigner is free software for an air-gapped Bitcoin signing device. It is inspired by [SeedSigner](https://github.com/SeedSigner/seedsigner) and is built for a larger portrait touchscreen instead of SeedSigner's small joystick display.

The device holds seeds only in memory. After the operating system has booted, the microSD card can be removed. Powering off clears the seeds. Nothing is written to storage unless you explicitly export a file.

The companion operating system is [bigsigner-os](https://github.com/BigSigner/bigsigner-os), a Buildroot image derived from SeedSigner OS. It keeps networking disabled and adds HDMI video plus a resistive touchscreen on SPI.

## Hardware

A typical build uses:

- A Raspberry Pi Zero, Zero W, or Zero 2 W. A board without Wi-Fi is preferable.
- The Waveshare 4inch HDMI LCD, SKU 12030, used at its native 480×800 portrait resolution.
- A Mini HDMI cable, and the display's GPIO header seated on pins 1–26 so the touch controller can use SPI.
- A Raspberry Pi camera, used for QR codes and for camera entropy. On the device, the scan and camera screens show the live picture in a viewfinder. That needs `picamera2` on the image. Reading the QR code also needs `pyzbar`. The browser emulator shows the camera above the panel instead.

The release image should not enable networking, Bluetooth, or USB. A development image with SSH is only for building the software. Do not use it with real funds.

## What it does

BigSigner helps you create or load a BIP39 seed, keep a passphrase if you use one, and work with watch-only keys. From those keys it can build and check:

- a single-signature native SegWit wallet
- a single-signature Taproot wallet
- a native SegWit multisig wallet

It reviews a proposed transaction before signing and can show receive addresses so you can check them against another wallet. Taproot multisig is not included in this version.

The Bitcoin library is [embit](https://github.com/diybitcoinhardware/embit) 0.8.0, the same release [SeedSigner pins](https://github.com/SeedSigner/seedsigner/blob/dev/requirements.txt).

## Documentation

Tutorials live in [docs/](docs/README.md). They are for people reading this repository. They are not installed on the device. [docs/architecture.md](docs/architecture.md) maps the code. [AGENTS.md](AGENTS.md) records the constraints that are easy to miss while changing it.

## Develop and test

The application is Python 3.10 or newer. These instructions use Python 3.12.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

`pytest` runs the unit tests and writes review screenshots under `artifacts/screenshots/`.

To run the same interface in a desktop browser, without a Raspberry Pi:

```bash
PYTHONPATH=src BIGSIGNER_EMULATOR=1 python -m bigsigner
```

Open http://127.0.0.1:8765. The page shows the 480×800 frame at the Waveshare picture size, 51.84 mm by 86.40 mm, and sends taps back to the application. A browser's millimeter is not always a ruler millimeter, so the buttons under the picture adjust that size and remember it. This mode is for development. Do not type a real seed into it. In that terminal, `r` clears the session and starts the program again, so code saved on disk is loaded. Ctrl+C stops it. Another port is `BIGSIGNER_PORT=8766`.

These variables are for development. Do not set them on a device that holds real funds.

| Variable | Purpose |
| --- | --- |
| `BIGSIGNER_EMULATOR` | Set to `1` to force the browser emulator. Without it, a machine with `/dev/fb0` uses the panel. |
| `BIGSIGNER_PORT` | Emulator port. The default is `8765`. |
| `BIGSIGNER_SDCARD_PATH` | A folder treated as the microSD card, including its subfolders. Load from SD card reads text files from it. |
| `BIGSIGNER_INITIAL_SEED` | A 12, 18, or 24 word mnemonic loaded when the boot screen is left. Commas are treated as spaces. An invalid value is printed and shown on screen. |
| `BIGSIGNER_INITIAL_WALLET_DESCRIPTOR` | A wallet descriptor loaded when the boot screen is left, after the initial seed. It is imported the same way as a descriptor from the Bitcoin Wallets page, including a BSMS 1.0 file. An invalid value is printed and shown on screen. |
| `BIGSIGNER_CPU_SERIAL` | A string mixed into camera entropy. The default is `bigsigner-emulator`. |

On a device whose HDMI framebuffer is `/dev/fb0`, the same command uses the panel and the touchscreen instead of the browser. BigSigner OS starts that device by running `src/main.py`. Syncing this checkout to a dev image and restarting uses that file.

The operating-system image is built from [bigsigner-os](https://github.com/BigSigner/bigsigner-os), not from this repository. See that project's documentation for how to build and flash a microSD card.

## Security

Report security issues to orenz0@protonmail.com. See [SECURITY.md](SECURITY.md). Do not include a real seed, passphrase, or private key.

## License

BigSigner is released under the MIT license. See [LICENSE](LICENSE).

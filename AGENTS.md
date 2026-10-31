# Working on BigSigner

BigSigner is an air-gapped Bitcoin signer for a portrait 480×800 touchscreen. Seeds stay in memory. The browser emulator and the Raspberry Pi panel run the same `App` object.

`SPEC.md` is the product spec. When its "Resolved decisions" section disagrees with the rest of that file, the resolved section wins. [docs/architecture.md](docs/architecture.md) is the map of the code. Tutorials in `docs/` describe what a person does with another wallet. They are not installed on the device.

## Screen

The panel is 480×800. The title bar is 88 pixels and does not scroll. The page margin is 20. Colors and the button rules live in `src/bigsigner/ui/canvas.py`, `.cursor/rules/button-colors.mdc`, and `.cursor/rules/button-labels.mdc`.

Buttons are the brighter blue, `(24, 92, 184)`. Dark navy, `(18, 36, 58)`, is only for a button that is currently deselected in a choice, such as the passphrase keyboard modes. A disabled button is grey. The title bar, toasts, and the boot screen may stay navy. Those are not buttons.

Button labels use Title Case. The words a, an, the, and, or, to, of, for, with, from, and in stay lowercase unless they are the first or last word. OK, QR, and SD stay in capitals. A technical token such as xpub keeps its own spelling, as in xpub only. Product terms keep their spelling: SingleSig, MultiSig, Native-Segwit, Taproot. Native-Segwit is written with a hyphen. The passphrase keyboard modes stay `abc`, `ABC`, `.?123`, and `#+=`.

There is no horizontal scrolling. Long text wraps. Fingerprints, addresses, xpubs, descriptors, and other technical values use the monospace font.

The title bar text is 32px. Body paragraphs and buttons are 36px, a little larger than the title. On Bitcoin Keys, the section labels, the fingerprint name, the hex, the seed summary, and an external key's kind and account are 32px. The fingerprint name on a key card is centered and breaks after the second word. A Bitcoin Wallets card lists the fingerprints under the title, monospace and separated by commas, breaking after a comma, and puts a key icon or an eye icon to the left of each fingerprint name. On the seed key, external key, and wallet screens the name breaks the same way, with a key icon for a seed or an eye icon for an external key on the left, lined up with the fingerprint icon. The seed key screen's fingerprint line, seed sentences, and buttons follow the title and button sizes above. Its three derive buttons open Derive Key, which starts with an account selector and then the external-key details, without Delete. Export to SD Card sits under Show Full Details there, and on an external key it sits under Show Full Details and above Delete Key. A single-signature derivation can create or open its wallet from that screen. On an external key, the type, account, derivation path, and extended public key use that fingerprint size. The path and the key preview are each centered on the next line, and Delete Key follows the other buttons. The side menu keeps its own size.

## Browser emulator

Tests do not start it. They construct `App`, call `render`, and tap.

```bash
PYTHONPATH=src python -m bigsigner.bundle
python3 -m http.server 8780 --directory web
```

Open http://127.0.0.1:8780/ . Run the bundle command again after changing Python, then reload the page. `web/bundle.json` is gitignored. Do not type a real seed into the emulator. The hash supplies `seed` and `descriptor`. The SD card is the files stored in the browser. `BIGSIGNER_INITIAL_SEED`, `BIGSIGNER_INITIAL_WALLET_DESCRIPTOR`, and `BIGSIGNER_SDCARD_PATH` are for tests and the panel, not this page.

## Tests

```bash
pytest
```

Screenshot tests write `artifacts/screenshots/<test name>/` and an `index.html` gallery. A flow that stands in for scanning a QR code writes the payload into a temporary directory, sets `BIGSIGNER_SDCARD_PATH`, and clicks the plus button, then Load from SD Card, then the file. The browser camera is not a stand-in for that path.

## External keys

A bare key expression is not stored on the first screen. Checks for an unsupported path, a duplicate, or a seed mismatch open Error loading key (or Error loading wallet, from the wallets page). OK returns to Bitcoin Keys or Bitcoin Wallets.

A wallet descriptor loaded from Bitcoin Keys opens a choice screen instead. An unsupported descriptor opens Error loading key, with no mention of Bitcoin Wallets. A singlesig descriptor offers Both Wallet and Key (the wallets-page import) or Only the Key (the key expression). A multisig descriptor offers Load Both Wallet and All Keys, then a menu of `<fingerprint> <first 10 characters of the xpub>...` in descriptor order, then Load Only Selected Key.

When the checks pass, Load External Key is two screens. The first is a red Warning and a Show Extended Public Key Details button. The second shows the type, account, derivation path, and a format menu (`xpub` or `tpub`, the SLIP-132 form when the path has one, and the full key expression). Only Continue on that second screen stores the key. Back from the details returns to the warning. Back from the warning leaves the key unloaded.

## Fingerprint names

`animal_name` in `src/bigsigner/names.py` names a fingerprint. The name is calculated, not chosen, and not stored as an editable nickname. The first three bytes are one integer. That integer is divided across 982 adjectives, 51 colors, and 346 animals from unique-names-generator. Adjectives are at most 9 letters, colors at most 9, and animals at most 10. Those are the shortest limits for which the lists still cover every value of three bytes. The name ends with the last two hex characters of the fingerprint. The worked example is in [docs/fingerprint-names.md](docs/fingerprint-names.md).

Cards on Bitcoin Keys: Seeds stay in `session.key_counter` order. SingleSig External Keys and MultiSig External Keys are separate sections, each shown only when it has a card. Each external key is its own card. Within a section those cards are ordered by fingerprint nickname, then Native-Segwit before Taproot, then account number.

## Licenses

Bundled notices are in `src/bigsigner/licenses.py`, shown from About → Licenses, and summarized in `LICENSE`. A new library or copied asset needs its notice in all three places. The word lists in `names.py` are MIT-licensed unique-names-generator data, not BigSigner originals.

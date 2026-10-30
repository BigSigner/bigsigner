# Load a seed

A seed is a BIP39 mnemonic of 12, 18, or 24 English words. BigSigner checks the checksum and refuses a phrase that does not pass. You can also create a new 12-word or 24-word seed from dice rolls or coin flips. The dice and coin methods follow SeedSigner: the characters you enter are hashed with SHA-256, and a 12-word result uses the first 16 bytes of that hash. An 18-word phrase can be imported, but this version does not generate one.

The seed stays in memory until you power the device off. It is not written to the microSD card.

## Passphrase

A passphrase is optional. BigSigner calls it a passphrase. It is the BIP39 passphrase, applied with Unicode NFKD normalization. An empty passphrase is the same as no passphrase. Two different passphrases produce two different fingerprints, even when the words are the same.

Spaces and capitalization are part of the passphrase. If it starts or ends with a space, is longer than 100 characters, or contains anything outside printable ASCII, BigSigner warns you that another wallet may not reproduce it. Coldcard, for example, accepts only ASCII characters 32–126 and at most 100 characters. The warning does not change the passphrase.

## What you should see

After the phrase is accepted, BigSigner shows the fingerprint and its calculated name: an adjective, a color, an animal, and the last two hex characters of the fingerprint. The name is not editable. How that name is calculated is described in [Fingerprint names](fingerprint-names.md). On the Bitcoin Keys card, a seed also shows its first word followed by "...", and a passphrase seed adds "+ Passphrase" plus the number assigned to that passphrase.

Before the words are shown again, confirm that nobody else can see the screen.

## Check it

The fingerprint is the first four bytes of the HASH160 of the master public key. Compare it with the fingerprint shown by the wallet that created the phrase, or with the one you wrote down when you generated the seed. If they differ, stop. Do not receive funds to addresses from a seed you cannot identify.

## Derive a key

The Seed Key screen does not create a wallet directly. It offers three buttons:

- Derive a Native-Segwit SingleSig Key (`m/84h/<coin>h/<account>h`)
- Derive a Native-Segwit MultiSig Key (`m/48h/<coin>h/<account>h/2h`)
- Derive a Taproot SingleSig Key (`m/86h/<coin>h/<account>h`)

Each opens Derive Key. The account selector is the first control: minus on the left, plus on the right, and the account index in the middle. Tapping the index opens a keypad. The screen then shows the same details as an external key: the fingerprint name, the fingerprint, the type, the derivation path, and the first 20 characters of the extended public key. Those 20 characters change when the account changes. Nothing new is stored. There is no Delete button.

Show Full Details shows the derived key expression, including its QR code. Export to SD Card is the next button. It asks for a format (Key Expression, the xpub or tpub, and the SLIP-132 form such as zpub when this path has one), then a file on the SD card. An existing file can be replaced, or New File can name a new one. The Key Expression file is `[fingerprint/derivation path]xpub/<0;1>/*`. The other formats are the key alone. A single-signature derivation also has a button that creates the wallet at the selected account, or opens that wallet if it already exists. A multisig derivation has no wallet button. A multisig wallet is loaded from a descriptor, or assembled from keys, rather than created from this one derived key.

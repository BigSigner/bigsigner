# Load a seed

A seed is a BIP39 mnemonic of 12, 18, or 24 English words. BigSigner checks the checksum and refuses a phrase that does not pass. You can also create a new 12-word or 24-word seed from dice rolls or coin flips. The dice and coin methods follow SeedSigner: the characters you enter are hashed with SHA-256, and a 12-word result uses the first 16 bytes of that hash. An 18-word phrase can be imported, but this version does not generate one.

The seed stays in memory until you power the device off. It is not written to the microSD card.

Scan QR Code and Load from File first show Seed Words, with 12 Words Seed, 18 Words Seed, or 24 Words Seed above a scrollable column of the words. The list starts at the bottom so the last word is visible. Scroll up to review the earlier words. Continue below the list opens the passphrase choice. Manual Entry also keeps the completed word list on screen after the last word; tap Continue to proceed. Choosing No Passphrase or saving a passphrase then loads the seed. Back from the passphrase choice returns to the words.

## Passphrase

A passphrase is optional. BigSigner calls it a passphrase. It is the BIP39 passphrase, applied with Unicode NFKD normalization. An empty passphrase is the same as no passphrase. Two different passphrases produce two different fingerprints, even when the words are the same.

Spaces and capitalization are part of the passphrase. If it starts or ends with a space, is longer than 100 characters, or contains anything outside printable ASCII, BigSigner warns you that another wallet may not reproduce it. Coldcard, for example, accepts only ASCII characters 32–126 and at most 100 characters. The warning does not change the passphrase.

## What you should see

After the phrase is accepted, BigSigner shows the fingerprint and its calculated name: an adjective, a color, an animal, and the last two hex characters of the fingerprint. The name is not editable. How that name is calculated is described in [Fingerprint names](fingerprint-names.md). On the Bitcoin Keys card, a seed also shows its first word in lowercase followed by "…", and a passphrase seed adds "+ Passphrase" plus the number assigned to that passphrase. On the Seed Key screen, under the fingerprint, the same seedling icon is followed by "First Word: " and that word.

Before the words are shown again, confirm that nobody else can see the screen.

## Check it

The fingerprint is the first four bytes of the HASH160 of the master public key. Compare it with the fingerprint shown by the wallet that created the phrase, or with the one you wrote down when you generated the seed. If they differ, stop. Do not receive funds to addresses from a seed you cannot identify.

## Export the words

Without a passphrase, Show and Export are side by side under the passphrase note. Show opens the privacy warning and then displays the seed; Back returns to Seed Key. Export opens the backup warning directly, and completing the export returns to Seed Key. With a passphrase, Show/Export opens the existing choices: Show Seed, Show Passphrase, and Export Seed to File. The export warning says that a file is not a complete backup: keep a physical copy on paper or metal as well, and wipe the card thoroughly before it is used in anything connected to the internet. Deleting the file is not enough. Continue opens SD Card or Temporary FS, then the file browser writes the words separated by spaces. There is no separate standard file format for a BIP39 seed. The passphrase is not included. Load from File reads that file, trims the surrounding space, and accepts the same words with extra spaces, newlines, or commas.

## Derive a key

The Seed Key screen does not create a wallet directly. Derive an Extended Public Key asks which type of key to derive:

- Native-Segwit SingleSig Key (`m/84h/<coin>h/<account>h`)
- Native-Segwit MultiSig Key (`m/48h/<coin>h/<account>h/2h`)
- Taproot SingleSig Key (`m/86h/<coin>h/<account>h`)

Each choice opens Derive Key. The account selector is the first control: minus on the left, plus on the right, and the account index in the middle. Tapping the index opens a keypad. The screen then shows the same details as an external key: the fingerprint name, the fingerprint, the type, the derivation path, and the first 20 characters of the extended public key. Those 20 characters change when the account changes. Nothing new is stored. There is no Delete button.

Show Full Details shows the derived key expression, including its QR code. Export to File is the next button. It asks for a format (Key Expression, the xpub or tpub, and the SLIP-132 form such as zpub when this path has one), then SD Card or Temporary FS, then a file in that storage. An existing file can be replaced, or New File can name a new one. The Key Expression file is `[fingerprint/derivation path]xpub/<0;1>/*`. The other formats are the key alone. A single-signature derivation then has a button that creates the wallet at the selected account, or opens that wallet if it already exists. A multisig derivation has no wallet button. A multisig wallet is loaded from a descriptor, or assembled from keys, rather than created from this one derived key.

## Derive a BIP85 child seed

Derive a BIP85 Child Seed sits under Create a Copy of This Seed with a Passphrase, or under Create a Copy of This Seed with a Different Passphrase when a passphrase is set. The label breaks after BIP85. The next screen labels the choice Number of Words. It is a dropdown of 12 words or 24 words, with 24 words selected, and an index that starts at 0. The child is an English BIP39 mnemonic from `m/83696968h/39h/0h/{12 or 24}h/{index}h`. 83696968 is the BIP85 purpose field. It is not the index 85. Specter DIY derives a child mnemonic with the same path. The child has no passphrase of its own. A passphrase on the parent is already part of the master key this derivation uses, so the same words with a passphrase produce a different child.

Derive Seed adds the child and opens it. Back from that screen returns to Bitcoin Keys. The notice says BIP85 child seed was added successfully. Deriving a seed that is already loaded shows This seed is already loaded. and stays on the BIP85 screen.

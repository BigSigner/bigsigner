# Load an external key

An external key is a watch-only key expression. It lets BigSigner show addresses for that key. It does not let BigSigner sign or send.

Load one from Bitcoin Keys, with the plus button, then either Scan QR Code or Load from SD Card. The text is a key expression:

```text
[fingerprint/84h/0h/0h]xpub.../<0;1>/*
```

A `zpub`, `Zpub`, `vpub`, or `Vpub` in that position is accepted when it matches the path and the current network. BigSigner stores the canonical `xpub` on mainnet, or `tpub` on testnet and regtest.

Generating a seed and typing a seed by hand are separate flows. They do not use this screen.

## When the file or QR code is a wallet descriptor

A descriptor this version does not support opens Error loading key. OK returns to Bitcoin Keys. The message does not send you to Bitcoin Wallets.

A supported singlesig descriptor (`wpkh` or `tr`) opens a screen titled Wallet Descriptor. It says this is a singlesig wallet descriptor and asks whether to load both the wallet and the key, or only the key. Both Wallet and Key continues as if that text had been loaded from the plus button on Bitcoin Wallets. Only the Key continues with the key expression, through the review below.

A supported multisig descriptor opens the same screen. It says this is a multisig wallet descriptor and asks whether to load the wallet and all the keys, or only a specific key. Load Both Wallet and All Keys continues as if that text had been loaded from the plus button on Bitcoin Wallets. Below that button, after a larger gap, a menu lists the key expressions in descriptor order. Each entry is the fingerprint in hex, a space, the first 10 characters of the extended public key, and `...`. Load Only Selected Key continues with the selected key expression, through the review below.

## Before it is stored

BigSigner opens a screen titled Error loading key, in red text, and does not store the key when:

- The derivation path is not a supported native-SegWit or Taproot path for this network.
- That fingerprint and path are already loaded.
- A seed with that fingerprint is already loaded and derives the same extended key. The message names the fingerprint. The external key is unnecessary.
- A seed with that fingerprint is already loaded but does not derive this extended key. BigSigner treats that as suspicious: a real wallet is less likely to produce it than a bug or malicious code, and less likely than winning the lottery.

OK at the bottom of that screen returns to Bitcoin Keys.

Otherwise it opens Load External Key. The first screen shows a centered red Warning. For a single-signature key it says you are about to load an external key for a singlesig wallet, and that the wallet owner must verify the extended public key on their hardware wallet before sending funds. For a multisig key it says you are about to load an external key for a multisig wallet, and that the co-signer must verify the extended public key (xpub) on their hardware wallet. Show Extended Public Key Details at the bottom opens the second Load External Key screen.

That screen first asks you to verify the extended public key on the other hardware wallet. A grey Format: label sits above a menu of the canonical extended key, the SLIP-132 form when this path has one, or the full key expression, and the chosen key is shown under the menu. Below that it asks you to verify the backed-up details: the type, the account, and the derivation path. Account 0 is marked default. Any other account is shown in red as non-default.

Continue is at the bottom of the second page. Scroll to it. Only that Continue stores the key and opens its External Key screen. Back from the details returns to the warning. Back from the warning leaves the key unloaded.

On the External Key screen, Show Full Details is followed by Export to SD Card, then Delete Key. Export to SD Card asks for Key Expression, the canonical extended key, or the SLIP-132 form when this path has one. The next screen lists the SD card. Choosing a file replaces it after a confirmation. New File asks for a name and writes that file.

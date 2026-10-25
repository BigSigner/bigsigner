# Load a multisig wallet

A native SegWit multisig wallet is imported as an output descriptor of this form:

```text
wsh(sortedmulti(2,[fingerprint/48h/0h/0h/2h]xpub.../<0;1>/*,[fingerprint/48h/0h/7h/2h]xpub.../<0;1>/*))#checksum
```

`2` is how many signatures are required. Each key has its own account. In the example, one cosigner uses account 0 and the other uses account 7. That is allowed. Every address still uses the same receive or change step and the same address index on every key. Receive index 5 of that example is `.../0h/2h/0/5` for the first key and `.../7h/2h/0/5` for the second.

On testnet the coin type is `1h`, not `0h`.

## Extended keys

Exported descriptors from BigSigner use `xpub` on mainnet and `tpub` on testnet. You can also import a `Zpub` while the network setting is mainnet, or a `Vpub` while it is testnet, when the path is the native SegWit multisig path ending in `2h`. BigSigner converts that key to `xpub` or `tpub` and then compares it with keys already loaded. A `zpub` or `vpub` is not accepted in a multisig descriptor. Those prefixes belong to single-signature native SegWit.

If a checksum is present, it is checked. A wrong checksum is rejected. A descriptor with no checksum is accepted.

## What is rejected

BigSigner refuses the descriptor when any of these are true:

- The script is not `wsh(sortedmulti(...))`. Unsorted `multi()`, legacy, nested SegWit, Taproot multisig, and Miniscript are not accepted.
- A key's path is not `m/48h/<coin>h/<account>h/2h` for the current network.
- The extended key's own depth or last child number disagrees with that path. The whole descriptor is rejected.
- The same fingerprint appears twice. One fingerprint can hold only one account index, so two accounts of the same key would collapse into one and the addresses would be wrong. That descriptor is refused.
- A loaded seed with that fingerprint does not derive the same extended key.
- A different extended key is already stored for the same fingerprint and path.
- There are fewer than 2 keys, more than 15, or the threshold is outside 1 through the number of keys.

## The same wallet, written differently

`sortedmulti` sorts the public keys when it builds an address. These two descriptors are the same 2-of-3 wallet, even though the key order differs and the checksums differ:

```text
wsh(sortedmulti(2,[A]xpubA/<0;1>/*,[B]xpubB/<0;1>/*,[C]xpubC/<0;1>/*))
wsh(sortedmulti(2,[B]xpubB/<0;1>/*,[A]xpubA/<0;1>/*,[C]xpubC/<0;1>/*))
```

Account indexes are not part of that identity either. A descriptor that uses account 7 for a cosigner is the same wallet as one that uses account 0, as long as the fingerprints, the script, and the threshold match. `h` and `'`, and `Zpub` versus `xpub`, are also the same key after they are read.

BigSigner does not decide this by editing the descriptor text and splitting on commas. A comma split breaks if a future descriptor puts a comma inside a key. The identity is a value instead: the current network, the script (`wpkh`, `tr`, or native-SegWit multisig), the threshold, and the fingerprints sorted as bytes. A readable form of that value, with the account written as `*` and the extended keys omitted, looks like `wsh(sortedmulti(2,[aa../48h/0h/*h/2h]/<0;1>/*,[bb../48h/0h/*h/2h]/<0;1>/*))`. That text is only a description of the value. It is not parsed back into a wallet.

A 2-of-3 and a 3-of-3 of the same people are different wallets. So are native SegWit and Taproot for one fingerprint.

The order of the fingerprints is a separate fact from that identity. The descriptor that first creates the wallet is stored in that order. The Wallet screen lists the keys in that saved order, and so does the descriptor it shows. A later descriptor of the same wallet, with the keys written in another order, does not change it. Account-index tuples in messages, such as account-indexes (0,7), follow that saved order too, not the order of the descriptor being loaded.

## Short name

Messages name a wallet briefly. A single-signature wallet is the fingerprint's name plus Native-Segwit or Taproot, for example `Wild Crimson Whale 0A Native-Segwit`. A multisig wallet is the threshold, the number of keys, and the fingerprint hex in the wallet's own order, for example `2-of-3 f992cf24,7e930c45,aabbccdd`. The long animal names are not repeated for every cosigner.

## Importing a descriptor

From Bitcoin Wallets, Scan descriptor QR code and Load descriptor from SD card use the same steps.

If the file is a seed, a transaction, or a key expression, the error screen says what it is and that it is not a wallet descriptor. If it is a descriptor of a kind this version does not accept, the error says the wallet descriptor is not supported. OK returns to Bitcoin Wallets.

Each key is then checked as if it were being loaded on its own. A key that names a loaded seed but does not match the extended key that seed derives stops the import. The error is the same suspicious-key screen used for a key expression. Nothing from the descriptor is stored.

Before the first new key, one warning says this is an external key for a multisig wallet and that the co-signers must verify the extended public keys on their hardware wallets. A singlesig descriptor says the wallet owner must verify it before funds are sent. The button is Show Extended Public Key Details. Each new key then has an Extended Public Key Details screen. Further new keys in the same multisig open that screen directly, without the warning again. Keys that are already loaded, or that the loaded seed can derive, are skipped.

If that set of fingerprints and threshold is already a wallet, the screen says Wallet "<short name>" was already loaded. When every key was already known, it says this descriptor points to account-index X (default) when that index is 0, or account-index X (non-default) otherwise. Several keys are written as account-indexes (X (default),Y (non-default)), in the wallet's own key order and without the fingerprints. When some keys are new, it says those account indexes can now be used, with the same note on each index. Continue stores any new keys, switches the accounts, and opens the wallet. Back leaves without storing them.

If the wallet is new, it is added and opened. Back from the wallet returns to Bitcoin Wallets, not to the scan or the file list.

## Single-signature descriptors

A single-signature native SegWit wallet uses `wpkh([fingerprint/84h/<coin>h/<account>h]xpub/<0;1>/*)`. A single-signature Taproot wallet uses `tr([fingerprint/86h/<coin>h/<account>h]xpub/<0;1>/*)` with no script tree. A `zpub` or `vpub` is accepted only for the native SegWit single-signature path, and only when it matches the current network setting.

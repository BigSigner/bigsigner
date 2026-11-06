# Sign a transaction

Create the transaction in a coordinator such as Sparrow. Export it as a PSBT and move that PSBT to BigSigner without using the network. A QR code or a file you carry yourself is the intended path. The coordinator is not trusted. BigSigner checks the PSBT against the wallet you have selected.

PSBT version 0 and version 2 are read. A version 0 PSBT that contains a per-input required locktime is rejected. Bitcoin transaction versions 2 and 3 are accepted. Other versions are rejected.

## What has to match

Every input must belong to the selected wallet. Each input needs a derivation path. For a multisig input, every cosigner must use the same receive-or-change step and the same address index. One key ending in `/0/5` and another in `/1/5`, or `/0/6`, is rejected.

All inputs in the transaction must use the same combination of accounts. If that combination is not the one currently selected, but every input agrees, BigSigner can switch to it when you confirm. Inputs that disagree with each other about the accounts are rejected.

An output is change only when its derivations use that same account combination, share one branch and address index, and the script BigSigner derives is the script in the output. Anything else is an external output, including an output that belongs to another account of the same seed.

The signature hash must be SIGHASH_ALL. Taproot also allows the default sighash. SIGHASH_NONE, SIGHASH_SINGLE, and ANYONECANPAY are rejected. A PSBT that contains PSBT_GLOBAL_TX_MODIFIABLE is rejected on version 0 and version 2.

## Transaction Signing

A PSBT that passes the checks opens Transaction Signing. The header says Spending from Wallet:, then the wallet name and Account: 0 (default) or Account: 3 (non-default). Under the account line, Transaction Id is a chevron, closed at first. Opening it shows the transaction id as four centered monospace rows, the same way an input shows a previous transaction id. A wallet name does not start a line with a word of two letters or fewer. A block-height locktime adds a grey note that the transaction can be mined only after that block height. The exact height is not included: Bitcoin accepts the transaction in the next block. More Information, closed at first, explains why wallets set a locktime near the chain tip.

Warnings are centered. There is one OP_RETURN warning: red when any OP_RETURN carries bitcoin, otherwise yellow when an OP_RETURN is present. A fee of 100000 sats or more is a red warning and the fee section is red. A timestamp locktime, a relative locktime, and a Replace-by-Fee disabled input are yellow warnings. The relative-locktime warning says to see below for more details.

Amounts are satoshi counts shown as BTC strings. The count is padded to at least nine digits and the point is placed eight digits from the right. It is not divided by a float. An OP_RETURN of zero sats is shown as 0. The largest amount, 21,000,000.00000000, fits on one line.

The output heading says 1 Output or the number of outputs. Those cards skip money that returns to the spending wallet. When every output returns to that wallet, the heading is replaced by a note that the transaction sends all funds back to the same wallet, except for the fee. Other outputs show the address in groups of four. A derivation that matches a loaded wallet shows that wallet, its account, and Receive or Change Address. Otherwise the card says External Address and offers Search for Address in Loaded Wallets. The search checks Receive and Change. Other wallets use the account they already have selected. This wallet tries each key from account 0 through its selected account plus 3. It looks at 50 addresses at a time and can continue with the next 50.

Change sits above the inputs. Its heading is 0 Change Outputs with no chevron, or 1 Change Output, or the number of change outputs. The input heading says 1 Input or the number of inputs. A change card shows the address and Change Address or Receive Address with the index. A receive address there is yellow. More than one change output is a yellow warning, because that is unusual although a wallet may do it for privacy. A change output on a receive address is a yellow warning too: it is unusual, but mostly harmless.

The fee is every input minus every output, including change and OP_RETURN. The fee rate is that fee divided by the virtual size, shown with two decimal places. The locktime section says the transaction could be mined right away when there is no absolute locktime and no relative locktime. Otherwise it names a block height, shows a UTC timestamp, or says there is no absolute locktime while a relative one remains. Inputs start closed unless a sequence is not 0xFFFFFFFD. An open input shows the previous transaction id, the output index, the amount, the sequence in hex, and Show Input QR. That code can be the raw txid and output index, or a link to that output on mempool.space or blockstream.info. On testnet or regtest, those two links have a control above Brightness that chooses Testnet, Testnet4, or Signet. Those are the networks both sites publish. Raw has no such control. A sequence of 0xFFFFFFFE says Replace-by-Fee is disabled and that the network no longer honors that flag. A lower sequence is a relative locktime in blocks, or in units of 512 seconds. A time duration breaks onto another line only after a comma.

Sign Transaction adds a signature for every loaded seed in the wallet. Show QR Code opens Signed Transaction and offers Animated UR, Static UR, Base64, Specter Animated, and BBQr. Static UR is one code. Animated UR, Specter Animated, and BBQr cycle about twice a second when they have more than one code. Brightness on that screen, and on an input's QR, dims or brightens the whole screen so the panel does not blind the camera. Black stays black. Export to SD Card writes a binary PSBT or base64 text.

Any number of OP_RETURN outputs is accepted, including one that carries bitcoin. That matches Bitcoin Core 31's default relay policy. Each script must be OP_RETURN followed only by data pushes, and the scripts together must be at most 100000 bytes. Any other output must be Native-Segwit SingleSig, Taproot, or Native-Segwit MultiSig. A Native-Segwit SingleSig output below 294 sats is refused, and a Taproot or Native-Segwit MultiSig output below 330 sats is refused. A transaction whose inputs are already signed by every seed this wallet holds is refused, even when a multisig still needs signatures from other wallets. A transaction over 400000 weight units, which is 100000 vB, is refused. That is Bitcoin Core's maximum standard weight.

## Signing

BigSigner adds a signature only for a fingerprint whose seed is loaded. Watch-only keys are shown as unable to sign. After a signature is added, return the PSBT to the coordinator by QR or by a file you explicitly export. Do not leave a seed on a device that still has a network connection.

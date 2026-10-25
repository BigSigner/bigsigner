# Sign a transaction

Create the transaction in a coordinator such as Sparrow. Export it as a PSBT and move that PSBT to BigSigner without using the network. A QR code or a file you carry yourself is the intended path. The coordinator is not trusted. BigSigner checks the PSBT against the wallet you have selected.

PSBT version 0 and version 2 are read. Bitcoin transaction version 1 and version 2 are accepted. Other versions are rejected.

## What has to match

Every input must belong to the selected wallet. Each input needs a derivation path. For a multisig input, every cosigner must use the same receive-or-change step and the same address index. One key ending in `/0/5` and another in `/1/5`, or `/0/6`, is rejected.

All inputs in the transaction must use the same combination of accounts. If that combination is not the one currently selected, but every input agrees, BigSigner can switch to it when you confirm. Inputs that disagree with each other about the accounts are rejected.

An output is change only when its derivations use that same account combination, share one branch and address index, and the script BigSigner derives is the script in the output. Anything else is an external output, including an output that belongs to another account of the same seed.

The signature hash must be SIGHASH_ALL. Taproot also allows the default sighash. SIGHASH_NONE, SIGHASH_SINGLE, and ANYONECANPAY are rejected.

## Amounts and warnings

Amounts are calculated in satoshis and shown in bitcoin with eight decimal places. The fee is the inputs minus the outputs. A negative fee is rejected. The fee rate is shown in sat/vB.

You also get a warning when:

- any input sequence is `0xFFFFFFFE` or `0xFFFFFFFF`
- the locktime is a timestamp, or every sequence is final so the locktime does nothing
- an input has a relative locktime
- there is more than one change output, or more than one external output
- a change output uses a receive address
- the fee is large compared with the amount being spent
- the transaction contains an OP_RETURN output

An OP_RETURN payload can be read as text or as hex. If an OP_RETURN output carries any bitcoin, signing is blocked, because that amount cannot be spent.

## Signing

BigSigner adds a signature only for a fingerprint whose seed is loaded. Watch-only keys are shown as unable to sign. After a signature is added, return the PSBT to the coordinator by QR or by a file you explicitly export. Do not leave a seed on a device that still has a network connection.

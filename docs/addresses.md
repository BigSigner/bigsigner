# Addresses

Open a wallet and tap Addresses. Receive is selected. Change is the other branch. Each row shows the index, starting at 0, then the address on one line. A line that does not fit ends with `…`.

The list does not derive every index. It derives the rows on screen and one page further on, and it drops rows that have scrolled far away. The highest index is 2147483647.

Tap a row to open that address. The title is Receive Address or Change Address and the index. An index of more than four digits shows the first three digits and …. That screen shows a QR code of the address, the address in groups of four characters, and the derivation path. The first group is black. Every second group is grey. The address and the path are centered. The path starts with the fingerprint hex, then the account path, the branch (`0` for receive, `1` for change), and the index. Twenty-five characters fit on one line. A longer path continues on the next line. The break is before a slash, and that slash starts the next line. A multisig wallet lists one path for each key. Export to SD Card writes the address alone. The suggested file name is the first fingerprint, receive or change, and the index. Load from SD Card on Verify Address reads that file. Sign Message sits under Export to SD Card. The page scrolls so that button is on screen. On a Native-Segwit SingleSig wallet it opens Manual Entry, Scan QR Code, or Load from SD Card, and the message is signed with this address. Manual Entry starts empty. A message that is not ASCII is refused. Text that begins with `signmessage ` after leading spaces and newlines is refused, because that command is loaded from the Sign Message button on the wallet screen. On any other wallet the button is grey, and the text below it says signing messages is supported only in Native-Segwit SingleSig wallets.

Addresses Tools stays under the list.

## Find an index

Find Address by Index asks for Receive or Change and an index. Show Address opens that address.

## Verify an address

Verify Address takes typed text, a QR code, or a text file from the SD card.

Manual Entry opens a keyboard with digits on the first row, then lowercase letters. There is no space bar and no shift to capitals or symbols. An address typed there that is not valid stays on that screen so it can be corrected. A scan or a file is recognized first. If it is a compact seed, a seed, a BSMS file, a wallet descriptor, a key expression, or a transaction, the message names that and says an address was required. An unrecognized scan or file says it is not an address. Either one returns to Verify Address.

The text can be the address alone, or a BIP21 URI:

- `bitcoin:bc1q...`
- `BITCOIN:BC1Q...`
- `bitcoin://bc1q...`
- `bitcoin:bc1q...?amount=0.01&label=Donation&message=Thanks`
- the same URI with `lightning=` or `pj=` in the query

Spaces and newlines are removed. The `bitcoin:` prefix, the query, and a `#` fragment are removed. The address is then lowercase. On mainnet it must start with `bc1`. On testnet it must start with `tb1`, and on regtest with `bcrt1`. A `1...` or `3...` address is refused. A descriptor, a key expression, a Uniform Resource, or anything that still contains `/` is refused, because those carry a derivation path.

The search looks through receive and change indexes 0-99. A match names the branch and the index, and Go to Address opens it. Back from the match, and from the address, returns to Addresses. Otherwise the screen says the address was not found in that range and offers the next range, 100-199, and so on. While that search runs, the button is grey and says Searching….

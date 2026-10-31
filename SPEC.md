# Preface

This file contained the original specification for the BigSigner project, but later during development it was updated to reflect the current state of the project.
It's basically a blob of information that I keep for my own reference, as well as for AI tools to help me develop the project.

BigSigner is a Python project inspired by SeedSigner (https://github.com/SeedSigner/SeedSigner) but with UX for larger touchscreens.
It will follow the similar concept of not saving any data on the device as permanent storage, and suggesting to the user to remove the SD-card once the system was booted.
Users could save information on an SD card if they want, if they explicitly ask to (other methods like the SeedSigner fork project called ShieldSigner - will not be supported in BigSigner).
Instead of the Waveshare 1.3-inch LCD HAT (240x240), this project targets 480x800 touchscreens (i.e. Waveshare 4inch HDMI LCD), connected via HDMI.

For the additional HDMI support, I've built https://github.com/BigSigner/bigsigner-os inspired by https://github.com/SeedSigner/seedsigner-os.
If you need the build artifacts of the bigsigner-os, let me know.

Learn about the file structure of the SeedSigner project and its dependencies, as this could be a good starting point for the BigSigner project.

Another interesting project to learn from is https://github.com/cryptoadvance/specter-diy which has UX for larger touchscreens (although it's not intended for Raspberry Pi Zero, so it's internal implementation details would be very different).

We wish not to install Bitcoin-related python packages that are not used by SeedSigner.

Add SECURITY.md file to the project. Security contact email should be orenz0@protonmail.com

# Resolved decisions

Where this section disagrees with the rest of the document, this section wins.

The screen is portrait 480×800. Supported wallets are single-sig native segwit (`m/84h/<coin>h/<account>h`), single-sig taproot key-path (`m/86h/<coin>h/<account>h`), and native-segwit multisig (`m/48h/<coin>h/<account>h/2h`). The coin type is `0h` on mainnet and `1h` on testnet and regtest.

A multisig address uses the same `/<branch>/<index>` suffix on every key. Accounts may differ, for example `.../0h/2h/0/5`, `.../7h/2h/0/5`, and `.../30h/2h/0/5`. Every input in one transaction must use the same account tuple. Inside one input, the branch and address index must match across keys. A mismatch of the extended key's stored depth or last child number with its origin path rejects the whole key expression, descriptor, or transaction.

`zpub` and `vpub` are accepted only for single-sig native segwit, and only when the network setting matches. `Zpub` and `Vpub` are accepted only for multisig native segwit, with the same network check. They are converted to `xpub` or `tpub` before they are compared with stored keys. Exports stay `xpub` or `tpub`. Regtest has no extended-key prefix of its own: it uses the testnet prefixes (`tpub`, and `vpub` / `Vpub` for the SLIP-132 forms). The key screen can display the SLIP-132 form for comparison with a Trezor.

Dice and coin entropy follow SeedSigner: SHA-256 of the ASCII string, first 16 bytes for 12 words. That matches Ian Coleman's Base 10 or Hex mode with the mnemonic length set to 12 or 24 words, and it does not match his Dice [1-6] mode. Generation is 12 or 24 words. An 18-word mnemonic can be imported when its checksum is valid. Camera entropy follows SeedSigner's chain, including the CPU serial and the time, so the same scene does not repeat.

Passphrases follow BIP39, including Unicode and NFKD. The UI calls them passphrases. A warning appears below the text field when a passphrase is outside ASCII 32–126, is longer than 100 characters, or has a leading or trailing space. The spaces are kept.

An `OP_RETURN` output produces a transaction-level warning, and its payload can be shown as text or hex. A non-zero `OP_RETURN` amount blocks signing. Replace-by-fee warning appears when any input sequence is `0xFFFFFFFE` or `0xFFFFFFFF`. Locktime sentences use the raw number with "greater than". Relative locktime says "at least" and cites BIP68. Message signatures are base64. The About screen shows the BigSigner logo, the version, and an Licenses list for the bundled libraries and assets.

# Development process

For a quick development cycle, build a mechanism to run BigSigner on an emulator, so that you could see if the UI looks good without having to build the firmware and run it on the hardware.

Here is one emulator: https://github.com/enteropositivo/seedsigner-emulator
Another emulator can be found at: https://bitsaga.be/insights/seedsigner-browser-simulator - maybe this one is better, because it runs in the browser, and for coding agents like you (Cursor), you already have the tools to open a browser tab and see the UI.

We should also prepare infrastructure for automatic tests, that would "click" the emulated device in special places, insert/remove virtual sd-cards, open the camera for virtual QR code scanning, etc.

# UI elements

For this app, we will use UI elements common in smartphone apps.

- Hamburger menu - an icon in the top left corner that opens a menu.
- Back button - an icon in the top left corner that appears when the user is not on the main screen, and goes back to the previous screen.
- Screen title - a title at the top of the screen, usually in the center.
- Buttons are the brighter blue. Dark navy is only for a button that is currently deselected in a choice, such as the passphrase keyboard modes `abc`, `ABC`, `.?123`, and `#+=`: the chosen mode is brighter blue and the others are navy. A disabled button is grey, not navy.
- Button labels use Title Case. Capitalize each word. These words stay lowercase unless they are the first or last word: a, an, the, and, or, to, of, for, with, from, in. A word that is written in capitals stays in capitals, such as OK, QR, and SD. A technical token keeps its own spelling, such as xpub in "xpub only". Product terms keep their spelling: SingleSig, MultiSig, Native-Segwit, Taproot. Native-Segwit is written with a hyphen. The passphrase keyboard modes stay the literal strings `abc`, `ABC`, `.?123`, and `#+=`.
- Scrolling - after opening a menu or a submenu, a page could appear with content that is too long to fit on the screen. In this case, we need to detect scrolling and implement it. Scrolling should not include the Screen title.
- Confirmation dialog - a dialog that appear with a title and a message, with no back button, and two buttons at the buttom: "Cancel" and "Confirm". Texts may vary in some cases, and the Confirm button could be blue in some cases and red in others (font color should be white in the Confirm button).
- Warning dialog - similar to the confirmation dialog, but with one button.
- Keyboard - a virtual keyboard that appears when the user needs to enter text. The edited text should appear at the top of the screen and the keyboard should appear at the bottom, with option to click at different places in the text to move the cursor. The keyboard should have modes like Smartphone keyboards, to switch between uppercase/lowercase/numbers/symbols. The numbers mode is labeled `.?123` because it also contains the common punctuation (`- _ . , ' "`). `#+=` holds the remaining symbols.
- Text editing dialog - a dialog that appears when the user needs to edit texts (labels, descriptions, etc.). It should appear full screen, with the edited text at the top and the keyboard at the bottom. Users should be able to click at different places in the text to move the cursor. Some text editing dialogs may be for multiline texts and some for single-line texts (which will break visually when the text is too long to fit on the screen). If the text takes many lines, scrolling should be implemented as well. There should also be Cancel & OK buttons at the bottom (above the keyboard) that will exit the dialog.
- A circular plus button, usually in the bottom right corner of the screen, that hovers over the content and does not scroll with it.
- Dropdown menu - a text element with a chevron icon that opens a dropdown menu. The dropdown menu may be scrollable if it's above a certain height. It could also be infinite scrolling, with a function that loads the item at index X when the user scrolls enough to reach it. Click the item will select it as the value of the text element (each item represents a key-value pair - the user sees the value, and the key is used to identify the selected item).
- Read/Write SD Card dialogs - should allow to browse the SD Card file tree (clicking a directory will open it, non-root directories will show a ".." item at the top to go up) and select a file to read from or write to. In some cases write cases, the user should be able to enter a filename and create a new file.

Bitcoin addresses, key expressions, fingerprints, xpubs, txids, wallet descriptors and maybe other technical values should be displayed in a monospace font.

There should be no horizontal scolling. Long texts should be wrapped.

## Logo

Can be found at: https://github.com/BigSigner/bigsigner-os/blob/main/hdmi-touch-demo/logo.png
It would be nice to have the logo appear during boot animation, with a subtitle mentioning the version and another subtitle mentioning that this is a fork of SeedSigner.

## Internationalization

For the first version, we will only support English, but we do need to prepare for other languages as well.
This includes RTL languages. No need to switch the entire UI to RTL (i.e. buttons on the top left should remain on the top-left), but the text should be RTL-aware.

# Data structure

## Fingerprints

Fingerprints are 4-byte values (usually presented in hex form) used to identify keys.
When loading a seed the fingerprint is calculated from the seed. When loading an xpub, the fingerprint is given with the derivation path and the xpub.

Every fingerprint has one name, calculated from the fingerprint bytes and never stored as an editable nickname. The first three bytes are read as one integer, from 0 through 0xFFFFFF. That integer is divided across the adjective, color, and animal lists, so every such value has its own combination. The name ends with the last two hex characters of the fingerprint in uppercase. The lists are the dictionaries from unique-names-generator, keeping adjectives of at most 9 letters, colors of at most 9, and animals of at most 10: 982 adjectives, 51 colors, and 346 animals. Those are the shortest limits for which the lists still cover every value of three bytes. They are copied into the program, and that project's MIT notice is included with BigSigner. A seed and a key expression with the same fingerprint share that name. Adding or removing keys does not change it. The arithmetic is written out in docs/fingerprint-names.md.

Loaded passphrases are remembered in a map from the passphrase text to a number. The first time a passphrase is loaded, a global counter increases and that number is stored. A later seed that uses the same passphrase shows the same number, so the user can see that two seeds share a passphrase. The number is not reused. When a seed with a passphrase is removed, the passphrase is dropped from the map only if no other loaded seed still uses it. Entering it again later receives a new number.

Fingerprint are stored as a map of the fingerprint to the fingerprint object.

The fingerprint object will also contain a list of keys (seeds, seed+passphrases, SingleSig Xpubs, MultiSig Xpubs) that use this fingerprint.

Fingerprints should be removed silently automatically if no key uses them.

## Keys

There are 4 types of keys:

- Seeds: 12/18/24 words mnemonic phrases, following BIP39 standard. Seeds are used to generate extended public keys (xpubs) for derivation paths, as well as sign transactions. There must never be a collision between two different seeds with the same fingerprint (even if fingerprint collision is statistically possible).

- Seed + passphrase: Similar to a seed, this will also have a passphrase (a.k.a the 25th word of the seed).

- SingleSig Xpub key expression: A key expression containing a fingerprint, a derivation path and an xpub. e.g. `[d34db33f/84h/0h/0h]xpub.../<0;1>/*`. Derivation path will be one of single-sig paths, e.g. m/84h/0h/<account>h (kind: Native-Segwit) or m/86h/0h/<account>h (kind: Taproot). For now we will only support Native-Segwit and Taproot in SingleSig Xpubs. No need to support Legacy or Nested Segwit, nor custom derivation paths.

- MultiSig Xpub key expression: A key expression containing a fingerprint, a derivation path and an xpub. e.g. `[d34db33f/48h/0h/0h/2h]xpub.../<0;1>/*`. The derivation path is m/48h/0h/<account>h/2h (Native SegWit). Single-sig xpubs are Native SegWit (`m/84h/0h/<account>h`) or Taproot (`m/86h/0h/<account>h`). Legacy, nested SegWit, and custom derivation paths are not supported.

Each derivation path prefix has one script type. `m/84h/0h/<account>h` and `m/48h/0h/<account>h/2h` are Native SegWit. `m/86h/0h/<account>h` is Taproot. A script type that does not match its derivation path is not supported.

When a seed or seed + passphrase is created/loaded, it will be compared to all existing key expressions of the same fingerprint for collisions with other seeds, as well as for collisions with SingleSig/MultiSig xpub keys. For every SingleSig/MultiSig Xpub key expression with the same fingreprint, we should try to derive the derivation path using the seed and see that we get the same xpub. If the xpub is different - we should warn the user and block the creation of the new key. For every seed with the same fingerprint - we should compare all the seed words and passphrase. If different - we should warn the user and block the creation of the new key.

When adding a SingleSig/MultiSig Xpub key expression, it will be compared to all existing key expressions of the same fingerprint for collisions with existing seeds, as well as for collisions with existing SingleSig/MultiSig Xpub key expressions. For every seed/seed+passphrase with the same fingerprint, we should try to derive the derivation path using the seed and see that we get the same xpub. If the xpub is different - we should warn the user and block the creation of the new key. For every xpub with the same fingerprint and the same derivation path - we should compare the xpubs. If different - we should warn the user and block the creation of the new key.

Adding the same seed, seed + passphrase, SingleSig Xpub key expression, or MultiSig Xpub key expression twice should be blocked with a warning.

After adding a seed or seed + passphrase, existing SingleSig/MultiSig Xpub keys that are derived from the same fingerprint are simply redundant - we should warn the user and then remove them.
This means that if a seed or seed + passphrase is added, the fingerprint will basically have only one key in its list of keys.

When adding a SingleSig/MultiSig Xpub key expression, we could find a seed or seed + passphrase (with the same fingerprint) from which the same xpub can be derived. If so, we should warn the user and block the creation of the new key, because it's redundant.

Statistically it is possible to have a fingerprint collision, i.e. two different seeds that produce the same fingerprint. However, we should not allow it.

## Wallets

For the first version, we will support single-sig Native SegWit, single-sig Taproot, and native-segwit sorted multisig.
Legacy and nested SegWit will not be supported.

Wallets will be created from wallet descriptors that match one of the following formats (for now):
- `wpkh([{fingerprint1}/84h/0h/{account1}h]{xpub1}/<0;1>/*)#{checksum}`
- `tr([{fingerprint}/86h/0h/0h]{xpub1}/<0;1>/*)#{checksum}`
- `wsh(sortedmulti({m},[{fingerprint1}/48h/0h/{account1}h/2h]{xpub1}/<0;1>/*,[{fingerprint2}/48h/0h/{account2}h/2h]{xpub2}/<0;1>/*, ...))#{checksum}`
where the parts in the `{}` brackets differ between each possible descriptor.
There could be other minor variations, such as the `<0;1>` part being presented just as `0`, or the `h` being `'`. Research the different variations that wallets use for wallet-descriptors, standard and non-standard.

Wallets will not represent only the descriptor that created them, but a range of account(s).
For example, when loading a wallet descriptor like:
`wpkh([d34db33f/84h/0h/7h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/<0;1>/*)#9j2t7pxq`
the key expression `[d34db33f/84h/0h/7h]xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL` will first be added in the keys dataset - following the conditions that we described in the previous section, i.e. we can avoid adding it if we can derive the xpub from a seed that matches the fingerprint `d34db33f` using the derivation path `m/84h/0h/7h`.
Then, the wallet that will be added will be represented by:
- descriptor range: `wpkh([d34db33f/84h/0h/{account1}h]/<0;1>/*)`
- *default* account1: 7

This means the user could play with the `{account1}` substring and replacing it with different indexes, as long as we can find the xpub of `[d34db33f/84h/0h/{account1}h]` in the keys dataset or can derive it from a seed/seed+passphrase that matches the fingerprint `d34db33f`.

When opening a wallet in the UX, the default account index should be used only if we can find the key expression or derive from seed. Otherwise we should pick the minimal index that we can find a key-expression for.

For multisig wallets, this means that there could be multiple `{account1}`, `{account2}`, `{account3}`, ... for the user to play with.

Many Bitcoin wallet implementations confuse the concept of a "wallet" and fix it to a single account index but I want our wallet to be a tool that allows to change the account index.

Wallet adding should be block if there is already a wallet with the same descriptor range.
If the default account indexes of the new wallet that the user tries to add are exactly the same as the default account indexes of the existing wallet - the user warning should explain that the same wallet was already added.
If the default account indexes of the new wallet are different, there are two cases:
- The user could already have changed the account indexes to those new account indexes (i.e. they already had the fingerprints' seed, or those key expressions are already in the keys dataset). In this case the warning should explain that the wallet was already added, and the user could switch the account indexes from the default ones (mentioning the default account indexes values) to the new ones (mentioning the new account indexes values)
- The keys dataset did not contain the key expressions in the new wallet descriptor, and did not have a seed with a matching fingerprint to derive the xpubs dynamically. In this case, after adding the key expressions of the new wallet, a success message should appear, mentioning that the existing wallet account-indexes can now be switched to the new account-indexes (mentioning their values).

# UX

After booting with the BigSigner logo (showing the version and the subtitle "Fork of SeedSigner"), the user should be presented with a warning reccomending to remove the SD-card. That screen shows the logo with the version in small text under it. After the user confirms theys should see the Keys screen.

The Keys screen, Wallets screen, Settings screen and About screen should be accessible from the sidebar menu (which should be accessible from the hamburger menu on the top left corner of those screens).

Other screens are internal screens reachable by doing actions in those main screens - and should have a back button in the top left corner to go back one screen back.

## Keys screen

The title of the screen should be "Bitcoin Keys".
This will also be the default screen when the app is opened.
When no keys are present, the screen should show a message "No keys found. Press the plus button to add a new key."

The plus button (hovering over the bottom right corner of the screen) will open a menu with the options to add a new key, similar to SeedSigner:
- Scan QR Code
- Manual Entry
- Load from SD Card
- Generate New Seed

When adding a new key, we should first check if the key is already present - and warn the user if it is.

After adding a new key, we should go to the Key screen for the new key.

(See screens below for more details)

When there are keys present, the screen should show them grouped by the fingerprint in the screen content area (which will be scrollable in case it doesn't fit on the screen).

Seed cards come first, under a "Seeds" label. External keys follow in two sections, "SingleSig External Keys" and "MultiSig External Keys". A label is shown only when that section has a card. Each external key is its own card, including two keys that share a fingerprint. Seed cards are ordered by `key_counter`, using a card's earliest key. External cards in each section are ordered by fingerprint nickname, then Native-Segwit before Taproot, then account number.

The "Seeds" label has a key icon before it. Each external section has an eye icon before it. Each card shows the fingerprint name on two centered lines, broken after the second word:

```
Condemned Chocolate
Chimpanzee DD
```

Below the name is a fingerprint icon followed by the fingerprint hex. A seed card adds one more line under the fingerprint: a seedling icon, then the seed's first word followed by "...". If that seed has a passphrase, the line continues with " + Passphrase" and the passphrase's number, for example "Abandon... + Passphrase1". An external-key card adds two lines under the fingerprint hex: Native-Segwit or Taproot, then the account, for example "Native-Segwit" and "Account #0". The section title already says whether the key is single-sig or multisig.

If the fingerprint has a seed or seed + passphrase in its list of keys (in this case the list in this case will only contain one key), we should show in a new row a symbol of a key followed by a small title "Generated from a 12/18/24 words seed".
In the case of a seed + passphrase, it should say "Generated from a 12/18/24 words seed + passphrase" and that passphrase's number, for example "Generated from a 12 words seed + passphrase1".

If some of the keys are SingleSig Xpubs, we should show in a new row a symbol of an eye (read only) followed by a small title "SingleSig Xpubs", and below it a list of the SingleSig Xpub keys displayed as:
"<kind> Account <account>: <derivation path prefix>", e.g. "Native-Segwit Account 3: m/84h/0h/3h".

If some of the keys are MultiSig Xpubs, we should show in a new row a symbol of an eye (read only) followed by a small title "MultiSig Xpubs", and below it a list of the MultiSig Xpub keys displayed as:
"<kind> Account <account>: <derivation path prefix>", e.g. "Native-Segwit Account 3: m/48h/0h/3h/2h".

This should be followed by the xpub's first 19 letters followed by "...", e.g. "xpub6ERApfZw...".

Clicking a key or creating a new key will open the Key screen.

### Key screen

This screen, like other screens that cannot be reached from the sidebar menu, should have a back button in the top left corner.

For xpub key expressions, the screen will show the key's:
- Type
- Fingerprint nickname
- Fingerprint hex

The fingerprint name is the calculated adjective-color-animal-hex name. It is not editable. On the key screen it is broken after the second word. A seed has a key icon on the left of that name, and an external key has an eye icon, the same size as the fingerprint icon below it. The name lines start at the same left edge as "Fingerprint: ". The screen scrolls when the sentences and buttons do not fit under the title.

Xpub key expressions should also show the account, the derivation path (which includes the account), and the xpub. Type, account, the path, and the extended public key use the same size as the fingerprint line. "Derivation Path:" is its own line, and the path is centered on the next line. "Extended Public Key:" is its own line, and the 19-character preview is centered on the next line. Show Full Details comes next. Export to SD Card follows it. Delete Key is the next button after that, in the list, not pinned to the bottom.
Some xpub keys may have a zpub/Zpub presentation (Depending on the derivation path prefix, for exmaple if it begins with m/84h/0h/<account>h and we know that it's a Native-Segwit). Show Full Details shows a QR code of the key, followed by the text, and its format switcher offers Key Expression, the canonical extended key, and that SLIP-132 form when the path has one.
Export to SD Card opens a screen with those same choices. Key Expression writes `[{fingerprint}/{derivation path prefix}]{xpub}/<0;1>/*`. The other choices write that key alone, such as the xpub or the zpub. The next screen lists the SD card. Choosing a file asks to replace it. New File asks for a name and then writes that file. A name wider than the field scrolls sideways inside it. The passphrase field scrolls the same way.

Seed keys should have a button to show the seed, and a button to export the seed to the SD Card.
The button to show the seed should first show a warning message for the user to verify that nobody is peeking over their shoulder.
Showing the seed opens one screen. The words are in one column, in the same size used for entering seed words. The format switcher stays at the bottom. When the cards are taller than the space above it, as they are for 12 and 24 words, that card area scrolls and the title bar stays put. At the bottom, `<` and `>` switch the format, and the current format name is between them. The formats, in order, are Words, Compact SeedQR, and Text QR (the seed words in uppercase, separated by spaces). After the last format, `>` returns to Words. On Words, `<` goes to Text QR. Each QR format has a Zoom In button that opens a screen titled Zoomed QR. Its back button returns to the QR. The view is a 9×9 module grid on the right side of the screen, 46×46 pixels per module. On the Waveshare 4-inch 480×800 panel the pixels are 0.108 mm square, so each module is 4.97 mm × 4.97 mm, the nearest whole-pixel size to 5 mm. The row number is shown to the left of each row, and the column number above each column. Both count from 1 at the top-left module of the whole code, including its quiet zone, so a scrolled window still matches the same squares on a 5 mm school grid. The numbers use a small monospace font sized for two digits, and a smaller size when a number has three digits. Direction buttons sit in a 3×3 pad at the bottom: Up in the top center, Left and Right in the middle row, and Down in the bottom center. One module of empty space separates that pad from the grid. A direction button is grey when the view is already at that edge.

If there is a passphrase, a button should allow to show it (again, with a warning message for the user to verify that nobody is peeking over their shoulder). No need to export the passphrase. The passphrase screen wraps the text inside the page margins. A run of characters with no spaces still breaks onto the next line. When the wrapped lines are taller than the screen, the page scrolls and the title bar stays put.

If there is no passphrase, there should be a label saying that no passphrase is used in the seed.

There should be a button to create another seed with a different passphrase. With no passphrase set, the button is Create a Copy of This Seed with a Passphrase. With a passphrase set, it is Create a Copy of This Seed with a Different Passphrase.

When the key is a single-signature key expression, the button is Create a Native-Segwit SingleSig Wallet or Create a Taproot SingleSig Wallet. If that wallet is already loaded, it is Go to Native-Segwit SingleSig Wallet or Go to Taproot SingleSig Wallet. Native-Segwit stays on one line. In the future there could be key expressions that support multiple script-types, and then we should show a button for each script-type.
When it's a seed, or a seed + passphrase, there should be three buttons: "Derive a Native-Segwit SingleSig Key", "Derive a Native-Segwit MultiSig Key", and "Derive a Taproot SingleSig Key". Each button breaks after "Derive a", and again after "Native-Segwit" or "Taproot". Each opens a Derive Key screen for that script. The screen derives an extended public key from the seed at one account. It does not store another key. The first control is an account selector: minus on the left, plus on the right, and the account index in an editable field in the middle. Minus does nothing at account 0. Tapping the field opens the account keypad, and Use This Account returns with that index. The rest of the screen follows the External Key screen: the fingerprint name, the fingerprint, the type, the derivation path on its own centered line, and a 20-character extended-public-key preview on its own centered line. The preview is long enough that changing the account changes it. There is no Delete button. Show Full Details shows the derived key expression, the same way an external key's details do. Export to SD Card is the next button. It uses the account selected on this screen and then the same format choice and SD card file choice as an external key. A single-signature derivation also has the create-or-open wallet button. Creating a wallet uses the account selected on this screen and then opens the Wallet screen. If that single-signature wallet already exists, the button opens it and leaves its account unchanged. Back from that wallet returns to Bitcoin Wallets. The key screen and the Derive Key screen are not kept on the back stack. The same back stack is used when the button on an external key creates or opens its wallet. A multisig derivation has no wallet button, because a multisig wallet is assembled from keys rather than from one derived key.

And finally there should be a red Delete Key button that should warn the user before deleting the key.
Key deletion might cause some wallets to become unusable - because one of their key expressions will no longer be derivable for any account index. For example, if the key expression in a wallet's descriptor depends on a fingerprint with a seed and the seed is deleted, or if it depends on a fingerprint which has multiple Xpub key expressions and we delete all of them.
If the key deletion would make a wallet unusable, we should warn the user that the wallet will also be deleted. When exactly one wallet is named, the warning uses its short name in quotes, for example Wallet "Grateful Ivory Impala 0A Native-Segwit".
If a wallet will simply be affected by the key deletion (i.e. some account index will no longer be derivable), we warn about that as well, again quoting that wallet's short name when only one wallet is affected.

### Scan QR Code screen (for seed or xpub key expression)

Research the SeedSigner project for the different formats. This should support both a single QR code and a sequence of QR codes such as BBQr, and a QR code that contains a compressed seed.

The data is expected to be either a seed, a compressed seed, a SingleSig/MultiSig Xpub key expression in one of the formats as described before, or a zpub/Zpub presentation of a SingleSig/MultiSig Xpub key expression.

It is also allowed to be a wallet descriptor: a singlesig Native-Segwit or Taproot wallet (`wpkh` or `tr`), or a native-segwit multisig wallet (`wsh(sortedmulti(...))`). For example, `wpkh([d34db33f/84h/0h/7h]xpub.../<0;1>/*)#checksum`.
Notice that the wallet script-type (`wpkh`, `tr`, or `wsh(sortedmulti)`) must match the expected derivation path (`m/84h/0h/<account>h`, `m/86h/0h/<account>h`, or `m/48h/.../2h`). A descriptor of a kind this version does not support opens an error screen. That screen does not tell the user to go to the Bitcoin Wallets page.
Notice that the data can use the "'" format instead of the "h" format for the derivation path, "0" instead of "<0;1>", and the checksum should be verified whenever we scan a wallet descriptor.
Research online for different formats used by different wallets.
A supported singlesig descriptor opens a screen that says this is a singlesig wallet descriptor and asks whether to load both the wallet and the key, or only the key. Both Wallet and Key continues as if the same content had been loaded with the plus button on Bitcoin Wallets. Only the Key continues with that descriptor's key expression.
A supported multisig descriptor opens a screen that says this is a multisig wallet descriptor and asks whether to load the wallet and all the keys, or only a specific key. Load Both Wallet and All Keys continues as if the same content had been loaded with the plus button on Bitcoin Wallets. Below that button, after a larger gap, a menu lists the key expressions in the same order as the descriptor. Each entry is the fingerprint in hex, a space, the first 10 characters of the extended public key, and `...`. Load Only Selected Key continues with the selected key expression.

A bare key expression (`[fingerprint/path]xpub...`, including a `zpub`, `Zpub`, `vpub`, or `Vpub` spelling) is not stored immediately. BigSigner first checks:

- The derivation path is one this version supports for the current network. Otherwise it shows an error and does not store the key.
- The same fingerprint and path are not already loaded with this extended key. A duplicate is an error. A different extended key for that same path is also an error.
- If a seed with that fingerprint is already loaded, BigSigner derives the path. When the extended key matches, it says the original seed is already loaded, names that fingerprint, and does not store the external key. When it does not match, it says the key claims to belong to a previously-imported seed and names that seed, then says the extended public key is not the one that seed derives, that this is very suspicious, and that the odds of a real wallet producing it, rather than a bug or malicious code, are lower than the odds of winning the lottery. The key is not stored.

If one of those checks fails after a QR scan or an SD card file, BigSigner opens a screen titled Error loading key. The message is red. OK at the bottom leaves the flow and returns to Bitcoin Keys. A descriptor import from Bitcoin Wallets uses the same kind of screen, titled Error loading wallet, and OK returns to Bitcoin Wallets.

When none of those apply, BigSigner opens Load External Key. The first screen has a centered red subtitle, Warning. A single-signature key says you are about to load an external key for a singlesig wallet, and that the wallet owner must verify the extended public key on their hardware wallet before funds are sent. A multisig key says you are about to load an external key for a multisig wallet, and that the co-signer must verify the extended public key (xpub) on their hardware wallet. Show Extended Public Key Details at the bottom of that screen opens a second Load External Key screen. Its subtitle, Extended Public Key Details, is centered. While a wallet import is showing several new keys, that subtitle ends with the key's place in that sequence, such as 1/3. It shows "Verify this Extended Public Key on the other hardware wallet:" in that same larger size. A grey Format: label sits above a menu. The menu offers the canonical `xpub` or `tpub`, the SLIP-132 form when this path has one (`zpub`, `Zpub`, `vpub`, or `Vpub`), and the full key expression. The extended key or expression is shown below the menu in the same size used for the extended key on the External Key screen. Then it shows "Verify these details are backed up:" in that same larger size, the type, the account (with "(default)" when the account is 0, or the account number and "- non-default" in red otherwise), and the derivation path starting with `m`. The Type:, Account:, and Derivation Path: labels are grey, and their values stay in the body color. Continue is at the bottom of that scroll. Only that second Continue stores the key, and then BigSigner opens its External Key screen. Back from the details returns to the warning. Back from the warning leaves the key unloaded.

If the data includes only an xpub without a fingerprint or derivation path (i.e. it's not a full key expression) - the user should be warned and then let them try again.

QR code scanning functionality will be needed in multiple places. I suggest to implement a common mechanism for scanning QR codes that return their data and type, and then depending on the functionality verify the data type and warn the user if it's not one of the expected types. For example, if the user scans a QR code containing a PSBT where he is expected to scan a QR code of a seed.

While the scan or camera-entropy screen is open, the Raspberry Pi panel opens the camera and draws the live picture in the viewfinder on the screen. QR codes are read from those frames when zbar is installed. The emulator still shows the browser camera above the panel instead of inside the viewfinder.

### Manual Entry screen

Via a text-editing dialog.
User should first choose if they want to enter a seed or a SingleSig/MultiSig Xpub key expression.
If the user selects a seed, use the list of legit seed words from the BIP39 standard, and warn the user if they enter an invalid word (don't allow them the proceed to the next word or approve the dialog). The seed length is a dropdown of 12, 18, and 24 words. 24 words is selected when the screen opens. Words already entered are listed in one column.
If there are less than 8 ways to complete the word prefix, instead of showing the keyboard show the 8 words in two columns of 4 words each. and let the user select.
Specter-DIY has a nice UX for this (although somewhat different from what I just described). Learn from it to get a good UX for this.
Notice that the last word must be a checksum word, and the user should not be allowed to continue with an invalid word even if it is in the BIP39 standard.

Switching between 12, 18, and 24 words keeps the words already entered. Choosing a longer length keeps every word. Choosing 12 words keeps only the first 11, and choosing 18 words keeps only the first 17, so the checksum word can be entered again.

If the user selects a SingleSig/MultiSig Xpub key expression, use the same mechanism that we mentioned in the QR code scanning section - except that in this case we don't expect the content to be a seed (or a compressed QR code of a seed).

### Load from SD Card screen

Similar to QR code scanning, but simply read a text file from the SD card, trim spaces/newlines, and use the content as seed words, a key expression, or a wallet descriptor. A supported wallet descriptor uses the same choice screen as a descriptor scanned from Bitcoin Keys. The screen lists the card, including subfolders. A file or folder name that does not fit on one line wraps at the character that would overflow, for up to three lines. A name that still does not fit ends with `...` on the third line. A folder opens when tapped, and `..` goes up. The browser emulator uses the files kept beside the picture.
Similar to QR code scanning, this mechanism should be generic as we may need the idea of loading a file from the SD card in multiple places - for example reading a PSBT from the SD card. The mechanism should first return the data and type, and then depending on the functionality verify the data type and warn the user if it's not one of the expected types.
If the content type doesn't match, similar warning should appear (mentioning the expected type and the actual type).

Also research for other binary/textual file formats that might be used to store Bitcoin seeds/key-expressions/wallet-descriptors/PSBTs/etc., and support them if possible. e.g. bsms files.

### Generate New Seed screen

This screen should explain the user that to create a random seed, they need a safe source of randomness, and that BigSigner does not use a TRNG chip.

Then the user should be able to select the seed length (12/18/24 words) that they want, and the source of randomness: dice/coins/camera. 24 words is selected when the screen opens.

Follow the SeedSigner/Specter-DIY projects for how many dice/coins are required for each length of seed that the user wants (12/18/24 words), and use their exact standardized algorithms.
A sequence of dice/coins/camera entered on SeedSigner/Specter-DIY should produce the same seed as a sequence of dice/coins/camera entered on BigSigner.
Show the user the seed words to approve them - warn the user that he must backup the words. The words are the same one-column cards as the seed display, under the warning. Continue follows those cards. When the list is taller than the screen, as it is for 12 and 24 words, the page scrolls and the title bar stays put.

## Wallets screen

Wallets can be created from a SingleSig Xpub or a Seed/Seed+Passphrase screen, as we explained above.

They could be also created from a hovering plus button on the bottom right corner of the screen of this screen. Clicking the button should open a menu of:

- Scan QR Code
- Load from SD Card
- Select from Existing SingleSig Key
- Select from Existing MultiSig Keys

Scan QR Code and Load from SD Card should both expect a descriptor that belongs to one of the following formats:
- SingleSig Native-Segwit wallet descriptor: `wpkh([{fingerprint}/84h/0h/{account}h]{xpub}/<0;1>/*)#{checksum}`
- SingleSig Taproot wallet descriptor: `tr([{fingerprint}/86h/0h/0h]{xpub1}/<0;1>/*)#{checksum}`
- Multisig wallet descriptor: `wsh(sortedmulti({m},[{fingerprint1}/48h/0h/{account1}h/2h]{xpub1}/<0;1>/*,[{fingerprint2}/48h/0h/{account2}h/2h]{xpub2}/<0;1>/*, ...))#{checksum}`

Like mentioned before, small common variations of the format should be allowed, like using "'" instead of "h" for the derivation path, "0" instead of "<0;1>".
A BSMS 1.0 file is accepted when it has the version line, one descriptor, a path line for the same receive and change branches, and a first address. The descriptor must be single-sig native SegWit, single-sig Taproot, or native-segwit multisig, and its derivation paths must match that script type and the path line. The first address must be the address the descriptor derives. Any other version, script type, path, or address is refused.
Unexpected derivation paths, or unexpected script-types for known derivation paths, should not be allowed.
The checksum should be verified whenever we scan a wallet descriptor. Also support formats where the checksum is not present.
A `wsh(sortedmulti(...))` descriptor must only contain native-segwit multisig key expressions (`m/48h/0h/{account}h/2h`). Custom derivation paths are not supported.

A bare key expression is not a wallet descriptor on this screen. It is reported as a key expression, not a wallet descriptor. On the Bitcoin Keys screen, a single-sig key expression can still be wrapped as a wallet when the user creates one from that key.

A wallet's identity ignores descriptor key order, checksums, account indexes, extended-key spelling, and `h` versus `'`. It is the network, the script, the threshold, and the fingerprints sorted as bytes. `sortedmulti` already sorts pubkeys at address time, so two writings of the same cosigners are one wallet. The identity is that value, not a descriptor string split on commas.

A wallet's short name is `<fingerprint name> Native-Segwit` or `<fingerprint name> Taproot` for a single-signature wallet. For multisig it is `<m>-of-<n> <fingerprint hex>,<fingerprint hex>,...` in the wallet's own key order.

The descriptor that creates a multisig wallet sets that key order. When this device creates the wallet from Select from Existing MultiSig Keys, the keys are ordered by the compressed public key of each key's first receive address, compared as raw bytes. That is the order Sparrow uses for the receive descriptor. A descriptor loaded from elsewhere keeps the order written in that descriptor. The Wallet screen lists the keys in the saved order. A later descriptor does not reorder them. Messages that name account indexes as (X,Y,Z) use the order saved on the existing wallet. A descriptor that repeats one fingerprint is refused, because a wallet keeps one account index per fingerprint.

Scan QR Code and Load from SD Card follow one flow. A seed, a transaction, or a bare key expression is an error that names what it is and says it is not a wallet descriptor. An unsupported descriptor is an error that says it is not supported. OK returns to Bitcoin Wallets.

A descriptor may arrive as the text itself, as a crypto-output UR, or as a BBQr of that text. A UR is one code, or a fountain-coded sequence of codes. A BBQr is one code, or a numbered sequence, in hex, base32, or zlib. The camera stays on the scan screen until every part has been read, and the line under the viewfinder counts the parts. An SD card file is decoded the same way when the file is one complete code. One part of a sequence in a file asks for the camera. The same decoding applies when Bitcoin Keys scans a QR code.

Each key expression is checked the way a lone key expression is checked. If it names a loaded seed but the derived extended key differs, the suspicious-key error is shown and nothing is stored. A singlesig descriptor warns that the wallet owner must verify the extended public key. Its screen is titled Load External Key and its button is Show Extended Public Key Details. A multisig descriptor opens Load MultiSig Wallet when the wallet is not loaded yet, even when every key is already loaded or can be derived from a loaded seed. If that wallet is already loaded and every key is known, this screen is skipped. When some of its keys are already known, a line above Warning says how many of the wallet's keys were already loaded. When any keys are still new, Warning says you are about to load that many external keys for a multisig wallet, and the button is Show Extended Public Key Details. Each new key then has an Extended Public Key Details screen. The subtitle includes that key's place among the new keys, such as 2/3. Later keys in the same multisig skip the warning and open that details screen directly. Keys already loaded, or derivable from a loaded seed, are not shown. When every key is already known, there is no Warning and the button is Continue.

If this identity is already a wallet, the screen says Wallet "<short name>" was already loaded. With no new keys, it says this descriptor points to account-index X (default) when X is 0, or account-index X (non-default) otherwise. Several keys are account-indexes X (default),Y (non-default) in the wallet's key order. With new keys, those keys are added and the screen says the wallet was already loaded and that you can now also use those account indexes, with the same note on each index. Go to Wallet opens the wallet and sets the accounts from the descriptor. If the wallet is new, it is added and opened. Back from that wallet returns to Bitcoin Wallets.

After adding a wallet or clicking a wallet in the list, we should switch to it.

Each card on Bitcoin Wallets shows the script first: Native-Segwit, Taproot, or `<m>-of-<n>` followed by that kind. Under the title, each fingerprint name is two lines, broken after the second word. A key icon is on the left when that fingerprint's seed is loaded. An eye icon is on the left when the fingerprint is only an external key. Under each name, that fingerprint's hex is on its own line. The fingerprint icon is indented so it sits under the start of the name text, and the hex follows it. Each later key has extra space above its name. A multisig card does not show one shared row of every fingerprint.

In the plus button menu, "Select from Existing SingleSig Key" opens a screen titled SingleSig Key. A menu chooses Native-Segwit or Taproot. The list shows seeds and single-signature keys of that script, one row per fingerprint, sorted by fingerprint nickname. A multisig key is not listed. Each row shows a grey key icon and Seed, or a grey eye icon and External Key, above the fingerprint name. Several accounts of one external key read External Keys (N accounts). That line uses the fingerprint row's size. The row also shows the fingerprint name and the fingerprint, with a checkbox, and the fingerprint line begins with "Fingerprint: ". One key can be selected. Create Wallet makes that singlesig wallet and opens it. A seed uses account 0. An external key uses its lowest account for that script. If that wallet is already loaded, the button is Go to Wallet and opens it.

In the plus button menu, "Select from Existing MultiSig Keys" shuold do the following:
- The screen is titled Native-Segwit Multisig. Let the user choose "m" (for the m-of-n).
- List seeds and native-segwit multisig key expressions, sorted by fingerprint nickname. A single-signature key is not listed, because it cannot be a cosigner. Above the fingerprint name, a seed shows a grey key icon and Seed. An external key shows a grey eye icon and External Key, or External Keys (N accounts) when that fingerprint has several accounts. That line uses the fingerprint row's size. Show the fingerprint nicknames and fingerprints, with a checkbox next to each. The fingerprint line has a fingerprint icon and begins with "Fingerprint: ". User needs to select at least m keys.
- Create the wallet from the wallet descriptor range of the selected fingerprints. The descriptor lists those keys in the byte order of their first receive public keys. If that threshold and those keys are already a wallet, the button is Go to Wallet and opens it.

### Wallet screen

Show all the information about the wallet. The type is one line at the top: "Type: " followed by Native-Segwit, Taproot, or `<m>-of-<n>` and that kind. For each key, in order:
- The fingerprint name, broken after the second word, with a key icon for a seed or an eye icon for an external key
- A fingerprint icon, then "Fingerprint: " and the fingerprint hex
- An Account control

The fingerprint nickname is shown without the account index. If the seed or seed+passphrase is loaded, the account control is a text field: tapping it opens a number keyboard, and any account index can be entered. That keyboard does not repeat the fingerprint name. If only xpubs are loaded and more than one account is available, it is a dropdown of those account indexes. Account 0 is labeled `0 (default)` in the field and in the menu. When only one account is available, the line reads `Account: N`, with ` (default)` after 0, and there is no dropdown. In a multisig wallet each key has its own control. A singlesig account change lasts while that wallet screen is open. Back from the wallet returns the account to the index it had when the wallet was opened.

Below we should show the wallet descriptor (of the selected accounts) with xpubs replaced by 12 first letters followed by "...". Clicking that should show the full wallet descriptor, prettified (newlines and indentation after brackets), and below show it in a QR code. This screen could be scrollable.

Addresses opens the wallet addresses screen. Show Descriptor follows it. That screen is titled Descriptor. The QR is above the descriptor, and the descriptor puts each key on its own indented line. On a multisig wallet, grey text after the descriptor says a Native-Segwit multisig descriptor can list its key expressions in any order, and the checksum changes with that order. The page scrolls. Brightness is under the text. `<` and `>` at the bottom switch the QR format, and the format name is between them. The formats are UR and Plain QR. UR is the default. It is a crypto-output Uniform Resource, written in capitals in the QR, the encoding Sparrow uses for a wallet descriptor. Plain QR is the descriptor text. After Plain QR, `>` returns to UR. On UR, `<` goes to Plain QR. Export to SD Card is the next button. It writes a BSMS 1.0 file: `BSMS 1.0`, the wallet descriptor with its checksum, `/0/*,/1/*`, and the first receive address. The next screen lists the SD card. Choosing a file asks to replace it. New File asks for a name and then writes that file. A name wider than the field scrolls sideways inside it. The passphrase field scrolls the same way. There is no format menu. Delete Wallet stays last and red.

Then there should be a Sign Transaction button that will open the Sign transaction screen.

Then there should be a Sign Message button that will open the Sign message screen.

Then a Verify Address button.

Finally there should be a red Delete Wallet button.

### Wallet addresses screen

Two tabs: Receive and Change.

Then a scrollable list of addresses in one line each - avoid overflowing by replacing that last characters with "...".
Clicking an address will open a dialog with the address, whether it's recieve/change, the full derivation path (with xpubs replaced by 12 first letters followed by "..."), and the address as a QR code.
No need to support exporting the address to an SD card.

### Sign message screen

Follow the BIPs, SeedSigner and Specter-DIY projects for how to sign a message, using a private key of a receive/change address.
Message could be typed manually, loaded from an SD card, scanned from a QR code.
Signed message should be allowed to be exported as a QR code or to an SD card (The signature should be displayed in hex format, but there is no need to show the original message that was signed).

### Sign transaction screen

In this flow we first have to import a v0 or v2 PSBT, and verify that it's valid:
- All inputs belong to the selected wallet. In case of a multisig, a single input cannot belong to different address-indexes for different key expressions, nor have one key expression use a Receive index (0) and another use a Change index (1). A warning about a non-standard PSBT should be shown in this case, and the process should be blocked.
- Outputs that come with key expressions with the same fingerprints and the same derivation paths as our selected wallet (and selected account indexes) have derived the addresses correctly - those are change outputs.
- In case of a multisig, a single change-output cannot belong to different address-indexes for different key expressions, nor have one key expression use a Receive index (0) and another use a Change index (1). A warning about a non-standard PSBT should be shown in this case, and the process should be blocked.

Outputs that come with key expressions with a different fingerprint or an unrelated derivation path (e.g. Taproot vs Native-Segwit), or even different account indexes, are considered external outputs - as if they did not include any derivation info at all.

If one of the nSequence values is not in one of the inclusive ranges: 0xFFFFFFFD-0xFFFFFFFF, 0x00000000-0x0000FFFF, 0x00400000-0x0040FFFF - block the process with a warning about the suspecious nSequence value.

Let's discuss about other possible validations to prevent malicious PSBTs from misleading the user and causing them to lose funds.

If all inputs belong to the selected wallet descriptor range, but on a different sequence of account-indexes than currently selected, we should warn the user that the transaction spends funds form different accounts on this wallet, mentioning the PSBT's input account-indexes and the selected wallet's account-indexes. If the user confirms, we should switch to the new account-indexes and continue. This all assumes that we actually can switch to those account-indexes (have the relevant seeds/key-expressions) - otherwise we shouild warn the user that the transaction spends funds from accounts that we don't have the seeds/xpubs for, and quit.

First details to display is the PSBT version, then the txid, then:
- PSBT version (v0 or v2) and transaction version (1 or 2). Other versions are not supported. If the Bitcoin transaction version is not 2, it should be in red, followed by a warning that a legacy transaction version is being used. If the Bitcoin transaction version is 1, and one of the inputs has an nSequence other than 0xFFFFFFFD, 0xFFFFFFFE or 0xFFFFFFFF - the process should be blocked with a warning that the Bitcoin v1 transaction includes non-typical nSequence values.
- Amount sent to external addresses: sum of all outputs that do not belong to the selected wallet and the selected account-indexes
- Fee rate in sats/vB (always use 2 decimal places even if the number is rounded, e.g. 2.00 sats/vB), and the total fee amount in Bitcoin.
- Total amount deducted - the sum of the two above.
- List of external outputs: address and Bitcoin amount.

Amounts should always be displayed in Bitcoin units with 8 digits after the decimal point, even if the last digits are 0.

Then we should show a list of warnings, in red color, if they occur:
- The nLocktime is set to a timestamp, not a block height.
- All the nSequences are set to 0xFFFFFFFF, which means that the nLocktime is disabled.
- Some nSequence values are not 0xFFFFFFFE, which means the wallet may attempt to prevent a replace-by-fee capability, but disabling replace-by-fee is no longer supported by most of the Bitcoin network.
- Some nSequence values are in the range 0x00000000-0x0000FFFF, 0x00400000-0x0040FFFF - which means the wallet has relative locktimes on those inputs.
- One of the change outputs has an address that is derived from a Receive derivation path instead of a Change derivation path. This won't cause any loss of funds, but is not common in modern wallet usage.
- There is more than one change output.
- There is more than one external output.

Then we should show the nLocktime value after a label "Locktime:"
- If it's 0, a gray text should say "no locktime",
- If it's a block height, a text should say "This transaction can be mined only after block height <height>", Make a research if this means including/excluding the exact nLocktime value. This text should be grey, because many wallets usually put one of the latest block heights in new transactions, even if that block-height has passed and the transaction can be mined immediately.
- If it's a timestamp, a red text should say "This transaction can be mined only after <yyyy-mm-dd hh:mm:ss> UTC", and mention that timestamp evaluation is not always accurate.

Then there should be a closed Inputs section with a chevron icon. Clicking the icon or the title should open/close the section.
Opening the section shuold show a list of inputs, and for each input:
- Previous output txid:number.
- Previous output amount in Bitcoin.
- Previous output address.
- nSequence. Any value other than 0xFFFFFFFD should be in red.
- If the nSequence value is 0xFFFFFFFE or 0xFFFFFFFF, a red text should say that the wallet may attempt to prevent a replace-by-fee capability, but disabling replace-by-fee is no longer supported by most of the Bitcoin network.
- If the nSequence value is in the range 0x00000000-0x0000FFFF a red text should say there is a relative locktime on the input, and this input can be mined only X blocks after the output transaction was mined (research if we have to include/exclude the exact number of blocks, i.e. that we don't have an off-by-one error).
- If the nSequence value is in the range 0x00400000-0x0040FFFF a red text should say there is a relative locktime on the input, and this input can be mined only X days, Y hours, Z minutes and W seconds after the output transaction was mined (research how to calculate the time delta from the nSequence value, and make sure we don't have an off-by-one error). No need to mention X/Y/Z/W values if they are zero.

Then there should be a clsoed Outputs section with a chevron icon. Clicking the icon or the title should open/close the section.
Opening the section should show a list of outputs, and for each output:
- Address
- Whether it's a change or external output
- Bitcoin amount
- If it's a change output, the address index and a list from the key expressions:
  - `<Fingerprint nickname>: <Receive/Change> [<fingerprint hex>/<full derivation path for the address>]`
If a change output is actually a Receive address, the word "Receive" should be in red.

Then, for each fingerprint involved in the transaction inputs, we should show:
- `<Fingerprint nickname>: <Our seed or External seed> <not signed yet, some inputs are still missing signatures, or already signed>`.
- If we have the wallet's seed for the fingerprint and it's not signed yet or some inputs are still missing signatures, there should be a "Sign" button that will add the missing signatures using this fingerprint seed.

Once any signature is added, a "Continue" button should become enabled.
If we there were no signatures to add in the first place (either it's a read-only wallet or all the inputs that we have the seeds for are already signed), there should be text explaining the situation.

The next page should allow exporting the signed PSBT as a single QR code or a sequence of QR codes (default should be a sequence), or as a file on the SD card.
Make a research of the various formats, and let the user switch between them.

### Verify address screen

Scan a QR code of an address or enter it manually.
The first 100 receive/change addresses should be scanned to see if we found that address.
Warning should tell the user we could not find that address in the wallet's first 100 addresses, then ask the user if they want to scan the next 100 addresses (addresses 100-199, etc.).

I'm not sure whether it should be a 100 constant or less/more. Check what SeedSigner & Specter-DIY do.

### Settings screen

A Network label with a dropdown for mainnet, testnet, and regtest. Choosing another network removes existing wallets and xpub keys, because their derivation paths are not valid on the new network. Seeds stay in memory.

Let's discuss what general settings are available on SeedSigner & Specter-DIY. I don't want the user to switch from BTC units to sats. amounts should always be shown with 8 digits after the decimal point.

### About screen

The About screen shows the BigSigner logo, the name and version, that this is a fork of SeedSigner, and that the hardware is a portrait 480×800 HDMI touchscreen. An Licenses button opens a scrollable list. Each row names one bundled work and its license, and opens that notice, which also scrolls. The list is the unique-names-generator word lists, embit, Pillow, qrcode, the DejaVu fonts, Font Awesome Free, and the SeedSigner icons. The same notices are kept in LICENSE.

# Tests

Bitcoin wallet apps that run on untrusted computers can try to generate malicious QR codes for seeds/PSBTS/etc. in order to trick the user.
Make a research and a lot of tests to prevent this.
Make a test for every blocker in the spec.
Use the emulator to take screenshots for the test results, that could be reviewed manually by me or by an AI agent.
Suggest possible tests cases, and learn from SeedSigner & Specter-DIY tests.

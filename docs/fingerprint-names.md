# Fingerprint names

A seed or an external key is labeled with a name calculated from its fingerprint. The name is not chosen by the person using the device, and it is not stored on its own. The same fingerprint always produces the same name.

The fingerprint is the first four bytes of the HASH160 of the master public key. On screen it is eight hex characters, such as `73c5da0a`.

## Calculation

`animal_name` in `src/bigsigner/names.py` does this:

1. Read the first three fingerprint bytes as a big-endian integer `V`. `V` is from 0 through 16,777,215 (`0xFFFFFF`).
2. The adjective is `ADJECTIVES[V mod 982]`. Replace `V` with `V // 982`.
3. The color is `COLORS[V mod 51]`. Replace `V` with `V // 51`.
4. The animal is `ANIMALS[V mod 346]`.
5. Append the last two hex characters of the whole fingerprint, in uppercase.

There are 982 adjectives, 51 colors, and 346 animals: 17,328,372 combinations. That is more than 2^24, so every value of the first three bytes has its own combination. The last fingerprint byte is not used to pick the words. It appears only as the two hex characters, so two fingerprints that share their first three bytes and differ in the last byte share the words and differ in the suffix.

## Example

The 12-word phrase that is `abandon` eleven times and then `about`, with no passphrase, has fingerprint `73c5da0a`.

The first three bytes are `0x73c5da`, which is 7,587,290.

- `7587290 mod 982 = 358`, and adjective 358 is Grateful. `7587290 // 982 = 7726`.
- `7726 mod 51 = 25`, and color 25 is Ivory. `7726 // 51 = 151`.
- `151 mod 346 = 151`, and animal 151 is Impala.
- The last two hex characters are `0A`.

The name is **Grateful Ivory Impala 0A**.

## Word lists

There is no standard that encodes a number as an adjective, a color, and an animal. The three lists are the dictionaries from [unique-names-generator](https://github.com/andreasonny83/unique-names-generator). A word is kept when the adjective has at most 9 letters, the color at most 9, and the animal at most 10. Those are the shortest limits for which the three lists still cover every value of three bytes. They are copied into `src/bigsigner/names.py` so the device does not need that library. The lists are MIT licensed, Copyright (c) 2018-2022 AndreaSonny. The notice is in `LICENSE` and on the device under About, Licenses.

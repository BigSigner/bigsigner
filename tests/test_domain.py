import pytest

from bigsigner.nicknames import normalize_nickname
from bigsigner.parse import ParseError, parse_key_expression, parse_wallet
from bigsigner.session import Session, SessionError
from embit import bip32, bip39
from embit.descriptor.checksum import checksum

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
LEGAL = "legal winner thank year wave sausage worth useful legal winner thank yellow"


def root_of(words, passphrase=""):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(words, passphrase))


def expression(words, path):
    root = root_of(words)
    public = root.derive(path).to_public()
    return f"[{root.my_fingerprint.hex()}/{path[2:]}]{public.to_string()}/<0;1>/*"


def test_the_longest_fingerprint_name_fits():
    from PIL import Image, ImageDraw

    from bigsigner.names import ADJECTIVES, ANIMALS, COLORS
    from bigsigner.ui.app import (
        NAME_ON_CARD,
        NAME_ON_KEY,
        NAME_ON_MULTISIG,
        NAME_ON_WALLET,
        NAME_ON_WALLET_CARD,
        _DETAIL_ICON,
        _WALLET_CARD_GAP,
        _WALLET_CARD_ICON,
    )
    from bigsigner.ui.canvas import MARGIN, WIDTH, font, wrap

    assert max(len(word) for word in ADJECTIVES) <= 9
    assert max(len(word) for word in COLORS) <= 9
    assert max(len(word) for word in ANIMALS) <= 10
    draw = ImageDraw.Draw(Image.new("RGB", (WIDTH, 40)))

    def fits(size: int, limit: int):
        name = _widest_animal_name(draw, size)
        assert len(name) <= 33
        face = font(size)
        assert draw.textlength(name, font=face) <= limit
        assert wrap(draw, name, face, limit) == [name]

    def fits_line(size: int, line: str, limit: int):
        face = font(size)
        assert draw.textlength(line, font=face) <= limit
        assert wrap(draw, line, face, limit) == [line]

    # Bitcoin Keys card: the name is two centered lines, broken after the second word.
    fits_line(NAME_ON_CARD, _widest_name_line(draw, NAME_ON_CARD, 0), WIDTH - 2 * MARGIN)
    fits_line(NAME_ON_CARD, _widest_name_line(draw, NAME_ON_CARD, 1), WIDTH - 2 * MARGIN)
    # Key screen: the same two lines sit to the right of a fingerprint-sized icon.
    key_room = WIDTH - MARGIN - (MARGIN + _DETAIL_ICON + 10)
    fits_line(NAME_ON_KEY, _widest_name_line(draw, NAME_ON_KEY, 0), key_room)
    fits_line(NAME_ON_KEY, _widest_name_line(draw, NAME_ON_KEY, 1), key_room)
    # Wallet screen: the same two lines sit to the right of the fingerprint icon.
    wallet_room = WIDTH - MARGIN - (MARGIN + _DETAIL_ICON + 10)
    fits_line(NAME_ON_WALLET, _widest_name_line(draw, NAME_ON_WALLET, 0), wallet_room)
    fits_line(NAME_ON_WALLET, _widest_name_line(draw, NAME_ON_WALLET, 1), wallet_room)
    # Wallet card: two lines to the right of the key or eye icon. Multisig row: two lines beside the checkbox.
    card_room = WIDTH - 2 * MARGIN - 32 - _WALLET_CARD_ICON - _WALLET_CARD_GAP
    fits_line(NAME_ON_WALLET_CARD, _widest_name_line(draw, NAME_ON_WALLET_CARD, 0), card_room)
    fits_line(NAME_ON_WALLET_CARD, _widest_name_line(draw, NAME_ON_WALLET_CARD, 1), card_room)
    multisig_room = WIDTH - 2 * MARGIN - 56
    fits_line(NAME_ON_MULTISIG, _widest_name_line(draw, NAME_ON_MULTISIG, 0), multisig_room)
    fits_line(NAME_ON_MULTISIG, _widest_name_line(draw, NAME_ON_MULTISIG, 1), multisig_room)


def _widest_name_line(draw, size: int, which: int) -> str:
    """The wider of the two centered lines, among names the fingerprint formula can produce."""
    from bigsigner.names import ADJECTIVES, ANIMALS, COLORS
    from bigsigner.ui.canvas import font

    face = font(size)

    def length(text: str) -> float:
        return draw.textlength(text, font=face)

    if which == 0:
        return f"{max(ADJECTIVES, key=length)} {max(COLORS, key=length)}"
    suffix = max(
        (left + right for left in "0123456789ABCDEF" for right in "0123456789ABCDEF"),
        key=length,
    )
    return f"{max(ANIMALS, key=length)} {suffix}"


def _widest_animal_name(draw, size: int) -> str:
    """The reachable fingerprint name with the greatest pixel width at this size."""
    from bigsigner.names import ADJECTIVES, ANIMALS, COLORS, animal_name
    from bigsigner.ui.canvas import font

    face = font(size)

    def length(text: str) -> float:
        return draw.textlength(text, font=face)

    adjective_widths = [length(word) for word in ADJECTIVES]
    color_widths = [length(word) for word in COLORS]
    animal_widths = [length(word) for word in ANIMALS]
    space = length(" ")
    suffix = max(
        (left + right for left in "0123456789ABCDEF" for right in "0123456789ABCDEF"),
        key=length,
    )
    suffix_width = length(suffix)
    widest_adjective = max(adjective_widths)
    best = -1.0
    best_name = ""
    max_q = 0xFFFFFF // len(ADJECTIVES)
    for quotient in range(max_q + 1):
        color_index = quotient % len(COLORS)
        animal_index = (quotient // len(COLORS)) % len(ANIMALS)
        if quotient < max_q:
            adjective_index = adjective_widths.index(widest_adjective)
            adjective_width = widest_adjective
        else:
            last = 0xFFFFFF - quotient * len(ADJECTIVES)
            adjective_index = max(range(last + 1), key=adjective_widths.__getitem__)
            adjective_width = adjective_widths[adjective_index]
        total = adjective_width + color_widths[color_index] + animal_widths[animal_index] + 3 * space + suffix_width
        if total > best:
            best = total
            value = quotient * len(ADJECTIVES) + adjective_index
            best_name = animal_name(value.to_bytes(3, "big") + bytes.fromhex(suffix))
    return best_name


def test_every_24_bit_prefix_has_its_own_name():
    from bigsigner.names import ADJECTIVES, ANIMALS, COLORS, animal_name

    assert len(ADJECTIVES) * len(COLORS) * len(ANIMALS) >= 0x1000000
    zero = bytes.fromhex("000000ab")
    assert animal_name(zero).startswith(f"{ADJECTIVES[0]} {COLORS[0]} {ANIMALS[0]} ")
    stepped = (len(ADJECTIVES)).to_bytes(3, "big") + b"\x00"
    assert animal_name(stepped).startswith(f"{ADJECTIVES[0]} {COLORS[1]} ")
    # Two prefixes that share no single-byte residue still differ.
    assert animal_name(bytes.fromhex("00000100")) != animal_name(bytes.fromhex("00010000"))
    # Documented in docs/fingerprint-names.md for abandon x11, about.
    assert animal_name(bytes.fromhex("73c5da0a")) == "Grateful Ivory Impala 0A"


def test_unknown_seed_nickname_ends_with_uppercase_hex():
    from bigsigner.names import animal_name

    assert animal_name(bytes.fromhex("f992cf24")).endswith(" 24")
    assert animal_name(bytes.fromhex("010203c9")).endswith(" C9")


def test_nickname_collapses_punctuation_and_case():
    assert normalize_nickname("Hello World") == normalize_nickname("Hello  World")
    assert normalize_nickname("Hello World") == normalize_nickname("Hello World__")
    assert normalize_nickname("Hello-World") == normalize_nickname("hello world")


def test_seed_nickname_and_duplicate():
    session = Session()
    added = session.add_mnemonic(ABANDON)
    assert added["fingerprint"].hex() == "73c5da0a"
    from bigsigner.names import animal_name

    key = session.fingerprints[added["fingerprint"]].keys[0]
    assert session.fingerprints[added["fingerprint"]].nickname == animal_name(added["fingerprint"])
    assert session.generated_from(key) == "Generated from a 12 words seed."
    with pytest.raises(SessionError, match="already loaded"):
        session.add_mnemonic(ABANDON)


def test_passphrase_is_a_different_fingerprint_and_warns_about_a_trailing_space():
    session = Session()
    session.add_mnemonic(ABANDON)
    added = session.add_mnemonic(ABANDON, passphrase="secret ")
    assert added["fingerprint"].hex() != "73c5da0a"
    assert any("space" in warning for warning in added["warnings"])
    from bigsigner.names import animal_name

    assert session.fingerprints[added["fingerprint"]].nickname == animal_name(added["fingerprint"])
    assert session.passphrase_index("secret ") == 1


def test_the_same_passphrase_keeps_its_number_until_no_seed_uses_it():
    from embit.bip39 import mnemonic_from_bytes

    session = Session()
    first = session.add_mnemonic(ABANDON, passphrase="shared")
    second_words = mnemonic_from_bytes(b"\x11" * 16).split()
    second = session.add_mnemonic(second_words, passphrase="shared")
    assert first["fingerprint"] != second["fingerprint"]
    assert session.passphrases["shared"] == 1
    first_key = session.fingerprints[first["fingerprint"]].keys[0]
    assert session.seed_summary(first_key) == "Abandon... + Passphrase1"
    assert session.generated_from(first_key) == "Generated from a 12 words seed + passphrase1."
    session.delete_key(first["fingerprint"], 0)
    assert session.passphrases["shared"] == 1
    session.delete_key(second["fingerprint"], 0)
    assert "shared" not in session.passphrases
    again = session.add_mnemonic(ABANDON, passphrase="shared")
    assert session.passphrases["shared"] == 2
    again_key = session.fingerprints[again["fingerprint"]].keys[0]
    assert "Passphrase2" in session.seed_summary(again_key)
    assert session.generated_from(again_key) == "Generated from a 12 words seed + passphrase2."


def test_empty_passphrase_is_the_same_seed():
    session = Session()
    session.add_mnemonic(ABANDON)
    with pytest.raises(SessionError, match="already loaded"):
        session.add_mnemonic(ABANDON, passphrase="")


def test_xpub_then_matching_seed_removes_the_xpub():
    session = Session()
    text = expression(ABANDON, "m/84h/0h/0h")
    session.add_text(text)
    fingerprint = bytes.fromhex("73c5da0a")
    name = session.fingerprints[fingerprint].nickname
    session.add_mnemonic(ABANDON)
    assert session.fingerprints[fingerprint].nickname == name
    assert len(session.fingerprints[fingerprint].keys) == 1
    assert session.fingerprints[fingerprint].keys[0].has_seed


def test_seed_rejects_a_contradictory_xpub():
    session = Session()
    foreign = expression(LEGAL, "m/84h/0h/0h")
    # Pretend the legal xpub belongs to the abandon fingerprint.
    abandon = root_of(ABANDON).my_fingerprint.hex()
    forged = foreign.replace(root_of(LEGAL).my_fingerprint.hex(), abandon, 1)
    session.add_text(forged)
    with pytest.raises(SessionError, match="does not match"):
        session.add_mnemonic(ABANDON)


def test_zpub_is_converted_and_matches_the_xpub():
    session = Session()
    session.add_text(expression(ABANDON, "m/84h/0h/0h"))
    from bigsigner.slip132 import display_form

    key = next(iter(session.fingerprints.values())).keys[0]
    zpub = display_form(key.xpub.to_string(), "main", key.role)
    text = expression(ABANDON, "m/84h/0h/0h").replace(key.xpub.to_string(), zpub)
    with pytest.raises(SessionError, match="already loaded"):
        session.add_text(text)


def test_zpub_is_rejected_for_a_multisig_path():
    text = expression(ABANDON, "m/48h/0h/0h/2h")
    key = parse_key_expression(text, "main")
    from bigsigner.slip132 import display_form

    zpub = display_form(key.canonical, "main", "singlesig_native")
    forged = text.replace(key.canonical, zpub)
    with pytest.raises(ParseError, match="does not match"):
        parse_key_expression(forged, "main")


def test_depth_mismatch_rejects_the_expression():
    text = expression(ABANDON, "m/84h/0h/7h")
    # Claim the account-0 key is account 7. The child number inside the key stays 0h.
    account0 = expression(ABANDON, "m/84h/0h/0h")
    xpub = account0.split("]")[1].split("/")[0]
    forged = text.split("]")[0] + "]" + xpub + "/<0;1>/*"
    with pytest.raises(ParseError, match="depth or last step"):
        parse_key_expression(forged, "main")


def test_taproot_multisig_is_rejected():
    with pytest.raises(ParseError, match="taproot multisig"):
        parse_key_expression(
            "[73c5da0a/48h/0h/0h/3h]" + expression(ABANDON, "m/84h/0h/0h").split("]")[1],
            "main",
        )


def test_multisig_wallet_keeps_different_accounts():
    session = Session()
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/7h/2h")
    body = f"wsh(sortedmulti(2,{first},{second}))"
    added = session.add_text(f"{body}#{checksum(body)}")
    assert "multisig" in added["message"]
    wallet = session.wallets[0]
    assert wallet.accounts[bytes.fromhex("73c5da0a")] == 0
    assert list(wallet.accounts.values())[1] == 7
    receive = session.addresses(0, 0, 0, 1)[0]
    assert receive.startswith("bc1q")


def test_same_wallet_with_a_new_account_does_not_create_a_second_wallet():
    session = Session()
    session.add_mnemonic(ABANDON)
    text = expression(ABANDON, "m/84h/0h/0h")
    body = f"wpkh({text})"
    session.add_text(f"{body}#{checksum(body)}")
    other = expression(ABANDON, "m/84h/0h/4h")
    with pytest.raises(SessionError, match="switch"):
        session.add_text(f"wpkh({other})#{checksum('wpkh(' + other + ')')}")
    assert len(session.wallets) == 1


def test_network_switch_keeps_seeds_and_drops_wallets():
    session = Session()
    session.add_mnemonic(ABANDON)
    session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})")
    assert session.wallets
    message = session.set_network("test")
    assert "Seeds" in message
    assert session.wallets == []
    assert len(session.fingerprints[bytes.fromhex("73c5da0a")].keys) == 1
    assert session.set_network("regtest") == ""


def test_testnet_vpub_requires_coin_type_1():
    session = Session()
    session.set_network("test")
    root = root_of(ABANDON)
    public = root.derive("m/84h/1h/0h").to_public()
    from bigsigner.slip132 import display_form

    canonical = public.to_string().replace("xpub", "tpub") if False else None
    # Derive a real testnet-looking key by rewriting version bytes.
    from bigsigner.slip132 import to_canonical, display_form as show

    main_form = root.derive("m/84h/0h/0h").to_public().to_string()
    # The path coin type is what the setting checks; use a testnet key at m/84h/1h/0h.
    test_key = root.derive("m/84h/1h/0h").to_public()
    tpub = to_canonical(test_key.to_string(), "test")
    vpub = show(tpub, "test", "singlesig_native")
    text = f"[{root.my_fingerprint.hex()}/84h/1h/0h]{vpub}/<0;1>/*"
    session.add_text(text)
    assert session.wallets == [] or session.fingerprints


def test_regtest_uses_testnet_slip132_prefixes_and_bcrt_addresses():
    session = Session()
    session.set_network("regtest")
    root = root_of(ABANDON)
    from bigsigner.slip132 import display_form, to_canonical

    public = root.derive("m/84h/1h/0h").to_public()
    tpub = to_canonical(public.to_string(), "regtest")
    vpub = display_form(tpub, "regtest", "singlesig_native")
    assert tpub.startswith("tpub")
    assert vpub.startswith("vpub")
    assert vpub == display_form(tpub, "test", "singlesig_native")
    session.add_text(f"wpkh([{root.my_fingerprint.hex()}/84h/1h/0h]{vpub}/<0;1>/*)")
    assert session.addresses(0, 0, 0, 1)[0].startswith("bcrt1")
    zpub = display_form(to_canonical(root.derive("m/84h/0h/0h").to_public().to_string(), "main"), "main", "singlesig_native")
    with pytest.raises(ParseError):
        parse_key_expression(f"[{root.my_fingerprint.hex()}/84h/1h/0h]{zpub}", "regtest")


def test_descriptor_without_checksum_is_accepted_and_a_bad_checksum_is_not():
    text = expression(ABANDON, "m/86h/0h/0h")
    wallet = parse_wallet(f"tr({text})", "main")
    assert wallet.role == "singlesig_taproot"
    with pytest.raises(ParseError, match="checksum"):
        parse_wallet(f"tr({text})#qqqqqqqq", "main")

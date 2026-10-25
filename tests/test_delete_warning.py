from embit import bip32, bip39
from embit.descriptor.checksum import checksum

from bigsigner.paths import MULTISIG_NATIVE, parse_path
from bigsigner.session import Session, StoredKey

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def root_of(words, passphrase=""):
    return bip32.HDKey.from_seed(bip39.mnemonic_to_seed(words, passphrase))


def expression(words, path, passphrase=""):
    root = root_of(words, passphrase)
    public = root.derive(path).to_public()
    return f"[{root.my_fingerprint.hex()}/{path[2:]}]{public.to_string()}/<0;1>/*"


def load(session: Session, body: str):
    session.add_text(f"{body}#{checksum(body)}")


def singlesig(session: Session, words: str, path: str, passphrase: str = ""):
    script = "tr" if path.startswith("m/86h/") else "wpkh"
    load(session, f"{script}({expression(words, path, passphrase)})")


def multisig(session: Session, members: list[tuple[str, str, str]]):
    keys = ",".join(expression(words, path, passphrase) for words, path, passphrase in members)
    load(session, f"wsh(sortedmulti({len(members)},{keys}))")


def fingerprint(words: str, passphrase: str = "") -> bytes:
    return root_of(words, passphrase).my_fingerprint


def test_delete_warning_when_no_wallet_depends_on_the_key():
    session = Session()
    session.add_mnemonic(ABANDON)
    other = fingerprint(ABANDON, "other")
    session.add_mnemonic(ABANDON, passphrase="other")
    singlesig(session, ABANDON, "m/84h/0h/0h", "other")
    message = session.deletion_message(fingerprint(ABANDON), 0)
    assert message == "Delete this key?"
    assert other in session.wallets[0].fingerprints


def test_delete_warning_when_one_wallet_will_be_removed():
    session = Session()
    singlesig(session, ABANDON, "m/84h/0h/0h")
    fp = fingerprint(ABANDON)
    message = session.deletion_message(fp, 0)
    name = session.wallet_short_name_of(session.wallets[0])
    assert message == f'Delete this key? Wallet "{name}" depends on it and will be removed.'


def test_delete_warning_when_several_wallets_will_be_removed():
    session = Session()
    session.add_mnemonic(ABANDON)
    singlesig(session, ABANDON, "m/84h/0h/0h")
    singlesig(session, ABANDON, "m/86h/0h/0h")
    message = session.deletion_message(fingerprint(ABANDON), 0)
    assert message == "Delete this key? 2 wallets depend on it and will be removed."


def test_delete_warning_when_one_wallet_loses_an_account():
    session = Session()
    singlesig(session, ABANDON, "m/84h/0h/4h")
    singlesig(session, ABANDON, "m/84h/0h/0h")
    fp = fingerprint(ABANDON)
    account0 = next(index for index, key in enumerate(session.fingerprints[fp].keys) if key.account == 0)
    message = session.deletion_message(fp, account0)
    name = session.wallet_short_name_of(session.wallets[0])
    assert message == (
        f'Delete this key? Wallet "{name}" depends on it and will not be able to use account-index 0.'
    )


def test_delete_warning_when_several_wallets_lose_accounts():
    session = Session()
    session.add_text(expression(ABANDON, "m/48h/0h/7h/2h"))
    session.add_text(expression(ABANDON, "m/48h/0h/0h/2h"))
    partners = ("one", "two", "three")
    for passphrase in partners:
        session.add_mnemonic(ABANDON, passphrase=passphrase)
        multisig(
            session,
            [
                (ABANDON, "m/48h/0h/0h/2h", ""),
                (ABANDON, "m/48h/0h/0h/2h", passphrase),
            ],
        )
    fp = fingerprint(ABANDON)
    account0 = next(index for index, key in enumerate(session.fingerprints[fp].keys) if key.account == 0)
    message = session.deletion_message(fp, account0)
    assert message == (
        "Delete this key? 3 wallets depend on it and will not be able to use some account-indexes."
    )


def test_delete_warning_when_some_wallets_are_removed_and_some_lose_accounts():
    session = Session()
    session.add_mnemonic(ABANDON)
    singlesig(session, ABANDON, "m/84h/0h/0h")
    singlesig(session, ABANDON, "m/86h/0h/0h")
    partners = ("one", "two", "three")
    for passphrase in partners:
        session.add_mnemonic(ABANDON, passphrase=passphrase)
        multisig(
            session,
            [
                (ABANDON, "m/48h/0h/0h/2h", ""),
                (ABANDON, "m/48h/0h/0h/2h", passphrase),
            ],
        )
    fp = fingerprint(ABANDON)
    public = root_of(ABANDON).derive("m/48h/0h/5h/2h").to_public()
    spare = StoredKey("xpub", fp, path=parse_path("m/48h/0h/5h/2h"), xpub=public, account=5)
    spare.role = MULTISIG_NATIVE
    session.fingerprints[fp].keys.append(spare)
    message = session.deletion_message(fp, 0)
    assert message == (
        "Delete this key? 2 wallets depend on it and will be removed. "
        "3 wallets depend on it and will not be able to use some account-indexes."
    )

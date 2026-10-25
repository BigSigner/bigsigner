from embit.psbt import DerivationPath, PSBT
from embit.script import address_to_scriptpubkey
from embit.transaction import Transaction, TransactionInput, TransactionOutput

from bigsigner.entropy import mnemonic_from_coins, mnemonic_from_dice
from bigsigner.psbt_review import ReviewError, review_psbt
from bigsigner.seedqr import compact_bytes, mnemonic_from_compact, mnemonic_from_standard, standard_digits
from bigsigner.session import Session

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def test_seedsigner_dice_vector():
    rolls = "65515223131652132161133154444123616466443112153441"
    assert (
        mnemonic_from_dice(rolls)
        == "hole luggage safe present express tragic orbit shed switch metal identify path"
    )


def test_coin_flips_are_hashed_as_text():
    assert mnemonic_from_coins("0" * 128) == mnemonic_from_coins("0" * 128)
    assert mnemonic_from_coins("0" * 128) != mnemonic_from_coins("1" * 128)


def test_seedqr_round_trip():
    assert mnemonic_from_standard(standard_digits(ABANDON)) == ABANDON
    assert mnemonic_from_compact(compact_bytes(ABANDON)) == ABANDON


def _funded(session):
    session.add_mnemonic(ABANDON)
    text = None
    from embit import bip32, bip39
    from embit.descriptor.checksum import checksum

    def expression(words, path):
        root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(words))
        public = root.derive(path).to_public()
        return f"[{root.my_fingerprint.hex()}/{path[2:]}]{public.to_string()}/<0;1>/*"

    key = expression(ABANDON, "m/84h/0h/0h")
    session.add_text(f"wpkh({key})#{checksum('wpkh(' + key + ')')}")
    receive = session.addresses(0, 0, 0, 1)[0]
    return receive


def test_psbt_review_blocks_a_nonzero_op_return_and_warns_on_final_sequence():
    session = Session()
    receive = _funded(session)
    script = address_to_scriptpubkey(receive)
    destination = address_to_scriptpubkey(
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
    )
    op_return = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    del op_return
    from embit.script import Script

    data = Script(b"\x6a\x05hello")
    tx = Transaction(
        version=2,
        vin=[TransactionInput(b"\x11" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[
            TransactionOutput(90_000, destination),
            TransactionOutput(0, data),
        ],
    )
    psbt = PSBT(tx)
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, script)
    wallet = session.wallets[0]
    fingerprint = wallet.fingerprints[0]
    public = session._seed_for(fingerprint)
    from bigsigner.session import _derive_public, _account_path

    derived = _derive_public(public, _account_path("main", wallet.role, 0))
    child = derived.derive("m/0/0")
    path = _account_path("main", wallet.role, 0) + [0, 0]
    psbt.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    # The receive script must be the child, not the account. Rebuild the witness utxo.
    psbt.inputs[0].witness_utxo = TransactionOutput(100_000, address_to_scriptpubkey(receive))
    reviewed = review_psbt(session, 0, psbt.serialize())
    assert any("OP_RETURN" in warning for warning in reviewed["warnings"])
    assert reviewed["external_amount"] == 90_000

    tx.vout.append(TransactionOutput(1, data))
    bad = PSBT(tx)
    bad.inputs[0].witness_utxo = TransactionOutput(100_000, address_to_scriptpubkey(receive))
    bad.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    try:
        review_psbt(session, 0, bad.serialize())
    except ReviewError as exc:
        assert "non-zero" in str(exc)
    else:
        raise AssertionError("A non-zero OP_RETURN was accepted.")

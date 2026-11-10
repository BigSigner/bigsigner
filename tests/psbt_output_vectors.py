"""Reproducible PSBTs for output ownership checks and MultiSig signing."""

from pathlib import Path

from embit.psbt import PSBT
from embit.transaction import SIGHASH, Transaction, TransactionInput

from test_address_search import ZOO
from test_domain import ABANDON, LEGAL, root_of
from test_psbt_output_accounts import _output
from test_psbt_wallet_mismatch import OTHER, _wallet

VECTORS = Path(__file__).resolve().parent / "vectors"
SINGLE_VECTOR = "native_segwit_spoofed_change.psbt"
SINGLE_ACCOUNT1_VECTOR = "native_segwit_spoofed_account1_receive_120.psbt"
MULTI_VECTOR = "native_segwit_multisig_2of3_spoofed_change.psbt"
MULTI_DESCRIPTOR = "native_segwit_multisig_2of3_descriptor.txt"
MULTI_TO_ABANDON_VECTOR = "native_segwit_multisig_2of3_to_abandon.psbt"
MULTI_TO_ABANDON_LEGAL_VECTOR = "native_segwit_multisig_2of3_to_abandon_signed_by_legal.psbt"


def spoofed_change_vector(multisig=False, *, account=0):
    """Spend account 0, with genuine output-1 keys at `account` but a foreign script."""
    purpose = 48 if multisig else 84
    session = _wallet((ABANDON, LEGAL, ZOO) if multisig else (ABANDON,), purpose)
    attacker = _wallet((LEGAL, ZOO, OTHER) if multisig else (LEGAL,), purpose)
    wallet = session.wallets[0]
    foreign = attacker.wallets[0]
    accounts = [0] * len(wallet.fingerprints)
    foreign_accounts = [0] * len(foreign.fingerprints)
    source = _output(session, wallet, accounts, 0, 0, 100_000)
    payment = _output(attacker, foreign, foreign_accounts, 0, 0, 50_000)
    claimed = _output(session, wallet, [account] * len(wallet.fingerprints), 0, 120, 40_000)
    actual = _output(attacker, foreign, foreign_accounts, 0, 120, 40_000)
    psbt = PSBT(Transaction(
        version=2,
        vin=[TransactionInput(b"\x71" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[payment.vout, actual.vout],
    ))
    scope = psbt.inputs[0]
    scope.witness_utxo = source.vout
    scope.witness_script = source.witness_script
    scope.bip32_derivations.update(source.bip32_derivations)
    scope.sighash_type = SIGHASH.ALL
    # Keep the selected wallet's public keys, fingerprints, paths, and witness
    # script while sending to the attacker's different Receive Address #120.
    claimed.script_pubkey = actual.script_pubkey
    psbt.outputs[1] = claimed
    return session, psbt


def write_spoofed_change_vectors(folder=VECTORS):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for multisig, name, account in ((False, SINGLE_VECTOR, 0),
                                    (False, SINGLE_ACCOUNT1_VECTOR, 1),
                                    (True, MULTI_VECTOR, 0)):
        session, psbt = spoofed_change_vector(multisig, account=account)
        path = folder / name
        path.write_bytes(psbt.serialize())
        written.append(path)
        if multisig:
            path = folder / MULTI_DESCRIPTOR
            path.write_text(session.descriptor_text(0) + "\n")
            written.append(path)
    return written


def multisig_to_abandon_vector(*, signed_by_legal=False):
    """Pay Abandon SingleSig and return Change #0 to the shared 2-of-3 wallet."""
    session = _wallet((ABANDON, LEGAL, ZOO), purpose=48)
    recipient = _wallet((ABANDON,))
    wallet = session.wallets[0]
    accounts = [0] * len(wallet.fingerprints)
    source = _output(session, wallet, accounts, 0, 0, 100_000)
    payment = _output(recipient, recipient.wallets[0], [0], 0, 0, 50_000)
    change = _output(session, wallet, accounts, 1, 0, 40_000)
    psbt = PSBT(Transaction(
        version=2,
        vin=[TransactionInput(b"\x72" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[payment.vout, change.vout],
    ))
    scope = psbt.inputs[0]
    scope.witness_utxo = source.vout
    scope.witness_script = source.witness_script
    scope.bip32_derivations.update(source.bip32_derivations)
    scope.sighash_type = SIGHASH.ALL
    psbt.outputs = [payment, change]
    if signed_by_legal:
        assert psbt.sign_with(root_of(LEGAL)) == len(psbt.inputs)
    return session, psbt


def write_multisig_payment_vectors(folder=VECTORS):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for signed, name in ((False, MULTI_TO_ABANDON_VECTOR), (True, MULTI_TO_ABANDON_LEGAL_VECTOR)):
        session, psbt = multisig_to_abandon_vector(signed_by_legal=signed)
        path = folder / name
        path.write_bytes(psbt.serialize())
        written.append(path)
    descriptor = folder / MULTI_DESCRIPTOR
    descriptor.write_text(session.descriptor_text(0) + "\n")
    return written + [descriptor]

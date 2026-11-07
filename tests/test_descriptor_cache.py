"""The parsed descriptor is reused until an input of its text changes."""

from embit.descriptor.checksum import checksum

import bigsigner.session as session_mod
from bigsigner.psbt_check import _script_at
from bigsigner.psbt_review import _script_at as review_script_at
from bigsigner.session import Session
from test_domain import LEGAL, expression
from test_psbt_load import ABANDON, _native


def _counting(session):
    calls = {"n": 0}
    original = session_mod._descriptor

    def wrapped(wallet, current):
        calls["n"] += 1
        return original(wallet, current)

    session_mod._descriptor = wrapped
    return calls, original


def test_the_same_wallet_reuses_one_parsed_descriptor():
    session = _native()
    wallet = session.wallets[0]
    fingerprint = wallet.fingerprints[0]
    calls, original = _counting(session)
    try:
        first = session._parsed_descriptor(wallet)
        second = session._parsed_descriptor(wallet)
        assert first is second
        assert calls["n"] == 1

        receive = _script_at(session, wallet, {fingerprint: 0}, 0, 0)
        change = _script_at(session, wallet, {fingerprint: 0}, 1, 0)
        again = review_script_at(session, wallet, {fingerprint: 0}, 0, 0)
        assert receive != change
        assert again == receive
        assert calls["n"] == 1
        assert wallet.accounts[fingerprint] == 0

        other = _script_at(session, wallet, {fingerprint: 1}, 0, 0)
        assert other != receive
        assert wallet.accounts[fingerprint] == 0
        assert calls["n"] == 2

        selected = session.addresses(0, 0, 0, 1)[0]
        assert calls["n"] == 3
        assert session.addresses(0, 0, 0, 1)[0] == selected
    finally:
        session_mod._descriptor = original


def test_a_changed_seed_or_network_rebuilds_the_descriptor():
    session = _native()
    wallet = session.wallets[0]
    calls, original = _counting(session)
    root = session._seed_for(wallet.fingerprints[0]).root
    chain = root.chain_code
    try:
        session._parsed_descriptor(wallet)
        assert calls["n"] == 1

        root.chain_code = bytes([chain[0] ^ 0x01]) + chain[1:]
        changed = session._parsed_descriptor(wallet)
        assert calls["n"] == 2
        root.chain_code = chain
        restored = session._parsed_descriptor(wallet)
        assert calls["n"] == 3
        assert changed is not restored

        session.network = "test"
        session._parsed_descriptor(wallet)
        assert calls["n"] == 4
        text = session_mod._descriptor(wallet, session)
        assert "/1h/" in text
        assert calls["n"] == 5
    finally:
        root.chain_code = chain
        session_mod._descriptor = original


def test_an_external_key_rebuilds_when_its_xpub_or_path_changes():
    session = Session()
    body = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    session.add_text(f"{body}#{checksum(body)}")
    wallet = session.wallets[0]
    stored = session._xpubs(wallet.fingerprints[0])[0]
    calls, original = _counting(session)
    chain = stored.xpub.chain_code
    path = tuple(stored.path)
    try:
        first = session._parsed_descriptor(wallet)
        assert calls["n"] == 1
        assert session._parsed_descriptor(wallet) is first

        stored.xpub.chain_code = bytes([chain[0] ^ 0x01]) + chain[1:]
        assert session._parsed_descriptor(wallet) is not first
        assert calls["n"] == 2
        stored.xpub.chain_code = chain
        session._parsed_descriptor(wallet)
        assert calls["n"] == 3

        stored.path = tuple(path[:-1]) + (path[-1] + 1,)
        session._parsed_descriptor(wallet)
        assert calls["n"] == 4
    finally:
        stored.xpub.chain_code = chain
        stored.path = path
        session_mod._descriptor = original


def test_a_multisig_descriptor_is_cached_for_every_key():
    session = Session()
    session.add_mnemonic(ABANDON.split())
    session.add_mnemonic(LEGAL.split())
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    body = f"wsh(sortedmulti(2,{first},{second}))"
    session.add_text(f"{body}#{checksum(body)}")
    wallet = session.wallets[0]
    accounts = {fingerprint: 0 for fingerprint in wallet.fingerprints}
    calls, original = _counting(session)
    try:
        left = _script_at(session, wallet, accounts, 0, 0)
        right = _script_at(session, wallet, accounts, 0, 1)
        assert left != right
        assert calls["n"] == 1

        wallet.threshold = 1
        changed = _script_at(session, wallet, accounts, 0, 0)
        assert changed != left
        assert calls["n"] == 2
    finally:
        wallet.threshold = 2
        session_mod._descriptor = original

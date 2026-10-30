"""crypto-output UR for the descriptor QR."""

from embit.descriptor.checksum import checksum

from bigsigner.qr import qr_matrix
from bigsigner.session import Session
from bigsigner.ur import decode_ur, encode_minimal
from test_domain import ABANDON, LEGAL, expression


def test_bytewords_match_the_published_crypto_output_vector():
    raw = bytes.fromhex(
        "d90193d90132a103582102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    )
    encoded = "taadmutaadeyoyaxhdclaoswaalbmwfpwekijndyfefzjtmdrtketphhktmngrlkwsfnospypsasrhhhjonnvwtsqzwljy"
    assert encode_minimal(raw) == encoded
    kind, cbor = decode_ur(f"UR:CRYPTO-OUTPUT/{encoded.upper()}")
    assert kind == "crypto-output"
    assert cbor == raw


def test_a_singlesig_descriptor_encodes_as_wpkh():
    from bigsigner.paths import SINGLESIG_NATIVE
    from bigsigner.session import _public_for

    session = Session()
    added = session.add_mnemonic(ABANDON)
    session.add_text(_wallet(ABANDON, "m/84h/0h/0h", "wpkh"))
    from bigsigner.ur import descriptor_ur

    text = descriptor_ur(session, 0)
    kind, cbor = decode_ur(text)
    assert kind == "crypto-output"
    assert cbor.startswith(bytes.fromhex("d90194d9012f"))
    key = _public_for(session, added["fingerprint"], SINGLESIG_NATIVE, 0)
    assert key.xpub.sec() in cbor


def test_a_multisig_descriptor_encodes_as_sortedmulti_in_receive_key_order():
    session = Session()
    session.add_text(_multisig())
    from bigsigner.ur import descriptor_ur

    text = descriptor_ur(session, 0)
    kind, cbor = decode_ur(text)
    assert kind == "crypto-output"
    assert cbor.startswith(bytes.fromhex("d90191d90197"))
    wallet = session.wallets[0]
    keys = []
    for fingerprint in wallet.fingerprints:
        key = next(
            item
            for item in session._xpubs(fingerprint)
            if item.account == wallet.accounts[fingerprint]
        )
        keys.append(key)
    ordered = sorted(keys, key=lambda key: key.xpub.derive("m/0/0").sec())
    first = cbor.find(ordered[0].xpub.sec())
    second = cbor.find(ordered[1].xpub.sec())
    assert 0 <= first < second
    assert qr_matrix(text.upper())


def _wallet(words, path, kind):
    body = f"{kind}({expression(words, path)})"
    return f"{body}#{checksum(body)}"


def _multisig():
    keys = [
        expression(ABANDON, "m/48h/0h/0h/2h"),
        expression(LEGAL, "m/48h/0h/1h/2h"),
    ]
    body = "wsh(sortedmulti(1," + ",".join(keys) + "))"
    return f"{body}#{checksum(body)}"

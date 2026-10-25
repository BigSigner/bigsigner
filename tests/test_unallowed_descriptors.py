"""Wallet descriptors this version refuses when loading from the Wallets page."""

import pytest
from embit.bip39 import mnemonic_from_bytes

from bigsigner.parse import parse_key_expression
from bigsigner.session import Session, SessionError
from bigsigner.slip132 import display_form
from test_domain import ABANDON, LEGAL, expression


def _multisig(*keys, threshold=2) -> str:
    return f"wsh(sortedmulti({threshold},{','.join(keys)}))"


def _sixteen_keys() -> str:
    keys = []
    for index in range(16):
        words = mnemonic_from_bytes(bytes([index + 1]) + b"\x3c" * 15)
        keys.append(expression(words, "m/48h/0h/0h/2h"))
    return _multisig(*keys)


def _depth_mismatch() -> str:
    claimed = expression(ABANDON, "m/84h/0h/7h")
    account0 = expression(ABANDON, "m/84h/0h/0h")
    xpub = account0.split("]")[1].split("/")[0]
    forged = claimed.split("]")[0] + "]" + xpub + "/<0;1>/*"
    return f"wpkh({forged})"


def _zpub_in_multisig() -> str:
    text = expression(ABANDON, "m/48h/0h/0h/2h")
    key = parse_key_expression(text, "main")
    zpub = display_form(key.canonical, "main", "singlesig_native")
    forged = text.replace(key.canonical, zpub)
    other = expression(LEGAL, "m/48h/0h/0h/2h")
    return _multisig(forged, other)


NATIVE = expression(ABANDON, "m/84h/0h/0h")
TAPROOT = expression(ABANDON, "m/86h/0h/0h")
MULTI = expression(ABANDON, "m/48h/0h/0h/2h")
OTHER = expression(LEGAL, "m/48h/0h/0h/2h")
OTHER_ACCOUNT = expression(ABANDON, "m/48h/0h/3h/2h")

UNALLOWED = [
    ("unsorted multi", f"wsh(multi(2,{MULTI},{OTHER}))", "Only sorted multisig"),
    ("nested segwit", f"sh(wpkh({NATIVE}))", "does not support that wallet type"),
    ("legacy pkh", f"pkh({NATIVE})", "does not support that wallet type"),
    ("miniscript", "wsh(and_v(v:pk(02aa),older(100)))", "does not support that wallet type"),
    ("sortedmulti_a", f"wsh(sortedmulti_a(2,{MULTI},{OTHER}))", "does not support that wallet type"),
    ("musig", f"musig({MULTI},{OTHER})", "does not support that wallet type"),
    ("taproot script tree", f"tr({TAPROOT},{TAPROOT})", "taproot script tree"),
    ("wpkh with a multisig path", f"wpkh({MULTI})", "native-segwit single-sig path"),
    ("tr with a native-segwit path", f"tr({NATIVE})", "taproot single-sig path"),
    ("sortedmulti with single-sig keys", _multisig(NATIVE, TAPROOT), "m/48h paths"),
    ("taproot multisig path", _multisig(expression(ABANDON, "m/48h/0h/0h/3h"), OTHER), "taproot multisig"),
    ("wrong coin type", f"wpkh({expression(ABANDON, 'm/84h/1h/0h')})", "not a supported"),
    ("repeated fingerprint", _multisig(MULTI, OTHER_ACCOUNT), "same fingerprint"),
    ("threshold above the key count", _multisig(MULTI, OTHER, threshold=3), "threshold or number of keys"),
    ("threshold zero", _multisig(MULTI, OTHER, threshold=0), "threshold or number of keys"),
    ("one multisig key", _multisig(MULTI, threshold=1), "threshold or number of keys"),
    ("more than 15 keys", _sixteen_keys(), "threshold or number of keys"),
    ("wrong checksum", f"wpkh({NATIVE})#qqqqqqqq", "checksum does not match"),
    ("zpub in a multisig", _zpub_in_multisig(), "does not match"),
    ("depth mismatch", _depth_mismatch(), "depth or last step"),
    ("address suffix", f"wpkh({NATIVE.replace('/<0;1>/*', '/2/*')})", "unsupported address suffix"),
    ("bare key expression", NATIVE, "key expression, not a wallet descriptor"),
]


@pytest.mark.parametrize("name,descriptor,reason", UNALLOWED, ids=[item[0] for item in UNALLOWED])
def test_unallowed_wallet_descriptors_are_refused(name, descriptor, reason):
    del name
    session = Session()
    with pytest.raises(SessionError, match=reason):
        session.plan_wallet_import(descriptor)
    assert session.wallets == []
    assert session.fingerprints == {}

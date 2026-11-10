"""Loading a PSBT, and the refusals that stop signing before the YAML view."""

import base64

from embit.psbt import DerivationPath, PSBT
from embit.script import Script, address_to_scriptpubkey
from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput

from bigsigner.psbt_check import NOT_SUPPORTED, check_loaded_psbt
from bigsigner.psbt_load import TOO_LARGE, UNREADABLE, is_binary_psbt, psbt_bytes
from bigsigner.psbt_review import ReviewError
from bigsigner.seedqr import compact_bytes
from bigsigner.session import Session, _account_path, _derive_public
from bigsigner.ui.app import TX_WATCH_ONLY, App

ABANDON = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _tap(app, label):
    app.render()
    matches = [hit for hit in app.hits if hit["label"] == label or hit["action"] == label]
    if not matches:
        raise AssertionError(label)
    hit = min(matches, key=lambda item: item["box"][1])
    left, top, right, bottom = hit["box"]
    app.tap((left + right) // 2, (top + bottom) // 2)


def _texts(app):
    return [item["text"] for item in app.texts]


def _native():
    from embit import bip32, bip39
    from embit.descriptor.checksum import checksum

    session = Session()
    session.add_mnemonic(ABANDON.split())
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(ABANDON))
    public = root.derive("m/84h/0h/0h").to_public()
    key = f"[{root.my_fingerprint.hex()}/84h/0h/0h]{public.to_string()}/<0;1>/*"
    session.add_text(f"wpkh({key})#{checksum('wpkh(' + key + ')')}")
    return session


def _child(session, account=0, branch=0, index=0):
    wallet = session.wallets[0]
    fingerprint = wallet.fingerprints[0]
    derived = _derive_public(session._seed_for(fingerprint), _account_path("main", wallet.role, account), "main")
    child = derived.derive(f"m/{branch}/{index}")
    path = _account_path("main", wallet.role, account) + [branch, index]
    return fingerprint, child, path


def _psbt(session, *, version=2, sequence=0xFFFFFFFD, sighash=SIGHASH.ALL, amount=100_000, output=90_000, account=0, branch=0, index=0, vout=0, extra_input=False):
    fingerprint, child, path = _child(session, account, branch, index)
    receive = session.addresses(0, branch if branch in (0, 1) else 0, index, 1)[0]
    script = address_to_scriptpubkey(receive)
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    vins = [TransactionInput(b"\x11" * 32, vout, sequence=sequence)]
    if extra_input:
        vins.append(TransactionInput(b"\x22" * 32, 1, sequence=sequence))
    tx = Transaction(version=version, vin=vins, vout=[TransactionOutput(output, destination)])
    psbt = PSBT(tx)
    for inp in psbt.inputs:
        inp.witness_utxo = TransactionOutput(amount, script)
        inp.bip32_derivations[child.key] = DerivationPath(fingerprint, path)
        if sighash is not None:
            inp.sighash_type = sighash
    return psbt


def _raises(session, psbt, snippet):
    try:
        check_loaded_psbt(session, 0, psbt)
    except ReviewError as exc:
        assert snippet in str(exc)
        assert "Bad Transaction" not in str(exc)
        assert any(part in str(exc) for part in (
            NOT_SUPPORTED, "does not belong", "spends from account", "spoof a change output",
        ))
    else:
        raise AssertionError(snippet)


def test_sign_transaction_is_disabled_for_a_watch_only_wallet():
    from test_domain import expression

    app = App()
    app.session.add_text(f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})")
    app.screen = "wallet"
    app.wallet_index = 0
    app.scroll["wallet"] = 10**9
    app.render()
    assert not any(hit["label"] == "Sign Transaction" for hit in app.hits)
    assert TX_WATCH_ONLY in " ".join(_texts(app))

    seeded = App()
    added = seeded.session.add_mnemonic(ABANDON.split())
    seeded.selected_fp = added["fingerprint"]
    seeded.screen = "key"
    seeded._act("derive-native")
    seeded._act("derive-wallet")
    seeded.notice = ""
    seeded.scroll["wallet"] = 10**9
    seeded.render()
    _tap(seeded, "Sign Transaction")
    assert seeded.screen == "load-psbt"
    seeded.render()
    assert "Load Transaction" in _texts(seeded)
    labels = [hit["label"] for hit in seeded.hits if hit["action"] in ("psbt-scan", "psbt-sd")]
    assert labels == ["Scan QR Code", "Load from File"]


def test_a_file_or_qr_that_is_not_a_psbt_names_what_it_is():
    from bigsigner.sdcard import mount_memory, unmount_memory

    app = App()
    added = app.session.add_mnemonic(ABANDON.split())
    app.selected_fp = added["fingerprint"]
    app.screen = "key"
    app._act("derive-native")
    app._act("derive-wallet")
    app.notice = ""
    _tap(app, "Sign Transaction")
    _tap(app, "Scan QR Code")
    app.accept_qr("signmessage m/84h/0h/0h/0/0 ascii:hello")
    assert app.screen == "load-psbt"
    assert app.notice == "This is a sign-message command, not a PSBT."
    _tap(app, "Dismiss")
    _tap(app, "Scan QR Code")
    app.accept_qr(ABANDON)
    assert app.notice == "This is a seed, not a PSBT."
    _tap(app, "Dismiss")
    _tap(app, "Scan QR Code")
    app.accept_qr(compact_bytes(ABANDON).decode("latin-1"))
    assert "compact seed" in app.notice

    mount_memory({"files": {"note.txt": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}})
    try:
        _tap(app, "Dismiss")
        _tap(app, "Load from File")
        _tap(app, "note.txt")
        assert app.screen == "load-psbt"
        assert app.notice == "This is a seed, not a PSBT."
    finally:
        unmount_memory()


def test_a_binary_psbt_file_is_the_bip174_form_and_loads_from_the_sd_card():
    from bigsigner.sdcard import mount_memory, unmount_memory

    session = _native()
    raw = _psbt(session).serialize()
    assert raw.startswith(b"psbt\xff")
    assert is_binary_psbt(raw)
    assert psbt_bytes(raw) == raw
    assert not is_binary_psbt(b"psbt")
    assert not is_binary_psbt(b"psbt\x00")
    try:
        psbt_bytes(b"psbt\x00not-a-psbt")
    except Exception as exc:
        assert str(exc) == UNREADABLE
    else:
        raise AssertionError("letters")
    try:
        psbt_bytes(b"psbt\xff" + b"\x00" * 100_001)
    except Exception as exc:
        assert str(exc) == TOO_LARGE
    else:
        raise AssertionError("size")

    app = App()
    app.session = session
    app.wallet_index = 0
    app.screen = "load-psbt"
    encoded = base64.b64encode(raw).decode("ascii")
    mount_memory({"files": {
        "wallet.psbt": {"base64": encoded},
        "wallet.txt": encoded,
        "note.bin": {"base64": base64.b64encode(b"\x00\x01\xff").decode("ascii")},
    }})
    try:
        _tap(app, "Load from File")
        _tap(app, "wallet.psbt")
        assert app.screen == "psbt-yaml"
        assert app.notice == ""
        app.back_one()
        assert app.screen == "load-psbt"
        _tap(app, "Load from File")
        _tap(app, "wallet.txt")
        assert app.screen == "psbt-yaml"
        app.back_one()
        _tap(app, "Load from File")
        _tap(app, "note.bin")
        assert app.screen == "load-psbt"
        assert app.notice == "That file is not text."
    finally:
        unmount_memory()


def test_a_specter_sequence_counts_the_parts_and_a_large_psbt_is_refused():
    session = _native()
    encoded = base64.b64encode(_psbt(session).serialize()).decode("ascii")
    app = App()
    app.session = session
    app.wallet_index = 0
    app.screen = "load-psbt"
    app._act("psbt-scan")
    assert app.screen == "scan"
    mid = len(encoded) // 2
    app.accept_qr(f"p1of2 {encoded[:mid]}")
    assert app.screen == "scan"
    assert app.scan_prompt() == "Scanned 1 of 2"
    app.accept_qr(f"p2of2 {encoded[mid:]}")
    assert app.screen == "psbt-yaml"
    app.render()
    assert "Transaction Signing" in _texts(app)
    assert "Spending from Wallet:" in _texts(app)

    blob = b"psbt\xff" + b"\x00" * 100_001
    try:
        psbt_bytes(base64.b64encode(blob).decode("ascii"))
    except Exception as exc:
        assert str(exc) == TOO_LARGE
    else:
        raise AssertionError("size")


def test_each_psbt_refusal_names_the_unsupported_case():
    session = _native()
    good = _psbt(session)
    checked = check_loaded_psbt(session, 0, base64.b64encode(good.serialize()).decode("ascii"))
    assert checked.tx.version == 2

    version = _psbt(session, version=1)
    _raises(session, version, "version other than 2 or 3")

    psbt_version = _psbt(session)
    psbt_version.version = 1
    _raises(session, psbt_version, "PSBT version other than 0 or 2")
    psbt_version.version = 2
    assert check_loaded_psbt(session, 0, psbt_version).version == 2

    for key, value in ((b"\x11", 500_000_000), (b"\x12", 10000)):
        locked = _psbt(session)
        locked.inputs[0].unknown = {key: value.to_bytes(4, "little")}
        _raises(session, locked.serialize(), "per-input required locktime")
        locked.version = 0
        _raises(session, locked, "per-input required locktime")
        locked.version = 2
        assert check_loaded_psbt(session, 0, locked).tx.locktime == 0

    modifiable = _psbt(session)
    modifiable.unknown = {b"\x06": b"\x00"}
    _raises(session, modifiable.serialize(), "modifiable transaction")
    modifiable.version = 0
    _raises(session, modifiable, "modifiable transaction")
    modifiable.version = 2
    _raises(session, modifiable.serialize(), "modifiable transaction")

    version3 = _psbt(session, version=3)
    assert check_loaded_psbt(session, 0, version3.serialize()).tx.version == 3

    empty = _psbt(session)
    empty.tx.vin.clear()
    empty.inputs.clear()
    _raises(session, empty, "no inputs")

    no_outputs = _psbt(session)
    no_outputs.tx.vout.clear()
    no_outputs.outputs.clear()
    _raises(session, no_outputs, "no outputs")

    from embit.psbt import OutputScope
    from embit.script import Script

    def _with_scripts(*scripts):
        psbt = _psbt(session, output=50_000)
        for amount, raw in scripts:
            psbt.outputs.append(OutputScope(vout=TransactionOutput(amount, Script(raw))))
        return psbt

    assert check_loaded_psbt(session, 0, _with_scripts((0, b"\x6a"), (5, b"\x6a\x02hi"))).tx.version == 2
    _raises(session, _with_scripts((0, b"\x6a\xac")), "data pushes")
    huge = b"\x6a\x4e" + (100_000).to_bytes(4, "little") + (b"\x00" * 100_000)
    _raises(session, _with_scripts((0, huge)), "100000 bytes")

    assert check_loaded_psbt(session, 0, _psbt(session, output=294)).tx.version == 2
    _raises(session, _psbt(session, output=293), "below 294 sats")
    taproot = b"\x51\x20" + (b"\x11" * 32)
    multisig = b"\x00\x20" + (b"\x22" * 32)
    assert check_loaded_psbt(session, 0, _with_scripts((330, taproot), (330, multisig))).tx.version == 2
    _raises(session, _with_scripts((329, taproot)), "Taproot output below 330")
    _raises(session, _with_scripts((329, multisig)), "P2WSH output below 330")
    legacy = b"\x76\xa9\x14" + (b"\x33" * 20) + b"\x88\xac"
    wrapped = b"\xa9\x14" + (b"\x44" * 20) + b"\x87"
    assert check_loaded_psbt(session, 0, _with_scripts((546, legacy), (540, wrapped))).tx.version == 2
    _raises(session, _with_scripts((545, legacy)), "legacy output below 546")
    _raises(session, _with_scripts((539, wrapped)), "P2SH output below 540")
    p2pk = bytes([33]) + (b"\x02" + b"\x11" * 32) + b"\xac"
    _raises(session, _with_scripts((100_000, p2pk)), "other than OP_RETURN, P2PKH, P2SH")

    duplicate = _psbt(session)
    duplicate.tx.vin.append(TransactionInput(b"\x11" * 32, 0, sequence=0xFFFFFFFD))
    duplicate.inputs.append(duplicate.inputs[0])
    _raises(session, duplicate, "same output")

    missing_amount = _psbt(session)
    missing_amount.inputs[0].witness_utxo = None
    _raises(session, missing_amount, "without witness UTXO data")

    too_much = _psbt(session, amount=100_000, output=150_000)
    _raises(session, too_much, "more than the inputs")

    missing_path = _psbt(session)
    missing_path.inputs[0].bip32_derivations.clear()
    _raises(session, missing_path, "without a master fingerprint")

    mixed = _psbt(session, extra_input=True, amount=100_000, output=50_000)
    fingerprint, child, path = _child(session, account=1)
    mixed.inputs[1].bip32_derivations.clear()
    mixed.inputs[1].bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    _raises(session, mixed, "more than one account or wallet")

    other = _psbt(session)
    fingerprint, child, path = _child(session)
    taproot_path = [86 | 0x80000000, path[1], path[2], 0, 0]
    other.inputs[0].bip32_derivations.clear()
    other.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, taproot_path)
    _raises(session, other, "does not belong to this wallet")

    account = _psbt(session, account=2)
    _raises(session, account, "spends from account 2")
    _raises(session, account, "change the account index")

    out_of_range = _psbt(session, branch=2)
    _raises(session, out_of_range, "would not derive")

    extra = _psbt(session)
    fingerprint, child, path = _child(session)
    extra.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, path + [1])
    _raises(session, extra, "would not derive")

    wrong_key = _psbt(session)
    fingerprint, child, path = _child(session)
    wrong_key.inputs[0].bip32_derivations.clear()
    wrong_key.inputs[0].bip32_derivations[child.derive("m/0/1").key] = DerivationPath(fingerprint, path)
    _raises(session, wrong_key, "public key does not match")

    script = _psbt(session)
    script.inputs[0].redeem_script = Script(b"\x51")
    _raises(session, script, "redeem script or witness script")

    sighash = _psbt(session, sighash=SIGHASH.NONE)
    _raises(session, sighash, "SIGHASH_ALL")

    final = _psbt(session, sequence=0xFFFFFFFF)
    _raises(session, final, "0xFFFFFFFF")

    weird = _psbt(session, sequence=0x10000)
    _raises(session, weird, "outside the supported ranges")

    change = _psbt(session)
    fingerprint, child, path = _child(session, branch=1, index=3)
    change.outputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, path)
    _raises(session, change, "change output")

    from embit import bip32, bip39
    from embit.descriptor.checksum import checksum

    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(ABANDON))
    public = root.derive("m/86h/0h/0h").to_public()
    key = f"[{root.my_fingerprint.hex()}/86h/0h/0h]{public.to_string()}/<0;1>/*"
    session.add_text(f"tr({key})#{checksum('tr(' + key + ')')}")
    named = _psbt(session)
    tap_path = [86 | 0x80000000, path[1], path[2], 0, 0]
    named.inputs[0].bip32_derivations.clear()
    named.inputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, tap_path)
    try:
        check_loaded_psbt(session, 0, named)
    except ReviewError as exc:
        message = str(exc)
    else:
        raise AssertionError("wallet")
    assert message.startswith("This transaction does not belong to wallet ")
    assert " It belongs to wallet " in message
    assert "(Native-Segwit)" in message
    assert "(Taproot)" in message
    foreign = _psbt(session)
    foreign.outputs[0].bip32_derivations[child.key] = DerivationPath(fingerprint, tap_path)
    _raises(session, foreign, "derived address does not match the PSBT")


def _seed_rows(session, psbt):
    from bigsigner.psbt_check import seed_sign_rows

    loaded = check_loaded_psbt(session, 0, psbt)
    return seed_sign_rows(session, session.wallets[0], loaded)


def test_a_transaction_already_signed_by_a_loaded_seed_stays_loaded():
    from embit.descriptor.checksum import checksum
    from embit.script import Witness

    from bigsigner.psbt_check import multisig_signature_note
    from bigsigner.session import _account_path, _public_for
    from test_domain import LEGAL, expression

    session = _native()
    _fingerprint, child, _path = _child(session)
    signed = _sign_loaded(session, _psbt(session))
    assert _seed_rows(session, signed)[0]["signed"] is True

    partial = _sign_loaded(session, _psbt(session, extra_input=True))
    partial.inputs[1].partial_sigs.clear()
    assert _seed_rows(session, partial)[0]["signed"] is False
    finalized = _sign_loaded(session, _psbt(session))
    raw = next(iter(finalized.inputs[0].partial_sigs.values()))
    finalized.inputs[0].partial_sigs.clear()
    finalized.inputs[0].final_scriptwitness = Witness([raw, child.key.sec()])
    assert _seed_rows(session, finalized)[0]["signed"] is True

    taproot = _native_taproot()
    key_spend = _sign_loaded(taproot, _psbt(taproot, sighash=None))
    assert _seed_rows(taproot, key_spend)[0]["signed"] is True
    field = _sign_loaded(taproot, _psbt(taproot, sighash=None))
    tap_sig = field.inputs[0].final_scriptwitness.items[0]
    field.inputs[0].final_scriptwitness = None
    field.inputs[0].unknown = {b"\x13": tap_sig}
    assert _seed_rows(taproot, field)[0]["signed"] is True

    multi = Session()
    multi.add_mnemonic(ABANDON.split())
    multi.add_mnemonic(LEGAL.split())
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    third = expression(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "m/48h/0h/0h/2h",
    )
    body = f"wsh(sortedmulti(2,{first},{second},{third}))"
    multi.add_text(f"{body}#{checksum(body)}")
    wallet = multi.wallets[0]
    receive = multi.addresses(0, 0, 0, 1)[0]
    script = address_to_scriptpubkey(receive)
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    tx = Transaction(
        version=2,
        vin=[
            TransactionInput(b"\x11" * 32, 0, sequence=0xFFFFFFFD),
            TransactionInput(b"\x22" * 32, 1, sequence=0xFFFFFFFD),
        ],
        vout=[TransactionOutput(50_000, destination)],
    )
    psbt = PSBT(tx)
    for index, scope in enumerate(psbt.inputs):
        scope.witness_utxo = TransactionOutput(100_000, script)
        for fingerprint in wallet.fingerprints:
            stored = _public_for(multi, fingerprint, wallet.role, 0)
            derived = stored.xpub.derive(f"m/0/{index}")
            path = _account_path("main", wallet.role, 0) + [0, index]
            scope.bip32_derivations[derived.key] = DerivationPath(fingerprint, path)
    assert multisig_signature_note(wallet, psbt) == (
        "Some inputs have no signatures. "
        "2 signatures are required to complete this 2-of-3 transaction."
    )
    ours = [
        scope.bip32_derivations and next(
            key for key, origin in scope.bip32_derivations.items()
            if origin.fingerprint == wallet.fingerprints[0]
        )
        for scope in psbt.inputs
    ]
    psbt.inputs[0].partial_sigs[ours[0]] = b"\x30"
    assert multisig_signature_note(wallet, psbt).startswith("Some inputs have no signatures.")
    psbt.inputs[1].partial_sigs[ours[1]] = b"\x30"
    assert multisig_signature_note(wallet, psbt) == (
        "Each input already has 1 signature. "
        "1 additional signature is required to complete this 2-of-3 wallet."
    )

    app = App()
    app.session = multi
    app.wallet_index = 0
    one = PSBT(
        Transaction(
            version=2,
            vin=[TransactionInput(b"\x33" * 32, 0, sequence=0xFFFFFFFD)],
            vout=[TransactionOutput(50_000, destination)],
        )
    )
    one.inputs[0].witness_utxo = TransactionOutput(100_000, script)
    for fingerprint in wallet.fingerprints:
        stored = _public_for(multi, fingerprint, wallet.role, 0)
        derived = stored.xpub.derive("m/0/0")
        path = _account_path("main", wallet.role, 0) + [0, 0]
        one.inputs[0].bip32_derivations[derived.key] = DerivationPath(fingerprint, path)
    app._accept_psbt_text(one.serialize(), "file")
    assert app.screen == "psbt-yaml"
    app.scroll["psbt-yaml"] = 10**9
    app.render()
    assert "Some inputs have no signatures." in " ".join(item["text"] for item in app.texts)
    sign_hits = [hit for hit in app.hits if hit["action"].startswith("psbt-sign-")]
    assert len(sign_hits) == 2
    app._act(sign_hits[0]["action"])
    app.render()
    assert app._psbt_signing
    assert app.notice_delay() == 0
    app.render()
    assert not app._psbt_signing
    app.scroll["psbt-yaml"] = 10**9
    app.render()
    shown = " ".join(item["text"] for item in app.texts)
    assert "Each input already has 1 signature." in shown
    assert "1 additional signature is required to complete this 2-of-3 wallet." in shown
    app._act("psbt-continue")
    assert app.screen == "psbt-share"
    app._act("back")
    assert app.screen == "psbt-yaml"
    app.scroll["psbt-yaml"] = 10**9
    app.render()
    restored = " ".join(item["text"] for item in app.texts)
    assert "Some inputs have no signatures." in restored
    assert "Each input already has 1 signature." not in restored
    assert not any(hit["action"] == "psbt-continue" for hit in app.hits)


def _sign_loaded(session, psbt):
    from bigsigner.session import _seed_root

    fingerprint = session.wallets[0].fingerprints[0]
    psbt.sign_with(_seed_root(session._seed_for(fingerprint)))
    return psbt


def test_a_signature_that_does_not_match_is_rejected():
    from embit.descriptor import Descriptor
    from embit.descriptor.checksum import checksum
    from embit.script import Witness

    from bigsigner.session import _account_path, _descriptor, _public_for, _seed_root
    from test_domain import LEGAL, expression

    session = _native()
    signed = _sign_loaded(session, _psbt(session))
    key = next(iter(signed.inputs[0].partial_sigs))
    raw = bytearray(signed.inputs[0].partial_sigs[key])
    raw[5] ^= 1
    signed.inputs[0].partial_sigs[key] = bytes(raw)
    try:
        check_loaded_psbt(session, 0, signed)
    except ReviewError as exc:
        assert str(exc) == "A signature on input 0 does not match."
    else:
        raise AssertionError("partial")

    _fingerprint, child, _path = _child(session)
    finalized = _sign_loaded(session, _psbt(session))
    good = next(iter(finalized.inputs[0].partial_sigs.values()))
    finalized.inputs[0].partial_sigs.clear()
    bad = bytearray(good)
    bad[5] ^= 1
    finalized.inputs[0].final_scriptwitness = Witness([bytes(bad), child.key.sec()])
    try:
        check_loaded_psbt(session, 0, finalized)
    except ReviewError as exc:
        assert str(exc) == "A signature on input 0 does not match."
    else:
        raise AssertionError("witness")

    taproot = _native_taproot()
    key_spend = _sign_loaded(taproot, _psbt(taproot, sighash=None))
    item = bytearray(key_spend.inputs[0].final_scriptwitness.items[0])
    item[0] ^= 1
    key_spend.inputs[0].final_scriptwitness = Witness([bytes(item)])
    try:
        check_loaded_psbt(taproot, 0, key_spend)
    except ReviewError as exc:
        assert str(exc) == "A signature on input 0 does not match."
    else:
        raise AssertionError("taproot")

    multi = Session()
    multi.add_mnemonic(ABANDON.split())
    multi.add_mnemonic(LEGAL.split())
    first = expression(ABANDON, "m/48h/0h/0h/2h")
    second = expression(LEGAL, "m/48h/0h/0h/2h")
    third = expression(
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        "m/48h/0h/0h/2h",
    )
    body = f"wsh(sortedmulti(2,{first},{second},{third}))"
    multi.add_text(f"{body}#{checksum(body)}")
    wallet = multi.wallets[0]
    derived = Descriptor.from_string(_descriptor(wallet, multi)).derive(0, branch_index=0)
    destination = address_to_scriptpubkey("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu")
    tx = Transaction(
        version=2,
        vin=[TransactionInput(b"\x44" * 32, 0, sequence=0xFFFFFFFD)],
        vout=[TransactionOutput(50_000, destination)],
    )
    psbt = PSBT(tx)
    scope = psbt.inputs[0]
    scope.witness_utxo = TransactionOutput(100_000, derived.script_pubkey())
    scope.witness_script = derived.witness_script()
    scope.sighash_type = SIGHASH.ALL
    for fingerprint in wallet.fingerprints:
        stored = _public_for(multi, fingerprint, wallet.role, 0)
        child_key = stored.xpub.derive("m/0/0")
        path = _account_path("main", wallet.role, 0) + [0, 0]
        scope.bip32_derivations[child_key.key] = DerivationPath(fingerprint, path)
    for fingerprint in wallet.fingerprints[:2]:
        psbt.sign_with(_seed_root(multi._seed_for(fingerprint)))
    assert len(scope.partial_sigs) == 2
    check_loaded_psbt(multi, 0, psbt)
    first_key = next(iter(scope.partial_sigs))
    broken = bytearray(scope.partial_sigs[first_key])
    broken[5] ^= 1
    scope.partial_sigs[first_key] = bytes(broken)
    try:
        check_loaded_psbt(multi, 0, psbt)
    except ReviewError as exc:
        assert str(exc) == "A signature on input 0 does not match."
    else:
        raise AssertionError("multisig")


def _native_taproot():
    from embit import bip32, bip39
    from embit.descriptor.checksum import checksum

    session = Session()
    session.add_mnemonic(ABANDON.split())
    root = bip32.HDKey.from_seed(bip39.mnemonic_to_seed(ABANDON))
    public = root.derive("m/86h/0h/0h").to_public()
    key = f"[{root.my_fingerprint.hex()}/86h/0h/0h]{public.to_string()}/<0;1>/*"
    session.add_text(f"tr({key})#{checksum('tr(' + key + ')')}")
    return session


def test_a_deep_psbt_problem_opens_its_own_screen():
    session = _native()
    wallet = session.wallets[0]
    wallet.accounts[wallet.fingerprints[0]] = 1
    app = App()
    app.session = session
    app.wallet_index = 0
    app.back = ["wallet"]
    app.screen = "load-psbt"
    app._act("psbt-scan")
    encoded = base64.b64encode(_psbt(session, account=0).serialize()).decode("ascii")
    app.accept_qr(encoded)
    assert app.screen == "psbt-error"
    assert app.notice == ""
    app.render()
    joined = " ".join(_texts(app))
    assert "Error loading PSBT" in joined
    assert "spends from account 0" in joined
    assert "selected account is 1" in joined
    assert "Go back to the wallet screen and change the account index." in joined
    assert not any(hit["action"] == "back" for hit in app.hits)
    button = next(hit for hit in app.hits if hit["label"] == "OK")
    text_bottom = max(item["box"][3] for item in app.texts if item["text"] != "Error loading PSBT")
    assert text_bottom < button["box"][1]
    _tap(app, "OK")
    assert app.screen == "load-psbt"
    assert app.psbt_error == ""

    refused = _psbt(session, account=1, sighash=SIGHASH.NONE)
    app._accept_psbt_text(base64.b64encode(refused.serialize()).decode("ascii"), "file")
    assert app.screen == "psbt-error"
    assert app.notice == ""
    app.render()
    assert "SIGHASH_ALL" in " ".join(_texts(app))

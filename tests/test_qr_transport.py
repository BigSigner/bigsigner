"""Scanning a descriptor that arrives as a UR or a BBQr."""

import base64
import zlib

from embit.descriptor.checksum import checksum

from bigsigner.bbqr import join_bbqr, split_bbqr
from bigsigner.fountain import FountainDecoder, part_from_cbor
from bigsigner.scan import QrSequence
from bigsigner.session import Session
from bigsigner.ui.app import App
from bigsigner.ur import descriptor_ur
from test_domain import ABANDON, expression

# The first twenty fountain parts of a 256-byte UR, from URKit's encoder test.
_PARTS = [
    "ur:bytes/1-9/lpadascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtdkgslpgh",
    "ur:bytes/2-9/lpaoascfadaxcywenbpljkhdcagwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsgmghhkhstlrdcxaefz",
    "ur:bytes/3-9/lpaxascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjksopdzmol",
    "ur:bytes/4-9/lpaaascfadaxcywenbpljkhdcasotkhemthydawydtaxneurlkosgwcekonertkbrlwmplssjtammdplolsbrdzcrtas",
    "ur:bytes/5-9/lpahascfadaxcywenbpljkhdcatbbdfmssrkzmcwnezelennjpfzbgmuktrhtejscktelgfpdlrkfyfwdajldejokbwf",
    "ur:bytes/6-9/lpamascfadaxcywenbpljkhdcackjlhkhybssklbwefectpfnbbectrljectpavyrolkzczcpkmwidmwoxkilghdsowp",
    "ur:bytes/7-9/lpatascfadaxcywenbpljkhdcavszmwnjkwtclrtvaynhpahrtoxmwvwatmedibkaegdosftvandiodagdhthtrlnnhy",
    "ur:bytes/8-9/lpayascfadaxcywenbpljkhdcadmsponkkbbhgsoltjntegepmttmoonftnbuoiyrehfrtsabzsttorodklubbuyaetk",
    "ur:bytes/9-9/lpasascfadaxcywenbpljkhdcajskecpmdckihdyhphfotjojtfmlnwmadspaxrkytbztpbauotbgtgtaeaevtgavtny",
    "ur:bytes/10-9/lpbkascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtwdkiplzs",
    "ur:bytes/11-9/lpbdascfadaxcywenbpljkhdcahelbknlkuejnbadmssfhfrdpsbiegecpasvssovlgeykssjykklronvsjkvetiiapk",
    "ur:bytes/12-9/lpbnascfadaxcywenbpljkhdcarllaluzmdmgstospeyiefmwejlwtpedamktksrvlcygmzemovovllarodtmtbnptrs",
    "ur:bytes/13-9/lpbtascfadaxcywenbpljkhdcamtkgtpknghchchyketwsvwgwfdhpgmgtylctotzopdrpayoschcmhplffziachrfgd",
    "ur:bytes/14-9/lpbaascfadaxcywenbpljkhdcapazewnvonnvdnsbyleynwtnsjkjndeoldydkbkdslgjkbbkortbelomueekgvstegt",
    "ur:bytes/15-9/lpbsascfadaxcywenbpljkhdcaynmhpddpzmversbdqdfyrehnqzlugmjzmnmtwmrouohtstgsbsahpawkditkckynwt",
    "ur:bytes/16-9/lpbeascfadaxcywenbpljkhdcawygekobamwtlihsnpalnsghenskkiynthdzotsimtojetprsttmukirlrsbtamjtpd",
    "ur:bytes/17-9/lpbyascfadaxcywenbpljkhdcamklgftaxykpewyrtqzhydntpnytyisincxmhtbceaykolduortotiaiaiafhiaoyce",
    "ur:bytes/18-9/lpbgascfadaxcywenbpljkhdcahkadaemejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtntwkbkwy",
    "ur:bytes/19-9/lpbwascfadaxcywenbpljkhdcadekicpaajootjzpsdrbalpeywllbdsnbinaerkurspbncxgslgftvtsrjtksplcpeo",
    "ur:bytes/20-9/lpbbascfadaxcywenbpljkhdcayapmrleeleaxpasfrtrdkncffwjyjzgyetdmlewtkpktgllepfrltataztksmhkbot",
]


def _message(parts):
    decoder = FountainDecoder()
    found = None
    for part in parts:
        _type, seq, payload = _split(part)
        seq_num, seq_len, message_len, checksum, data = part_from_cbor(payload)
        assert (seq_num, seq_len) == seq
        decoder.receive(seq_num, seq_len, message_len, checksum, data)
        found = decoder.message
    return found


def _split(part):
    from bigsigner.ur import split_ur

    return split_ur(part)


def test_pure_and_mixed_fountain_parts_rebuild_the_same_message():
    pure = _message(_PARTS[:9])
    # Parts 10-20 never isolate fragment 4 on their own. Part 5 is that fragment.
    mixed = _message([_PARTS[4], *_PARTS[9:]])
    assert mixed == pure
    assert pure is not None


def test_a_ur_round_trip_is_the_same_descriptor():
    session = Session()
    session.add_mnemonic(ABANDON)
    body = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    session.add_text(f"{body}#{checksum(body)}")
    text = descriptor_ur(session, 0).upper()
    sequence = QrSequence()
    decoded = sequence.take(text, "main", "QR code", "descriptor")
    assert decoded == session.descriptor_text(0)


def test_scanning_a_ur_opens_the_wallet_flow():
    session = Session()
    session.add_mnemonic(ABANDON)
    body = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    session.add_text(f"{body}#{checksum(body)}")
    ur = descriptor_ur(session, 0).upper()

    app = App()
    app.screen = "wallets"
    app.scan_kind = "descriptor"
    app.screen = "scan"
    app.accept_qr(ur)
    assert app.screen != "load-error"
    assert app.load_error == ""


def test_a_bbqr_sequence_counts_parts_then_loads_the_descriptor():
    session = Session()
    session.add_mnemonic(ABANDON)
    body = f"wpkh({expression(ABANDON, 'm/84h/0h/0h')})"
    descriptor = f"{body}#{checksum(body)}"
    parts = _bbqr_parts(descriptor.encode("utf-8"), count=2)
    app = App()
    app.screen = "scan"
    app.scan_kind = "descriptor"
    app.accept_qr(parts[1])
    assert app.screen == "scan"
    assert app.scan_prompt() == "Scanned 1 of 2 parts."
    app.accept_qr(parts[0])
    assert app.screen != "load-error"
    assert "not recognized" not in app.load_error


def test_one_bbqr_part_in_a_file_asks_for_the_camera():
    from bigsigner.scan import import_scanned
    from bigsigner.session import SessionError

    parts = _bbqr_parts(b"wpkh(x)", count=2)
    try:
        import_scanned(Session(), parts[0], expect="descriptor", source="file")
    except SessionError as exc:
        assert "sequence" in str(exc)
    else:
        raise AssertionError("a single part was imported")


def _bbqr_parts(raw: bytes, count: int) -> list[str]:
    compressed = zlib.compress(raw, level=9, wbits=-10)
    encoded = base64.b32encode(compressed).decode("ascii").rstrip("=")
    size = (len(encoded) + count - 1) // count
    # Base32 parts other than the last must be a multiple of 8 characters.
    size += (8 - size % 8) % 8
    chunks = [encoded[index : index + size] for index in range(0, len(encoded), size)]
    while len(chunks) < count:
        chunks.append("")
    chunks = chunks[:count]
    parts = []
    for index, chunk in enumerate(chunks):
        header = f"B$ZU{count:02d}{index:02d}"
        # count and index above only work for 0-9. The test uses 2.
        part = header + chunk
        encoding, file_type, total, number, payload = split_bbqr(part)
        assert (encoding, file_type, total, number) == ("Z", "U", count, index)
        parts.append(part)
    assert join_bbqr([part[8:] for part in parts], "Z") == raw
    return parts

"""Uniform Resource encoding and decoding for a wallet descriptor.

The QR uses the crypto-output type from BCR-2020-010. That is the UR Sparrow
shows for a wallet descriptor. The account extended key is the HD key, and the
receive and change steps ``/<0;1>/*`` are left off: a scanner that follows
Sparrow treats a missing child path as ``/0/*`` and ``/1/*``.

The bytewords list is copied from Blockchain Commons URKit.
"""

import io
import zlib

from embit.bip32 import HDKey
from embit.descriptor.checksum import checksum
from embit.ec import PublicKey
from embit.networks import NETWORKS

from .paths import HARDENED, MULTISIG_NATIVE, SINGLESIG_TAPROOT, format_index
from .session import SessionError, _public_for

# 256 four-letter words, concatenated. Minimal form keeps the first and last letter.
BYTEWORDS = (
    "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrew"
    "bulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdeli"
    "dicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfair"
    "fernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow"
    "goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedide"
    "aidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokept"
    "keyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluau"
    "lucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote"
    "numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquad"
    "quizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslot"
    "soapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinugly"
    "undouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs"
    "whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom"
)

_WPKH = 404
_TR = 409
_WSH = 401
_SORTED_MULTISIG = 407
_HDKEY = 303
_KEYPATH = 304
_COIN_INFO = 305


def descriptor_ur(session, wallet_index: int) -> str:
    """Lowercase ``ur:crypto-output/...`` for one wallet. The QR uppercases it."""
    wallet = session.wallets[wallet_index]
    keys = [
        _public_for(session, fingerprint, wallet.role, wallet.accounts[fingerprint])
        for fingerprint in wallet.fingerprints
    ]
    if wallet.role == MULTISIG_NATIVE:
        keys = sorted(keys, key=lambda key: key.xpub.derive("m/0/0").sec())
    return encode_ur("crypto-output", _crypto_output(keys, wallet.role, wallet.threshold, session.network))


def encode_ur(type_name: str, cbor: bytes) -> str:
    return f"ur:{type_name}/{encode_minimal(cbor)}"


def decode_ur(text: str) -> tuple[str, bytes]:
    """Return the type and CBOR from a single-part UR. Case does not matter."""
    type_name, seq, encoded = split_ur(text)
    if seq is not None:
        raise ValueError("This UR is not a single part.")
    return type_name, encoded


def split_ur(text: str) -> tuple[str, tuple[int, int] | None, bytes]:
    """Return the type, the ``seq-len`` pair for a fountain part, and the decoded bytes."""
    body = "".join(text.split()).lower()
    if not body.startswith("ur:"):
        raise ValueError("This is not a UR.")
    rest = body[3:]
    type_name, _, tail = rest.partition("/")
    if not type_name or not tail or not _ur_type(type_name):
        raise ValueError("This UR could not be read.")
    seq = None
    encoded = tail
    if "/" in tail:
        head, _, encoded = tail.partition("/")
        number, dash, length = head.partition("-")
        if not dash or not number.isdigit() or not length.isdigit():
            raise ValueError("This UR could not be read.")
        seq = (int(number), int(length))
    if not encoded or not encoded.isalpha():
        raise ValueError("This UR could not be read.")
    try:
        return type_name, seq, decode_minimal(encoded)
    except (ValueError, KeyError) as exc:
        raise ValueError("This UR could not be read.") from exc


def text_from_ur(type_name: str, cbor: bytes, network: str) -> str:
    """The descriptor, seed, or other text carried by one complete UR."""
    try:
        item = cbor_decode(cbor)
    except (ValueError, IndexError, UnicodeDecodeError) as exc:
        raise SessionError("This UR could not be read.") from exc
    if type_name == "crypto-output":
        body = _output_descriptor(item, network)
        return f"{body}#{checksum(body)}"
    if type_name == "bytes":
        if not isinstance(item, (bytes, bytearray)):
            raise SessionError("This UR could not be read.")
        return _bytes_as_text(bytes(item))
    if type_name == "crypto-psbt":
        if not isinstance(item, (bytes, bytearray)):
            raise SessionError("This UR could not be read.")
        return _psbt_text(bytes(item))
    if type_name == "output-descriptor":
        return _output_descriptor_v3(item)
    raise SessionError("This UR type is not supported.")


def encode_minimal(data: bytes) -> str:
    payload = data + (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")
    return "".join(_minimal(byte) for byte in payload)


def decode_minimal(encoded: str) -> bytes:
    if len(encoded) % 2:
        raise ValueError("Bytewords are an even number of letters.")
    raw = bytes(_MINIMAL_INDEX[encoded[index : index + 2]] for index in range(0, len(encoded), 2))
    data, checksum = raw[:-4], raw[-4:]
    if (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big") != checksum:
        raise ValueError("The UR checksum does not match.")
    return data


def _minimal(value: int) -> str:
    start = value * 4
    return BYTEWORDS[start] + BYTEWORDS[start + 3]


_MINIMAL_INDEX = {_minimal(value): value for value in range(256)}


def _crypto_output(keys, role: str, threshold: int, network: str) -> bytes:
    if role == MULTISIG_NATIVE:
        body = _map(
            [
                (1, _uint(int(threshold))),
                (2, _array([_tag(_HDKEY, _hdkey(key, network)) for key in keys])),
            ]
        )
        return _tag(_WSH, _tag(_SORTED_MULTISIG, body))
    wrapper = _TR if role == SINGLESIG_TAPROOT else _WPKH
    return _tag(wrapper, _tag(_HDKEY, _hdkey(keys[0], network)))


def _hdkey(key, network: str) -> bytes:
    xpub = key.xpub
    coin = 0 if network == "main" else 1
    origin = _map(
        [
            (1, _path(key.path)),
            (2, _uint(int.from_bytes(key.fingerprint, "big"))),
            (3, _uint(len(key.path))),
        ]
    )
    return _map(
        [
            (2, b"\xf4"),
            (3, _bstr(xpub.sec())),
            (4, _bstr(xpub.chain_code)),
            (5, _tag(_COIN_INFO, _map([(1, _uint(0)), (2, _uint(coin))]))),
            (6, _tag(_KEYPATH, origin)),
            (8, _uint(int.from_bytes(xpub.fingerprint, "big"))),
        ]
    )


def _path(steps) -> bytes:
    parts = []
    for step in steps:
        parts.append(_uint(step & ~HARDENED))
        parts.append(b"\xf5" if step & HARDENED else b"\xf4")
    return _array(parts)


def _uint(value: int) -> bytes:
    return _head(0, value)


def _bstr(data: bytes) -> bytes:
    return _head(2, len(data)) + data


def _array(items) -> bytes:
    return _head(4, len(items)) + b"".join(items)


def _map(pairs) -> bytes:
    return _head(5, len(pairs)) + b"".join(_uint(key) + value for key, value in pairs)


def _tag(tag: int, item: bytes) -> bytes:
    return _head(6, tag) + item


def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 256:
        return bytes([(major << 5) | 24, value])
    if value < 65536:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def _ur_type(name: str) -> bool:
    return bool(name) and all(char.islower() or char.isdigit() or char == "-" for char in name)


class Tagged:
    def __init__(self, tag: int, value):
        self.tag = tag
        self.value = value


def cbor_decode(data: bytes):
    value, offset = _cbor_read(data, 0)
    if offset != len(data):
        raise ValueError("The CBOR value does not fill its bytes.")
    return value


def _cbor_read(data: bytes, index: int):
    if index >= len(data):
        raise ValueError("The CBOR value is cut off.")
    initial = data[index]
    major = initial >> 5
    info = initial & 0x1F
    index += 1
    if info < 24:
        length = info
    elif info == 24:
        length = data[index]
        index += 1
    elif info == 25:
        length = int.from_bytes(data[index : index + 2], "big")
        index += 2
    elif info == 26:
        length = int.from_bytes(data[index : index + 4], "big")
        index += 4
    elif info == 27:
        length = int.from_bytes(data[index : index + 8], "big")
        index += 8
    else:
        raise ValueError("This CBOR length is not supported.")
    if major == 0:
        return length, index
    if major == 1:
        return -1 - length, index
    if major == 2:
        end = index + length
        return bytes(data[index:end]), end
    if major == 3:
        end = index + length
        return data[index:end].decode("utf-8"), end
    if major == 4:
        items = []
        for _ in range(length):
            item, index = _cbor_read(data, index)
            items.append(item)
        return items, index
    if major == 5:
        mapping = {}
        for _ in range(length):
            key, index = _cbor_read(data, index)
            value, index = _cbor_read(data, index)
            mapping[key] = value
        return mapping, index
    if major == 6:
        value, index = _cbor_read(data, index)
        return Tagged(length, value), index
    if major == 7 and length == 20:
        return False, index
    if major == 7 and length == 21:
        return True, index
    if major == 7 and length == 22:
        return None, index
    raise ValueError("This CBOR value is not supported.")


_SCRIPTS = {
    400: "sh",
    401: "wsh",
    402: "pk",
    403: "pkh",
    404: "wpkh",
    405: "combo",
    406: "multi",
    407: "sortedmulti",
    409: "tr",
}


def _output_descriptor(item, network: str) -> str:
    names = []
    while isinstance(item, Tagged) and item.tag in _SCRIPTS:
        names.append(_SCRIPTS[item.tag])
        item = item.value
        if names[-1] in ("multi", "sortedmulti"):
            break
    if not names:
        raise SessionError("This UR is not a wallet descriptor.")
    if names[-1] in ("multi", "sortedmulti"):
        inner = _multisig(names[-1], item, network)
        for name in reversed(names[:-1]):
            inner = f"{name}({inner})"
        return inner
    inner = _key_expression(item, network)
    for name in reversed(names):
        inner = f"{name}({inner})"
    return inner


def _multisig(name: str, item, network: str) -> str:
    if not isinstance(item, dict) or 1 not in item or 2 not in item:
        raise SessionError("This UR multisig could not be read.")
    keys = ",".join(_key_expression(key, network) for key in item[2])
    return f"{name}({item[1]},{keys})"


def _key_expression(item, network: str) -> str:
    if not isinstance(item, Tagged) or item.tag != _HDKEY or not isinstance(item.value, dict):
        raise SessionError("This UR key is not an extended public key.")
    fields = item.value
    if fields.get(2) is True:
        raise SessionError("This UR contains a private key.")
    pubkey = fields.get(3)
    chain = fields.get(4)
    origin = fields.get(6)
    if not isinstance(pubkey, (bytes, bytearray)) or not isinstance(chain, (bytes, bytearray)):
        raise SessionError("This UR key is not an extended public key.")
    if not isinstance(origin, Tagged) or origin.tag != _KEYPATH or not isinstance(origin.value, dict):
        raise SessionError("This UR key does not include its derivation path.")
    steps = _fixed_steps(origin.value.get(1))
    if 2 not in origin.value:
        raise SessionError("This UR key does not include its master fingerprint.")
    if 8 not in fields:
        raise SessionError("This UR key does not include its parent fingerprint.")
    parent = _fingerprint_bytes(fields[8])
    version = NETWORKS["main" if network == "main" else "test"]["xpub"]
    try:
        public = PublicKey.read_from(io.BytesIO(bytes(pubkey)))
        extended = HDKey(
            public,
            bytes(chain),
            version=version,
            depth=len(steps),
            fingerprint=parent,
            child_number=steps[-1],
        )
    except Exception as exc:
        raise SessionError("This UR key could not be read.") from exc
    suffix = _child_suffix(fields.get(7))
    path = "/".join(format_index(step) for step in steps)
    return f"[{_fingerprint_bytes(origin.value[2]).hex()}/{path}]{extended.to_string()}{suffix}"


def _fixed_steps(components) -> list[int]:
    if not isinstance(components, list) or not components:
        raise SessionError("This UR key does not include its derivation path.")
    steps = []
    index = 0
    while index < len(components):
        if not isinstance(components[index], int) or index + 1 >= len(components):
            raise SessionError("This UR derivation path is not a fixed account path.")
        number = components[index]
        hardened = components[index + 1] is True
        steps.append(number | HARDENED if hardened else number)
        index += 2
    return steps


def _child_suffix(children) -> str:
    if children is None:
        return "/<0;1>/*"
    if not isinstance(children, Tagged) or children.tag != _KEYPATH or not isinstance(children.value, dict):
        raise SessionError("This UR key uses a child path this version does not read.")
    return "/" + _child_path(children.value.get(1))


def _child_path(components) -> str:
    if not isinstance(components, list):
        raise SessionError("This UR key uses a child path this version does not read.")
    steps = []
    index = 0
    while index < len(components):
        item = components[index]
        if isinstance(item, int):
            if index + 1 >= len(components):
                raise SessionError("This UR key uses a child path this version does not read.")
            hardened = components[index + 1] is True
            steps.append(f"{item}h" if hardened else str(item))
            index += 2
            continue
        if isinstance(item, list) and len(item) == 0:
            if index + 1 >= len(components):
                raise SessionError("This UR key uses a child path this version does not read.")
            steps.append("*")
            index += 2
            continue
        if isinstance(item, list) and len(item) == 4:
            left = f"{item[0]}h" if item[1] is True else str(item[0])
            right = f"{item[2]}h" if item[3] is True else str(item[2])
            steps.append(f"<{left};{right}>")
            index += 1
            continue
        raise SessionError("This UR key uses a child path this version does not read.")
    if not steps:
        raise SessionError("This UR key uses a child path this version does not read.")
    return "/".join(steps)


def _fingerprint_bytes(value: int) -> bytes:
    if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFF:
        raise SessionError("This UR fingerprint could not be read.")
    return value.to_bytes(4, "big")


def _output_descriptor_v3(item) -> str:
    if isinstance(item, Tagged):
        item = item.value
    if not isinstance(item, dict) or not isinstance(item.get(1), str):
        raise SessionError("This UR is not a wallet descriptor.")
    source = item[1]
    if "@" in source:
        raise SessionError("This UR type is not supported.")
    return source


def _bytes_as_text(data: bytes) -> str:
    if data.startswith(b"psbt"):
        return _psbt_text(data)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SessionError("This UR could not be read.") from exc


def _psbt_text(data: bytes) -> str:
    import base64

    return base64.b64encode(data).decode("ascii")

"""BSMS 1.0 wallet files.

A valid file has four lines: the version, one output descriptor, the receive
and change paths, and the first address. The address must be the one that
descriptor derives, and the paths must describe the same branches.
"""

from embit.descriptor import Descriptor
from embit.networks import NETWORKS

from .parse import ParseError, parse_wallet, split_checksum, _normalize_expression


def descriptor_from_bsms(text: str, network: str) -> str:
    """Return the descriptor from a BSMS 1.0 file, or explain why it is refused."""
    lines = _records(text)
    if lines[0] != "BSMS 1.0":
        if lines[0].upper().startswith("BSMS"):
            raise ParseError("This BSMS file uses a version BigSigner does not read.")
        raise ParseError("This BSMS file is not valid.")
    descriptor = lines[1]
    try:
        body, _digest = split_checksum(_normalize_expression(descriptor))
    except ParseError as exc:
        raise ParseError(f"This BSMS file cannot be used. {exc}") from exc
    if not body.startswith(("wpkh(", "tr(", "wsh(", "sh(")):
        raise ParseError("This BSMS file is not a wallet descriptor.")
    try:
        parsed = parse_wallet(descriptor, network)
    except ParseError as exc:
        raise ParseError(f"This BSMS file cannot be used. {exc}") from exc
    branches = _path_branches(lines[2])
    expected = _descriptor_branches(parsed)
    if branches != expected:
        raise ParseError("This BSMS file's derivation paths do not match the descriptor.")
    branch = 0 if 0 in branches else 1
    try:
        derived = (
            Descriptor.from_string(body)
            .derive(0, branch_index=branch)
            .address(network=NETWORKS[{"main": "main", "regtest": "regtest"}.get(network, "test")])
        )
    except Exception as exc:
        raise ParseError("This BSMS file's first address could not be checked.") from exc
    if derived.lower() != lines[3].lower():
        raise ParseError("This BSMS file's first address does not match the descriptor.")
    return descriptor


def _records(text: str) -> list[str]:
    text = text.lstrip("\ufeff").replace("\r\n", "\n").replace("\r", "\n").strip()
    lines = [line.strip() for line in text.split("\n")]
    if any(line == "" for line in lines):
        raise ParseError("This BSMS file has an empty line.")
    if len(lines) != 4:
        raise ParseError("This BSMS file does not have the four required lines.")
    return lines


def _path_branches(line: str) -> set[int]:
    parts = [part.strip() for part in line.split(",")]
    if not parts or any(part == "" for part in parts) or len(parts) != len(set(parts)):
        raise ParseError("This BSMS file's derivation paths do not match the descriptor.")
    branches = set()
    for part in parts:
        if part.startswith("m/"):
            part = part[1:]
        if not part.startswith("/"):
            part = "/" + part
        if part == "/0/*":
            branches.add(0)
        elif part == "/1/*":
            branches.add(1)
        else:
            raise ParseError("This BSMS file's derivation paths do not match the descriptor.")
    return branches


def _descriptor_branches(parsed) -> set[int]:
    notes = {key.branch_note for key in parsed.keys}
    if notes == {"both"}:
        return {0, 1}
    if notes == {"receive_only"}:
        return {0}
    if notes == {"change_only"}:
        return {1}
    raise ParseError("This BSMS file's derivation paths do not match the descriptor.")

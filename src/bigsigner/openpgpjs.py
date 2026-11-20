"""GPG operations for the web emulator, performed by OpenPGP.js.

The device uses ``GpgBackend`` and the ``gpg`` command. This backend is selected
only when Python is running under Pyodide. Keys stay in the page until reload.
"""

import base64
from pathlib import Path
import hashlib
import json
import os
import re

from . import sdcard
from .gpg import (
    CHECKSUM_LIMIT, CHECKSUM_NAME, CHECKSUM_SIGNATURE, CommandResult, GpgError, Outcome, PublicKey,
    _manifest_line, _password_bytes, files_left_unchecked, manifest_for_name,
)
from .openpgp_subkey import secret_subkey_armor


class OpenPgpJsBackend:
    """The same operations the GPG screens call, answered by OpenPGP.js."""

    threaded = False

    def __init__(self):
        self._version_line = None

    @property
    def supported(self) -> bool:
        try:
            from js import bigsignerOpenpgp
        except Exception:
            return False
        return bigsignerOpenpgp is not None

    def version_line(self) -> str:
        if self._version_line is not None:
            return self._version_line
        self._version_line = ""
        if not self.supported:
            return ""
        try:
            self._version_line = self._call({"op": "version"}).get("version") or ""
        except GpgError:
            self._version_line = ""
        return self._version_line

    def mix_entropy(self, digest: bytes):
        """The browser random source cannot accept the camera digest."""
        return None

    def list_keys(self, timestamp=None):
        try:
            result = self._call({"op": "list"})
        except GpgError as exc:
            return Outcome(False, str(exc))
        return Outcome(True, keys=[_key(item) for item in result.get("keys") or []])

    def inspect_key(self, content, timestamp=None):
        try:
            result = self._call({"op": "inspect", **_content(content)})
            keys = [_key(item) for item in result.get("keys") or []]
            if not keys:
                raise GpgError("The GPG key information has no fingerprint.")
        except GpgError as exc:
            return Outcome(False, str(exc))
        return Outcome(True, keys=keys)

    def import_key(self, content, timestamp=None):
        try:
            self._call({"op": "import", **_content(content)})
        except GpgError as exc:
            return Outcome(False, str(exc))
        return Outcome(True, stages=[CommandResult("Import GPG Key", 0, "The key was imported.\n")])

    def delete_key(self, fingerprint: str):
        try:
            self._call({"op": "delete", "fingerprint": fingerprint})
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult("Delete Keys", 1, "", str(exc))])
        return Outcome(True, stages=[CommandResult("Delete Keys", 0, "The key was deleted.\n")])

    def export_key(self, fingerprint: str, *, secret: bool = False, subkey: bool = False):
        name = "Export Private Subkey" if subkey else ("Export Private Key" if secret else "Export Public Key")
        try:
            result = self._call({"op": "export", "fingerprint": fingerprint, "secret": secret or subkey, "subkey": subkey})
            armor = result.get("armor") or ""
            if result.get("patch"):
                armor = secret_subkey_armor(armor, result.get("primary") or "", result.get("sub") or fingerprint)
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult(name, 1, "", str(exc))])
        marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----" if secret or subkey else "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        ok = marker in armor
        return Outcome(ok, "" if ok else "The key could not be exported.", [CommandResult(name, 0 if ok else 1, armor if ok else "", "" if ok else "The key could not be exported.")])

    def add_subkey(self, fingerprint: str, algo: str, usage: str, expire: str, timestamp: int):
        try:
            self._call({
                "op": "add-subkey", "fingerprint": fingerprint, "algo": algo,
                "usage": usage, "expire": expire, "timestamp": timestamp,
            })
            keys = self.list_keys()
        except GpgError as exc:
            return Outcome(False, str(exc))
        if not keys.ok:
            return keys
        return Outcome(True, keys=keys.keys)

    def encrypt_file(self, fingerprints: list[str], relative: str, output_name: str, storage: str):
        if not fingerprints:
            raise GpgError("Select an encryption key.")
        if not output_name or output_name in (".", "..") or "/" in output_name or "\\" in output_name or "\x00" in output_name:
            raise GpgError("The file name is not valid.")
        data = _read(relative, storage)
        try:
            result = self._call({"op": "encrypt", "fingerprints": list(fingerprints), "data": _b64(data)})
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult("Encrypt File", 1, "", str(exc))])
        armor = result.get("armor") or ""
        if not armor.startswith("-----BEGIN PGP MESSAGE-----"):
            return Outcome(False, "The file could not be encrypted.", [CommandResult("Encrypt File", 1, "", "The file could not be encrypted.")])
        sdcard.write_bytes(_sibling(relative, output_name), armor.encode("utf-8"), storage=storage)
        return Outcome(True, stages=[CommandResult("Encrypt File", 0, "The encrypted file was written.\n")])

    def encrypt_symmetric(self, relative: str, output_name: str, storage: str, password: str):
        _password_bytes(password)
        if not output_name or output_name in (".", "..") or "/" in output_name or "\\" in output_name or "\x00" in output_name:
            raise GpgError("The file name is not valid.")
        data = _read(relative, storage)
        try:
            result = self._call({"op": "encrypt", "password": password, "data": _b64(data)})
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult("Encrypt File", 1, "", str(exc))])
        armor = result.get("armor") or ""
        if not armor.startswith("-----BEGIN PGP MESSAGE-----"):
            return Outcome(False, "The file could not be encrypted.", [CommandResult("Encrypt File", 1, "", "The file could not be encrypted.")])
        sdcard.write_bytes(_sibling(relative, output_name), armor.encode("utf-8"), storage=storage)
        return Outcome(True, stages=[CommandResult("Encrypt File", 0, "The encrypted file was written.\n")])

    def sign_file(self, fingerprint: str, relative: str, storage: str, timestamp: int):
        data = _read(relative, storage)
        try:
            result = self._call({"op": "sign", "fingerprint": fingerprint, "data": _b64(data), "timestamp": timestamp})
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult("Sign File", 1, "", str(exc))])
        armor = result.get("armor") or ""
        if not armor.startswith("-----BEGIN PGP SIGNATURE-----"):
            return Outcome(False, "The file could not be signed.", [CommandResult("Sign File", 1, "", "The file could not be signed.")])
        sdcard.write_bytes(_sibling(relative, Path(relative).name + ".asc"), armor.encode("utf-8"), storage=storage)
        return Outcome(True, stages=[CommandResult("Sign File", 0, "The signature was written.\n")])

    def sign_folder(self, fingerprint: str, relative: str, storage: str, timestamp: int):
        manifest = _folder_manifest(relative, storage)
        sdcard.write_bytes(sdcard.child_path(relative, CHECKSUM_NAME), manifest, storage=storage)
        try:
            result = self._call({"op": "sign", "fingerprint": fingerprint, "data": _b64(manifest), "timestamp": timestamp})
        except GpgError as exc:
            return Outcome(False, str(exc), [CommandResult("Sign File", 1, "", str(exc))])
        armor = result.get("armor") or ""
        if not armor.startswith("-----BEGIN PGP SIGNATURE-----"):
            return Outcome(False, "The folder could not be signed.", [CommandResult("Sign File", 1, "", "The folder could not be signed.")])
        sdcard.write_bytes(sdcard.child_path(relative, CHECKSUM_SIGNATURE), armor.encode("utf-8"), storage=storage)
        return Outcome(True, stages=[CommandResult("Sign File", 0, "The signature was written.\n")])

    def verify(self, relative, storage, timestamp, checksums=False, only=None):
        name = Path(relative).name
        if not name.lower().endswith(".asc") or len(name) <= 4:
            raise GpgError("Choose an .asc signature file.")
        parent = "" if "/" not in relative.replace("\\", "/") else str(Path(relative).parent)
        if parent == ".":
            parent = ""
        companion_name = name[:-4]
        companion = sdcard.child_path(parent, companion_name)
        signature = _read(relative, storage)
        if sdcard.file_exists(companion, storage=storage):
            data = _read(companion, storage)
            verified = self._detached(signature, data, timestamp)
            stages = [verified]
            if verified.returncode:
                return Outcome(False, "Signature verification failed.", stages)
            if not checksums:
                return Outcome(True, stages=stages)
            limited = _only_manifest(data, only)
            if limited is None:
                return Outcome(False, "This file is not listed in the checksum file.", stages)
            checked = _check_manifest(limited, parent, storage)
            stages.append(checked)
            unchecked = [] if only is not None else _unchecked_files(limited, parent, storage, companion_name, name)
            failed = checked.returncode != 0
            return Outcome(not failed, "The SHA256 check failed." if failed else "", stages, unverified=unchecked)
        if not checksums:
            raise GpgError(f'The matching file "{companion_name}" is missing from this folder.')
        verified, body = self._cleartext(signature, timestamp)
        stages = [verified]
        if verified.returncode:
            return Outcome(False, "Signature verification failed.", stages)
        limited = _only_manifest(body, only)
        if limited is None:
            return Outcome(False, "This file is not listed in the checksum file.", stages)
        checked = _check_manifest(limited, parent, storage)
        stages.append(checked)
        unchecked = [] if only is not None else _unchecked_files(limited, parent, storage, "", name)
        failed = checked.returncode != 0
        return Outcome(not failed, "The SHA256 check failed." if failed else "", stages, unverified=unchecked)

    def _detached(self, signature: bytes, data: bytes, timestamp: int) -> CommandResult:
        try:
            text = signature.decode("utf-8")
            self._call({"op": "verify-detached", "armored": text, "data": _b64(data), "timestamp": timestamp})
        except (UnicodeDecodeError, GpgError) as exc:
            return CommandResult("Signature Verification", 1, "", str(exc))
        return CommandResult("Signature Verification", 0, "Good signature.\n", "")

    def _cleartext(self, signature: bytes, timestamp: int):
        try:
            text = signature.decode("utf-8")
            result = self._call({"op": "verify-cleartext", "armored": text, "timestamp": timestamp})
        except (UnicodeDecodeError, GpgError) as exc:
            return CommandResult("Signature Verification", 1, "", str(exc)), b""
        body = result.get("text") or ""
        return CommandResult("Signature Verification", 0, "Good signature.\n", ""), body.encode("utf-8")

    def _call(self, payload: dict) -> dict:
        if not self.supported:
            raise GpgError("GPG commands are not available in the web emulator. Use the BigSigner device.")
        from pyodide.ffi import run_sync
        from js import bigsignerOpenpgp

        raw = run_sync(bigsignerOpenpgp(json.dumps(payload)))
        if not isinstance(raw, str):
            raw = str(raw)
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GpgError("The GPG command failed.") from exc
        if not result.get("ok"):
            raise GpgError(result.get("error") or "The GPG command failed.")
        return result


def _key(record: dict) -> PublicKey:
    return PublicKey(
        fingerprint=record.get("fingerprint") or "",
        key_id=record.get("keyId") or "",
        algorithm=record.get("algorithm") or "",
        created=record.get("created") or "",
        expires=record.get("expires") or "Never",
        validity=record.get("validity") or "Unknown",
        user_ids=list(record.get("userIds") or []),
        subkeys=[_subkey(item) for item in record.get("subkeys") or []],
        secret=bool(record.get("secret")),
        secret_available=bool(record.get("secretAvailable")),
        contains_private=bool(record.get("containsPrivate")),
        needs_passphrase=bool(record.get("needsPassphrase")),
        capabilities=record.get("capabilities") or "",
    )


def _subkey(record: dict) -> dict:
    return {
        "fingerprint": record.get("fingerprint") or "",
        "key_id": record.get("keyId") or "",
        "algorithm": record.get("algorithm") or "",
        "created": record.get("created") or "",
        "expires": record.get("expires") or "Never",
        "validity": record.get("validity") or "Unknown",
        "capabilities": record.get("capabilities") or "",
        "secret": bool(record.get("secret")),
        "secret_available": bool(record.get("secretAvailable")),
        "contains_private": bool(record.get("containsPrivate")),
        "needs_passphrase": bool(record.get("needsPassphrase")),
    }


def _content(content) -> dict:
    if isinstance(content, str):
        content = content.encode("utf-8")
    if content.startswith(b"-----BEGIN"):
        return {"armored": content.decode("utf-8")}
    return {"binary": _b64(content)}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _read(relative: str, storage: str) -> bytes:
    try:
        return sdcard.read_bytes(relative, storage=storage, max_bytes=CHECKSUM_LIMIT)
    except sdcard.SdError as exc:
        raise GpgError(str(exc)) from exc


def _sibling(relative: str, name: str) -> str:
    parent = "" if "/" not in relative.replace("\\", "/") else str(Path(relative).parent)
    if parent == ".":
        parent = ""
    return sdcard.child_path(parent, name)


def _folder_manifest(relative: str, storage: str) -> bytes:
    try:
        entries = sdcard.list_folder(relative, storage=storage)
    except sdcard.SdError as exc:
        raise GpgError(str(exc)) from exc
    names = sorted(
        (item["name"] for item in entries if item["kind"] == "file" and item["name"] not in (CHECKSUM_NAME, CHECKSUM_SIGNATURE)),
        key=lambda name: name.encode(),
    )
    lines = []
    for name in names:
        digest = hashlib.sha256(_read(sdcard.child_path(relative, name), storage)).hexdigest()
        lines.append(_manifest_line(name, digest))
    if not lines:
        raise GpgError("This folder has no files to sign.")
    return b"".join(lines)


def _only_manifest(content: bytes, only: str | None) -> bytes | None:
    if only is None:
        return content
    return manifest_for_name(content, only)


def _unchecked_files(content: bytes, directory: str, storage: str, checksum_name: str, signature_name: str) -> list[str]:
    mentioned = [entry for entry, _digest in _manifest_entries(content)]
    try:
        present = [item["name"] for item in sdcard.list_folder(directory, storage=storage) if item["kind"] == "file"]
    except sdcard.SdError:
        return []
    return files_left_unchecked(present, mentioned, checksum_name, signature_name)


def _check_manifest(content: bytes, directory: str, storage: str) -> CommandResult:
    lines = []
    errors = []
    failed = False
    for name, digest in _manifest_entries(content):
        path = sdcard.child_path(directory, name)
        try:
            data = _read(path, storage)
        except GpgError:
            lines.append(f"{name}: FAILED")
            errors.append(f"sha256sum: {name}: No such file or directory")
            failed = True
            continue
        if hashlib.sha256(data).hexdigest() == digest.lower():
            lines.append(f"{name}: OK")
        else:
            lines.append(f"{name}: FAILED")
            failed = True
    stdout = ("\n".join(lines) + "\n") if lines else ""
    stderr = "\n".join(errors)
    if failed and not stderr:
        stderr = "sha256sum: WARNING: 1 computed checksum did NOT match"
    return CommandResult("SHA256 Check", 1 if failed else 0, stdout, stderr, True)


def _manifest_entries(content: bytes):
    for raw in content.split(b"\n"):
        line = raw.rstrip(b"\r")
        if not line.strip() or line.startswith(b"#"):
            continue
        escaped = line.startswith(b"\\")
        body = line[1:] if escaped else line
        match = re.fullmatch(rb"([0-9a-fA-F]{64})[ \t][ *](.+)", body) or re.fullmatch(rb"([0-9a-fA-F]{64})[ \t](.+)", body)
        if not match:
            raise GpgError("The checksum file contains an unsupported checksum line.")
        digest, name = match.group(1).decode("ascii"), match.group(2)
        if escaped:
            name = re.sub(rb"\\([\\nr])", lambda item: {b"\\": b"\\", b"n": b"\n", b"r": b"\r"}[item[1]], name)
        name = os.fsdecode(name)
        if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name:
            raise GpgError("A checksum entry points outside the selected folder.")
        yield name, digest

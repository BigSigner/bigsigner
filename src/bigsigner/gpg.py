"""GnuPG operations with a private RAM keyring and native, streaming file checks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import fcntl
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

from . import sdcard

KEY_LIMIT = 1_048_576
CHECKSUM_LIMIT = 4_194_304
# Linux RNDADDENTROPY is _IOW('R', 0x03, int[2]). The size in the request is 8.
_RNDADDENTROPY = (1 << 30) | (8 << 16) | (ord("R") << 8) | 3
_SUBKEY_ALGOS = {"ed25519", "cv25519", "rsa3072", "rsa4096"}
_SUBKEY_USAGES = {"sign", "encr", "auth"}


def mix_kernel_entropy(digest: bytes) -> None:
    """Mix the camera digest into the kernel pool.

    The entropy count is 0. The digest is 32 bytes wide, and that width is not
    a measurement of how unpredictable the pictures were. The bytes are still mixed.
    """
    if len(digest) != 32:
        raise GpgError("The camera digest is not 32 bytes.")
    argument = struct.pack("ii32s", 0, 32, digest)
    try:
        fd = os.open("/dev/random", os.O_RDWR)
    except OSError as exc:
        raise GpgError("The camera capture could not be mixed into the Linux random number generator.") from exc
    try:
        fcntl.ioctl(fd, _RNDADDENTROPY, argument)
    except OSError as exc:
        raise GpgError("The camera capture could not be mixed into the Linux random number generator.") from exc
    finally:
        os.close(fd)


def quick_add_arguments(fingerprint: str, algo: str, usage: str, expire: str) -> list[str]:
    """Positional arguments for ``gpg --quick-add-key``.

    Algorithm, usage, and expiration are always named. ``never`` is no
    expiration. A set time is ``YYYYMMDDThhmmss`` in UTC.
    """
    if algo not in _SUBKEY_ALGOS or usage not in _SUBKEY_USAGES:
        raise GpgError("The subkey choice is not valid.")
    if expire != "never" and not re.fullmatch(r"\d{8}T\d{6}", expire):
        raise GpgError("The subkey expiration is not valid.")
    if not re.fullmatch(r"[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
        raise GpgError("The key fingerprint is not valid.")
    return [fingerprint, algo, usage, expire]


class GpgError(Exception):
    pass


@dataclass
class CommandResult:
    name: str
    returncode: int
    stdout: str = ""
    stderr: str = ""
    checksums: bool = False
    raw_stdout: bytes | None = None


@dataclass
class PublicKey:
    fingerprint: str = ""
    key_id: str = ""
    algorithm: str = ""
    created: str = ""
    expires: str = ""
    validity: str = ""
    user_ids: list[str] = field(default_factory=list)
    subkeys: list[dict] = field(default_factory=list)
    secret: bool = False
    secret_available: bool = False
    contains_private: bool = False
    needs_passphrase: bool = False
    keygrip: str = ""
    capabilities: str = ""


@dataclass
class Outcome:
    ok: bool
    message: str = ""
    stages: list[CommandResult] = field(default_factory=list)
    keys: list[PublicKey] = field(default_factory=list)
    unverified: list[str] = field(default_factory=list)


def _date(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OverflowError, OSError):
        return value


def _unescape(value: str) -> str:
    data = re.sub(rb"\\x([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), value.encode("utf-8"))
    return data.decode("utf-8", errors="replace")


def parse_keys(output: str, *, secret: bool = False) -> list[PublicKey]:
    """Read primary fingerprints and UID records; never confuse a subkey's FPR.

    Secret records are refused unless ``secret`` is set. Import preview and the
    secret-key list use that mode. The public list keeps the default.
    """
    keys = []
    current = None
    target = None
    algorithms = {"1": "RSA", "2": "RSA", "3": "RSA", "16": "ElGamal", "17": "DSA",
                  "18": "ECDH", "19": "ECDSA", "22": "EdDSA", "25": "X25519", "26": "X448",
                  "27": "Ed25519", "28": "Ed448"}
    validities = {"r": "Revoked", "e": "Expired", "d": "Disabled", "i": "Invalid", "n": "Not Valid",
                  "m": "Marginal", "f": "Full", "u": "Ultimate", "w": "Known Private Key"}
    for line in output.splitlines():
        parts = line.split(":")
        parts += [""] * max(0, 15 - len(parts))
        kind = parts[0]
        if kind in ("sec", "ssb") and not secret:
            raise GpgError("Only public GPG keys can be loaded.")
        if kind in ("pub", "sub") or (secret and kind in ("sec", "ssb")):
            values = dict(key_id=parts[4], algorithm=algorithms.get(parts[3], "Algorithm " + parts[3]),
                          created=_date(parts[5]) if parts[5] else "Unknown",
                          expires=_date(parts[6]) if parts[6] not in ("", "0") else "Never",
                          validity=validities.get(parts[1], "Unknown"))
            if parts[2]:
                values["algorithm"] += f" ({parts[2]} bits)"
            # Field 15 is "+" when this secret key's private material is present.
            # A stub, including a certificate exported with --export-secret-subkeys, is "#".
            available = kind in ("sec", "ssb") and parts[14] == "+"
            # "#" is a stub with no private material. show-keys leaves this field empty.
            contains_private = kind in ("sec", "ssb") and parts[14] != "#"
            if kind in ("pub", "sec"):
                current = PublicKey(**values, secret=kind == "sec", secret_available=available,
                                    contains_private=contains_private, capabilities=parts[11])
                keys.append(current)
                target = current
            elif current is not None:
                values["capabilities"] = parts[11]
                values["secret"] = available
                values["contains_private"] = contains_private
                current.subkeys.append(values)
                target = values
        elif kind == "grp" and target is not None:
            grip = parts[9].upper()
            if re.fullmatch(r"[0-9A-F]{40}", grip):
                if isinstance(target, PublicKey):
                    target.keygrip = grip
                else:
                    target["keygrip"] = grip
        elif kind == "fpr" and target is not None:
            fingerprint = parts[9].upper()
            if len(fingerprint) in (32, 40, 64) and re.fullmatch(r"[0-9A-F]+", fingerprint):
                if isinstance(target, PublicKey):
                    target.fingerprint = fingerprint
                else:
                    target["fingerprint"] = fingerprint
        elif kind == "uid" and current is not None:
            current.user_ids.append(_unescape(parts[9]))
    if any(not key.fingerprint for key in keys):
        raise GpgError("The GPG key information has no primary fingerprint.")
    return keys


def status_names(output: str) -> set[str]:
    return {line.split()[1] for line in output.splitlines()
            if line.startswith("[GNUPG:] ") and len(line.split()) > 1}


def signature_ok(result: CommandResult) -> bool:
    names = status_names(result.stdout)
    failures = {"BADSIG", "ERRSIG", "NO_PUBKEY", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NODATA", "FAILURE", "BADARMOR"}
    return result.returncode == 0 and "VALIDSIG" in names and not names.intersection(failures)


# These signature formats do not take a random nonce. ECDSA, DSA, and any
# algorithm the colon record does not name still need a mixed camera capture.
_DETERMINISTIC_SIGNATURES = {"RSA", "Ed25519", "EdDSA", "Ed448"}
CHECKSUM_NAME = "SHA256SUMS"
CHECKSUM_SIGNATURE = "SHA256SUMS.asc"


def passphrase_required(keyinfo_line: str) -> bool:
    """True when gpg-agent's KEYINFO protection field is ``P``.

    ``C`` is an unprotected secret, including one saved with an empty passphrase.
    ``-`` means the protection is not known. Only ``P`` is a passphrase.
    """
    parts = keyinfo_line.split()
    return len(parts) > 7 and parts[0] == "S" and parts[1] == "KEYINFO" and parts[7] == "P"


def signature_is_deterministic(algorithm: str) -> bool:
    """True when this signing key's signature bytes do not depend on the kernel RNG."""
    return algorithm.split(" (", 1)[0] in _DETERMINISTIC_SIGNATURES


def sha256_manifest(directory: Path) -> bytes:
    """GNU binary-mode lines for the files directly in ``directory``.

    Subfolders, the checksum file, and its signature are omitted. A symlink
    that resolves outside the folder is omitted too.
    """
    root = directory.resolve()
    lines = []
    for child in sorted(directory.iterdir(), key=lambda item: item.name.encode()):
        if child.name in (CHECKSUM_NAME, CHECKSUM_SIGNATURE) or not child.is_file():
            continue
        if child.is_symlink():
            try:
                child.resolve().relative_to(root)
            except (ValueError, OSError):
                continue
        digest = hashlib.sha256()
        with child.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        lines.append(_manifest_line(child.name, digest.hexdigest()))
    if not lines:
        raise GpgError("This folder has no files to sign.")
    return b"".join(lines)


def _manifest_line(name: str, digest: str) -> bytes:
    raw = name.encode("utf-8")
    if any(byte in raw for byte in (b"\\", b"\n", b"\r")):
        escaped = raw.replace(b"\\", b"\\\\").replace(b"\n", b"\\n").replace(b"\r", b"\\r")
        return b"\\" + digest.encode("ascii") + b" *" + escaped + b"\n"
    return f"{digest} *{name}\n".encode("utf-8")


def looks_like_sha256sums(content: bytes) -> bool:
    """True when every line is blank, spaces, or a SHA256 checksum, and one checksum exists.

    A checksum line is 64 hex characters, one or more spaces, and a filename.
    """
    if not sdcard.ascii_text(content):
        return False
    found = False
    for line in content.splitlines():
        if line == b"" or _only_spaces(line):
            continue
        if _SHA256_LINE.fullmatch(line):
            found = True
            continue
        return False
    return found


def _only_spaces(line: bytes) -> bool:
    return bool(line) and all(byte == 0x20 for byte in line)


_SHA256_LINE = re.compile(rb"[0-9a-fA-F]{64} +.+")


def manifest_filenames(content: bytes) -> list[str]:
    """Filenames named by a GNU or BSD SHA256 manifest, in file order."""
    names = []
    for line in content.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line.strip() or line.startswith(b"#"):
            continue
        escaped = line.startswith(b"\\")
        body = line[1:] if escaped else line
        match = re.fullmatch(rb"[0-9a-fA-F]{64}[ \t][ *](.+)", body)
        if not match:
            match = re.fullmatch(rb"SHA256 \((.+)\) = [0-9a-fA-F]{64}", line)
        if not match:
            # GNU also accepts the legacy one-whitespace form.
            match = re.fullmatch(rb"[0-9a-fA-F]{64}[ \t](.+)", body)
        if not match:
            raise GpgError("The checksum file contains an unsupported checksum line.")
        name = match[1]
        if escaped:
            name = re.sub(rb"\\([\\nr])", lambda item: {b"\\": b"\\", b"n": b"\n", b"r": b"\r"}[item[1]], name)
        names.append(os.fsdecode(name))
    return names


def files_left_unchecked(present: list[str], mentioned: list[str], *reserved: str) -> list[str]:
    """Files in the folder that the checksum list does not name.

    ``reserved`` holds the checksum file and the signature file. The result
    keeps the order of ``present``.
    """
    skip = set(mentioned)
    skip.update(name for name in reserved if name)
    return [name for name in present if name not in skip]


def check_manifest_paths(content: bytes, directory: Path) -> None:
    """Confine GNU/BSD manifest paths before allowing the checker to open them."""
    root = directory.resolve()
    for name in manifest_filenames(content):
        try:
            if name == "-" or "\x00" in name or Path(name).is_absolute():
                raise ValueError
            (root / name).resolve().relative_to(root)
        except (ValueError, OSError, RuntimeError) as exc:
            raise GpgError("A checksum entry points outside the selected folder.") from exc


class GpgBackend:
    def __init__(self, home: Path | None = None):
        self.home = home

    @property
    def supported(self):
        return sys.platform not in ("emscripten", "wasi")

    def _home(self):
        if not self.supported:
            raise GpgError("GPG commands are not available in the web emulator. Use the BigSigner device.")
        if self.home is None:
            try:
                self.home = sdcard.ram_directory("bigsigner-gpg")
            except sdcard.SdError as exc:
                raise GpgError("A RAM filesystem is required for the GPG keyring.") from exc
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.home.chmod(0o700)
        return self.home

    def version_line(self) -> str:
        """First stdout line of ``gpg --version``. Empty when GPG cannot run."""
        if hasattr(self, "_version_line"):
            return self._version_line
        self._version_line = ""
        if not self.supported:
            return ""
        env = dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC")
        try:
            result = subprocess.run(["gpg", "--version"], stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ""
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        self._version_line = lines[0] if lines else ""
        return self._version_line

    def command(self, name, args, *, data=None, cwd=None, timestamp=None, checksums=False, agent=False, passphrase=None):
        home = self._home()
        if checksums:
            argv = ["sha256sum", *args]
        else:
            # Secret import, secret listing, and private export need gpg-agent.
            # --no-autostart leaves those operations with no key encryption key.
            argv = ["gpg", "--no-options", "--homedir", str(home), "--batch", "--no-tty"]
            if not agent:
                argv.append("--no-autostart")
            argv += ["--no-auto-key-retrieve", "--no-auto-key-import", "--auto-key-locate", "clear"]
            if timestamp is not None:
                argv += ["--faked-system-time", str(timestamp)]
            if passphrase is not None:
                argv += ["--pinentry-mode", "loopback", "--passphrase", passphrase]
            argv += args
        env = dict(os.environ, GNUPGHOME=str(home), LC_ALL="C", LANG="C", TZ="UTC")
        try:
            result = subprocess.run(argv, input=data, stdin=subprocess.DEVNULL if data is None else None,
                                    capture_output=True, cwd=cwd, env=env, timeout=3600)
            return CommandResult(name, result.returncode, result.stdout.decode("utf-8", "replace"),
                                 result.stderr.decode("utf-8", "replace"), checksums, result.stdout)
        except FileNotFoundError:
            return CommandResult(name, 127, stderr=f"{argv[0]} is not installed on this system.", checksums=checksums)
        except subprocess.TimeoutExpired as exc:
            return CommandResult(name, 124, (exc.stdout or b"").decode("utf-8", "replace"),
                                 (exc.stderr or b"").decode("utf-8", "replace") + "\nThe command timed out.", checksums)
        except OSError as exc:
            raise GpgError("The command could not be started: " + str(exc)) from exc

    def list_keys(self, timestamp=None):
        listed = self.command("GPG Keys", ["--with-colons", "--with-fingerprint", "--list-keys"], timestamp=timestamp)
        if listed.returncode:
            return Outcome(False, "Could not list GPG keys.", [listed])
        secret = self.command("Secret Keys", ["--with-colons", "--with-fingerprint", "--with-keygrip", "--list-secret-keys"], timestamp=timestamp, agent=True)
        stages = [listed, secret]
        if secret.returncode:
            return Outcome(False, "Could not list GPG keys.", stages)
        try:
            keys = parse_keys(listed.stdout)
            secret_keys = {key.fingerprint: key for key in parse_keys(secret.stdout, secret=True)}
        except GpgError as exc:
            return Outcome(False, str(exc), stages)
        for key in keys:
            found = secret_keys.get(key.fingerprint)
            key.secret = found is not None
            key.secret_available = bool(found and found.secret_available)
            key.contains_private = bool(found and found.contains_private)
            key.keygrip = found.keygrip if found else ""
            key.needs_passphrase = key.secret_available and self._passphrase_required(key.keygrip)
            found_subs = {sub.get("fingerprint"): sub for sub in found.subkeys} if found else {}
            for sub in key.subkeys:
                match = found_subs.get(sub.get("fingerprint"))
                sub["secret"] = bool(match and match.get("secret"))
                sub["contains_private"] = bool(match and match.get("contains_private"))
                sub["keygrip"] = match.get("keygrip", "") if match else ""
                sub["needs_passphrase"] = bool(sub["secret"] and self._passphrase_required(sub["keygrip"]))
        return Outcome(True, stages=stages, keys=keys)

    def _passphrase_required(self, grip: str) -> bool:
        """Ask gpg-agent whether this secret keygrip is stored under a passphrase."""
        if not re.fullmatch(r"[0-9A-F]{40}", grip):
            return False
        env = dict(os.environ, GNUPGHOME=str(self._home()), LC_ALL="C", LANG="C", TZ="UTC")
        try:
            result = subprocess.run(["gpg-connect-agent", f"keyinfo {grip}", "/bye"],
                                    stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
        return any(passphrase_required(line) for line in result.stdout.decode("utf-8", "replace").splitlines())

    def export_key(self, fingerprint: str, *, secret: bool = False, subkey: bool = False):
        """ASCII-armored public key, private certificate, or one private subkey.

        A subkey export is ``gpg --armor --export-secret-subkeys <fingerprint>!``.
        The ``!`` keeps that subkey's secret and leaves out the certificate
        secret and every other subkey. The other exports are
        ``gpg --armor --export <fingerprint>`` and
        ``gpg --armor --export-secret-keys <fingerprint>``.
        """
        if not re.fullmatch(r"[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
            return Outcome(False, "The key fingerprint is not valid.")
        if subkey:
            secret = True
            name, option, target = "Export Private Subkey", "--export-secret-subkeys", fingerprint + "!"
        elif secret:
            name, option, target = "Export Private Key", "--export-secret-keys", fingerprint
        else:
            name, option, target = "Export Public Key", "--export", fingerprint
        result = self.command(name, ["--armor", option, "--", target], agent=secret)
        marker = "-----BEGIN PGP PRIVATE KEY BLOCK-----" if secret else "-----BEGIN PGP PUBLIC KEY BLOCK-----"
        ok = result.returncode == 0 and marker in result.stdout
        return Outcome(ok, "" if ok else "The key could not be exported.", [result])

    def mix_entropy(self, digest: bytes):
        if not self.supported:
            raise GpgError("GPG commands are not available in the web emulator. Use the BigSigner device.")
        mix_kernel_entropy(digest)

    def add_subkey(self, fingerprint: str, algo: str, usage: str, expire: str, timestamp: int):
        """Add one subkey with ``gpg --quick-add-key`` at the typed UTC time."""
        try:
            positional = quick_add_arguments(fingerprint, algo, usage, expire)
        except GpgError as exc:
            return Outcome(False, str(exc))
        added = self.command(
            "Add a Subkey",
            ["--quick-add-key", *positional],
            timestamp=timestamp,
            agent=True,
            passphrase="",
        )
        if added.returncode:
            return Outcome(False, "The subkey could not be added.", [added])
        listed = self.list_keys()
        stages = [added, *listed.stages]
        if not listed.ok:
            return Outcome(False, listed.message, stages)
        return Outcome(True, stages=stages, keys=listed.keys)

    def inspect_key(self, content, timestamp=None):
        result = self.command("Key Details", ["--with-colons", "--show-keys", "--with-fingerprint"], data=content, timestamp=timestamp)
        if result.returncode:
            return Outcome(False, "The GPG key could not be read.", [result])
        try:
            keys = parse_keys(result.stdout, secret=True)
            if not keys:
                raise GpgError("The GPG key information has no fingerprint.")
        except GpgError as exc:
            return Outcome(False, str(exc), [result])
        return Outcome(True, stages=[result], keys=keys)

    def import_key(self, content, timestamp=None):
        result = self.command("Import GPG Key", ["--status-fd", "1", "--import"], data=content, timestamp=timestamp, agent=True)
        names = status_names(result.stdout)
        summaries = [line.split()[2:] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] IMPORT_RES ")]
        processed = any(parts and parts[0].isdigit() and int(parts[0]) > 0 for parts in summaries)
        ok = result.returncode == 0 and processed and not names.intersection({"IMPORT_PROBLEM", "FAILURE", "NODATA"})
        return Outcome(ok, "" if ok else "The GPG key could not be imported.", [result])

    def delete_key(self, fingerprint: str):
        """Remove this primary key and its subkeys from both keyrings.

        ``gpg --delete-secret-keys`` runs first. A public key has no secret, so
        that command's "not found" status still continues to ``gpg --delete-keys``.
        """
        if not re.fullmatch(r"[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
            return Outcome(False, "The key fingerprint is not valid.")
        secret = self.command(
            "Delete Secret Keys",
            ["--yes", "--status-fd", "1", "--delete-secret-keys", "--", fingerprint],
            agent=True,
        )
        public = self.command(
            "Delete Keys",
            ["--yes", "--status-fd", "1", "--delete-keys", "--", fingerprint],
        )
        stages = [secret, public]
        secret_gone = secret.returncode == 0 or "DELETE_PROBLEM 1" in secret.stdout
        ok = secret_gone and public.returncode == 0
        return Outcome(ok, "" if ok else "The GPG key could not be deleted.", stages)

    @staticmethod
    def _read_manifest(path):
        with path.open("rb") as handle:
            content = handle.read(CHECKSUM_LIMIT + 1)
        if len(content) > CHECKSUM_LIMIT:
            raise GpgError("The signed checksum content is larger than 4 MiB.")
        return content

    def encrypt_file(self, fingerprints: list[str], relative: str, output_name: str, storage: str):
        """Armored file encryption for the exact encryption-subkey fingerprints."""
        path = sdcard.native_path(relative, storage=storage)
        if path is None or not path.is_file():
            raise GpgError("Encrypting a file requires the device filesystem.")
        if not fingerprints:
            raise GpgError("Select an encryption key.")
        if not output_name or output_name in (".", "..") or "/" in output_name or "\\" in output_name or "\x00" in output_name:
            raise GpgError("The file name is not valid.")
        args = ["--trust-model", "always", "--yes", "--armor", "--encrypt"]
        for fingerprint in fingerprints:
            if not re.fullmatch(r"[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
                raise GpgError("The key fingerprint is not valid.")
            args += ["--recipient", fingerprint + "!"]
        args += ["--output", output_name, "--", path.name]
        encrypted = self.command("Encrypt File", args, cwd=path.parent)
        return Outcome(encrypted.returncode == 0, "" if encrypted.returncode == 0 else "The file could not be encrypted.", [encrypted])

    def sign_file(self, fingerprint: str, relative: str, storage: str, timestamp: int):
        """Detached armored signature ``<name>.asc`` for one file, using that exact key."""
        path = sdcard.native_path(relative, storage=storage)
        if path is None or not path.is_file():
            raise GpgError("Signing a file requires the device filesystem.")
        signed = self._detach_sign(fingerprint, path, path.with_name(path.name + ".asc"), timestamp)
        return Outcome(signed.returncode == 0, "" if signed.returncode == 0 else "The file could not be signed.", [signed])

    def sign_folder(self, fingerprint: str, relative: str, storage: str, timestamp: int):
        """Write SHA256SUMS for the files in one folder, then sign that file."""
        directory = sdcard.native_path(relative, storage=storage)
        if directory is None or not directory.is_dir():
            raise GpgError("Signing a folder requires the device filesystem.")
        manifest = sha256_manifest(directory)
        (directory / CHECKSUM_NAME).write_bytes(manifest)
        signed = self._detach_sign(fingerprint, directory / CHECKSUM_NAME, directory / CHECKSUM_SIGNATURE, timestamp)
        return Outcome(signed.returncode == 0, "" if signed.returncode == 0 else "The folder could not be signed.", [signed])

    def _detach_sign(self, fingerprint: str, source: Path, output: Path, timestamp: int):
        if not re.fullmatch(r"[0-9A-F]{32}|[0-9A-F]{40}|[0-9A-F]{64}", fingerprint):
            raise GpgError("The key fingerprint is not valid.")
        args = ["--yes", "--armor", "--detach-sign", "--digest-algo", "SHA256",
                "--local-user", fingerprint + "!", "--output", output.name, "--", source.name]
        return self.command("Sign File", args, cwd=source.parent, timestamp=timestamp, agent=True, passphrase="")

    def verify(self, relative, storage, timestamp, checksums=False):
        self._home()
        path = sdcard.native_path(relative, storage=storage)
        if path is None:
            raise GpgError("GPG file verification requires the device filesystem.")
        if not path.name.lower().endswith(".asc") or len(path.name) <= 4 or not path.is_file():
            raise GpgError("Choose an .asc signature file.")
        directory = path.parent
        companion = path.with_name(path.name[:-4])
        try:
            companion.resolve().relative_to(directory.resolve())
        except ValueError as exc:
            raise GpgError("The matching file points outside the selected folder.") from exc
        sig_name = "./" + path.name
        stages = []
        manifest = None
        # This check treats each loaded key as trusted. It does not write ownertrust.
        verify_args = ["--trust-model", "always", "--status-fd", "1", "--verify"]
        if companion.is_file():
            if checksums:
                # Verify and check the same immutable bytes, without staging a file.
                manifest = self._read_manifest(companion)
                args, data = [*verify_args, "--", sig_name, "-"], manifest
            else:
                args, data = [*verify_args, "--", sig_name, "./" + companion.name], None
        elif checksums:
            signed = self._read_manifest(path)
            args, data = verify_args, signed
        else:
            raise GpgError(f'The matching file "{companion.name}" is missing from this folder.')
        verified = self.command("Signature Verification", args, data=data, cwd=directory, timestamp=timestamp)
        stages.append(verified)
        if not signature_ok(verified):
            return Outcome(False, "Signature verification failed.", stages)
        if not checksums:
            return Outcome(True, stages=stages)
        if manifest is None:
            extracted = self.command("Extract Signed Checksums", ["--max-output", str(CHECKSUM_LIMIT), "--decrypt"], data=signed, cwd=directory, timestamp=timestamp)
            stages.append(extracted)
            if extracted.returncode:
                return Outcome(False, "The signed checksums could not be extracted.", stages)
            manifest = extracted.raw_stdout if extracted.raw_stdout is not None else extracted.stdout.encode("utf-8")
        try:
            check_manifest_paths(manifest, directory)
        except GpgError as exc:
            return Outcome(False, str(exc), stages)
        checked = self.command("SHA256 Check", ["--check"], data=manifest, cwd=directory, checksums=True)
        stages.append(checked)
        present = sorted((child.name for child in directory.iterdir() if child.is_file()), key=lambda name: (name.casefold(), name))
        checksum_name = companion.name if companion.is_file() else ""
        unchecked = files_left_unchecked(present, manifest_filenames(manifest), checksum_name, path.name)
        failed = checked.returncode != 0
        return Outcome(not failed, "The SHA256 check failed." if failed else "", stages, unverified=unchecked)

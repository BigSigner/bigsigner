"""GnuPG operations with a private RAM keyring and native, streaming file checks."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import subprocess
import sys

from . import sdcard

KEY_LIMIT = 1_048_576
CHECKSUM_LIMIT = 4_194_304


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
    capabilities: str = ""


@dataclass
class Outcome:
    ok: bool
    message: str = ""
    stages: list[CommandResult] = field(default_factory=list)
    keys: list[PublicKey] = field(default_factory=list)


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


def check_manifest_paths(content: bytes, directory: Path) -> None:
    """Confine GNU/BSD manifest paths before allowing the checker to open them."""
    root = directory.resolve()
    for line in content.split(b"\n"):
        line = line.rstrip(b"\r")
        if not line.strip() or line.startswith(b"#"):
            continue
        escaped = line.startswith(b"\\")
        match = re.fullmatch(rb"[0-9a-fA-F]{64}[ \t][ *](.+)", line[1:] if escaped else line)
        if not match:
            match = re.fullmatch(rb"SHA256 \((.+)\) = [0-9a-fA-F]{64}", line)
        if not match:
            # GNU also accepts the legacy one-whitespace form.
            match = re.fullmatch(rb"[0-9a-fA-F]{64}[ \t](.+)", line[1:] if escaped else line)
        if not match:
            raise GpgError("The checksum file contains an unsupported checksum line.")
        name = match[1]
        if escaped:
            name = re.sub(rb"\\([\\nr])", lambda item: {b"\\": b"\\", b"n": b"\n", b"r": b"\r"}[item[1]], name)
        name = os.fsdecode(name)
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

    def command(self, name, args, *, data=None, cwd=None, timestamp=None, checksums=False, agent=False):
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
        secret = self.command("Secret Keys", ["--with-colons", "--with-fingerprint", "--list-secret-keys"], timestamp=timestamp, agent=True)
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
            found_subs = {sub.get("fingerprint"): sub for sub in found.subkeys} if found else {}
            for sub in key.subkeys:
                match = found_subs.get(sub.get("fingerprint"))
                sub["secret"] = bool(match and match.get("secret"))
                sub["contains_private"] = bool(match and match.get("contains_private"))
        return Outcome(True, stages=stages, keys=keys)

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

    @staticmethod
    def _read_manifest(path):
        with path.open("rb") as handle:
            content = handle.read(CHECKSUM_LIMIT + 1)
        if len(content) > CHECKSUM_LIMIT:
            raise GpgError("The signed checksum content is larger than 4 MiB.")
        return content

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
        if companion.is_file():
            if checksums:
                # Verify and check the same immutable bytes, without staging a file.
                manifest = self._read_manifest(companion)
                args, data = ["--status-fd", "1", "--verify", "--", sig_name, "-"], manifest
            else:
                args, data = ["--status-fd", "1", "--verify", "--", sig_name, "./" + companion.name], None
        elif checksums:
            signed = self._read_manifest(path)
            args, data = ["--status-fd", "1", "--verify"], signed
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
        return Outcome(checked.returncode == 0, "" if checked.returncode == 0 else "The SHA256 check failed.", stages)

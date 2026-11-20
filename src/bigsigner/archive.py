"""Compress and extract files with the gzip and tar commands.

A plain gzip member is one byte stream. Its optional original name can be an
absolute path, so that name is never used as a destination. A gzip of a tar
archive can also name absolute paths, ``..`` components, and links. Those
members are refused before anything is written.
"""

import errno
import gzip
import io
import os
import subprocess
import tarfile
import threading
from pathlib import Path

from . import sdcard
from .sdcard import SdError


GZIP_MAGIC = b"\x1f\x8b"
_CHUNK = 64 * 1024
OUTSIDE = "This archive contains a path outside the selected folder."


def gzip_file(source: str, destination: str, *, storage: str = "sd", destination_storage: str | None = None, progress=None) -> None:
    """Write a gzip of ``source`` to ``destination`` without replacing it."""
    destination_storage = destination_storage or storage
    size = sdcard.file_size(source, storage=storage)
    if sdcard.path_exists(destination, storage=destination_storage):
        raise SdError("A file or directory already has that name.")
    _require_parent(destination, destination_storage)
    source_native = sdcard.native_path(source, storage=storage)
    destination_native = sdcard.native_path(destination, storage=destination_storage)
    if source_native is not None and destination_native is not None:
        _gzip_native(source_native, destination_native, progress, size)
        return
    data = b"".join(sdcard.read_chunks(source, storage=storage))
    if progress is not None:
        progress(len(data), max(size, 1))
    sdcard.create_file(destination, gzip.compress(data), storage=destination_storage)


def extract_gzip(source: str, directory: str, *, storage: str = "sd", destination_storage: str | None = None, progress=None) -> None:
    """Extract a gzip into ``directory``.

    A tar archive is extracted with its folders. Any other gzip is one file,
    named from the selected file with one trailing ``.gz`` removed.
    """
    destination_storage = destination_storage or storage
    if not sdcard.path_exists(directory, storage=destination_storage):
        raise SdError("That folder is not available.")
    if sdcard.file_exists(directory, storage=destination_storage):
        raise SdError("That folder is not available.")
    prefix = sdcard.read_prefix(source, storage=storage, size=2)
    if not prefix.startswith(GZIP_MAGIC):
        raise SdError("This file is not a gzip file.")
    source_native = sdcard.native_path(source, storage=storage)
    destination_native = sdcard.native_path(directory, storage=destination_storage)
    if source_native is not None and destination_native is not None:
        _gzip_test(source_native)
        _extract_native(source_native, destination_native, directory, destination_storage, Path(source).name, progress)
        return
    data = b"".join(sdcard.read_chunks(source, storage=storage))
    payload = _checked_payload(data)
    if _tar_payload(payload[:512]):
        _extract_tar_bytes(payload, directory, destination_storage, progress)
        return
    _write_single(directory, destination_storage, Path(source).name, payload, progress)


def _gzip_test(path: Path) -> None:
    """Refuse a gzip whose CRC or size trailer does not match. Writes nothing."""
    result = _run(["gzip", "-t", str(path)])
    if result.returncode != 0:
        raise SdError("The gzip checksum is not valid.")


def _checked_payload(data: bytes) -> bytes:
    """The uncompressed bytes, after the same CRC and size check as gzip -t."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
            return handle.read()
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise SdError("The gzip checksum is not valid.") from exc


def _require_parent(destination: str, storage: str) -> None:
    parent = sdcard.parent_path(destination)
    if parent and not sdcard.path_exists(parent, storage=storage):
        raise SdError("That folder is not available.")


def _write_single(directory: str, storage: str, filename: str, payload: bytes, progress) -> None:
    name = _single_name(filename)
    target = sdcard.child_path(directory, name)
    if sdcard.path_exists(target, storage=storage):
        raise SdError("A file or directory already has that name.")
    if progress is not None:
        progress(0, max(len(payload), 1))
    sdcard.create_file(target, payload, storage=storage)
    if progress is not None:
        progress(len(payload), max(len(payload), 1))


def _single_name(filename: str) -> str:
    name = Path(filename).name
    if name.lower().endswith(".gz"):
        name = name[:-3]
    if not name or name in (".", "..") or any(char in name for char in "/\\\x00"):
        raise SdError("The file name is not valid.")
    return name


def _tar_payload(header: bytes) -> bool:
    return len(header) >= 262 and header[257:262] == b"ustar"


def _safe_relative(name: str) -> str | None:
    """A path that stays inside the destination, or None when it would not."""
    if not isinstance(name, str) or "\x00" in name or "\\" in name:
        return None
    if name.startswith("/") or (len(name) >= 2 and name[1] == ":" and name[0].isalpha()):
        return None
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    return "/".join(parts)


def _extract_tar_bytes(payload: bytes, directory: str, storage: str, progress) -> None:
    try:
        handle = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as exc:
        raise SdError("The gzip file could not be read.") from exc
    with handle:
        members = []
        for member in handle.getmembers():
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise SdError(OUTSIDE)
            relative = _safe_relative(member.name)
            if relative is None or (member.isfile() and not relative):
                raise SdError(OUTSIDE)
            members.append((member, relative))
        if not any(relative for _member, relative in members):
            raise SdError("This gzip file has no files.")
        _refuse_existing(directory, storage, [(relative, "d" if member.isdir() else "-") for member, relative in members])
        total = max(1, sum(1 for member, _relative in members if member.isfile()))
        written = 0
        for member, relative in members:
            if not relative:
                continue
            if member.isdir():
                _ensure_dir(sdcard.child_path(directory, relative), storage)
                continue
            _ensure_dir(sdcard.parent_path(sdcard.child_path(directory, relative)), storage)
            extracted = handle.extractfile(member)
            if extracted is None:
                raise SdError("The gzip file could not be read.")
            sdcard.create_file(sdcard.child_path(directory, relative), extracted.read(), storage=storage)
            written += 1
            if progress is not None:
                progress(written, total)


def _refuse_existing(directory: str, storage: str, members: list[tuple[str, str]]) -> None:
    for relative, kind in members:
        if not relative:
            continue
        path = sdcard.child_path(directory, relative)
        if kind == "d":
            if sdcard.file_exists(path, storage=storage):
                raise SdError("A file or directory already has that name.")
            continue
        if sdcard.path_exists(path, storage=storage):
            raise SdError("A file or directory already has that name.")
        parent = sdcard.parent_path(path)
        while parent and parent != directory:
            if sdcard.file_exists(parent, storage=storage):
                raise SdError("A file or directory already has that name.")
            parent = sdcard.parent_path(parent)


def _ensure_dir(relative: str, storage: str) -> None:
    if not relative or sdcard.path_exists(relative, storage=storage):
        if relative and sdcard.file_exists(relative, storage=storage):
            raise SdError("A file or directory already has that name.")
        return
    _ensure_dir(sdcard.parent_path(relative), storage)
    sdcard.create_directory(relative, storage=storage)


def _gzip_native(source: Path, destination: Path, progress, size: int) -> None:
    try:
        proc = subprocess.Popen(["gzip", "-c"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise SdError("gzip is not available.") from exc
    errors: list[BaseException] = []

    def feed():
        try:
            read = 0
            with open(source, "rb") as handle:
                while chunk := handle.read(_CHUNK):
                    proc.stdin.write(chunk)
                    read += len(chunk)
                    if progress is not None:
                        progress(read, max(size, 1))
            proc.stdin.close()
        except BaseException as exc:
            errors.append(exc)
            try:
                proc.stdin.close()
            except OSError:
                pass

    thread = threading.Thread(target=feed)
    created = False
    try:
        thread.start()
        with open(destination, "xb") as dst:
            created = True
            while chunk := proc.stdout.read(_CHUNK):
                dst.write(chunk)
            dst.flush()
            os.fsync(dst.fileno())
        thread.join()
        code = proc.wait()
        if errors:
            raise errors[0]
        if code != 0:
            raise SdError("The file could not be compressed.")
    except OSError as exc:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        thread.join()
        if created:
            destination.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise SdError("There is not enough free space.") from exc
        raise SdError("The file could not be compressed.") from exc
    except Exception:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        thread.join()
        if created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _extract_native(source: Path, destination: Path, directory: str, storage: str, filename: str, progress) -> None:
    header = _gzip_prefix(source, 512)
    if _tar_payload(header):
        members = _cli_members(source)
        _refuse_existing(directory, storage, members)
        for relative, _kind in members:
            if relative:
                _confine(destination, relative)
        if progress is not None:
            progress(0, 1)
        result = _run(["tar", "-x", "-z", "-f", str(source), "-C", str(destination)])
        if result.returncode != 0:
            raise SdError("The gzip file could not be read.")
        if progress is not None:
            progress(1, 1)
        return
    name = _single_name(filename)
    target = destination / name
    _confine(destination, name)
    if target.exists() or target.is_symlink():
        raise SdError("A file or directory already has that name.")
    _gunzip_native(source, target, progress)


def _gzip_prefix(path: Path, size: int) -> bytes:
    try:
        proc = subprocess.Popen(["gzip", "-dc", str(path)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise SdError("gzip is not available.") from exc
    try:
        data = proc.stdout.read(size)
    except OSError as exc:
        proc.kill()
        proc.wait()
        raise SdError("The gzip file could not be read.") from exc
    proc.stdout.close()
    proc.kill()
    proc.wait()
    return data


def _cli_members(path: Path) -> list[tuple[str, str]]:
    names = _run(["tar", "-t", "-z", "-f", str(path)])
    verbose = _run(["tar", "-t", "-v", "-z", "-f", str(path)])
    if names.returncode != 0 or verbose.returncode != 0:
        raise SdError("The gzip file could not be read.")
    listed = names.stdout.decode("utf-8", "surrogateescape").splitlines()
    kinds = verbose.stdout.decode("utf-8", "surrogateescape").splitlines()
    if len(listed) != len(kinds):
        raise SdError("The gzip file could not be read.")
    if not listed:
        raise SdError("This gzip file has no files.")
    members = []
    for name, line in zip(listed, kinds):
        kind = line[:1]
        if kind not in "-d":
            raise SdError(OUTSIDE)
        relative = _safe_relative(name)
        if relative is None or (kind == "-" and not relative):
            raise SdError(OUTSIDE)
        members.append((relative, kind))
    if not any(relative for relative, _kind in members):
        raise SdError("This gzip file has no files.")
    return members


def _confine(root: Path, relative: str) -> None:
    current = root.resolve()
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        if current.is_symlink():
            raise SdError(OUTSIDE)
        last = index == len(parts) - 1
        if current.exists() and not last and not current.is_dir():
            raise SdError("A file or directory already has that name.")
    try:
        current.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise SdError(OUTSIDE) from exc


def _gunzip_native(source: Path, destination: Path, progress) -> None:
    try:
        proc = subprocess.Popen(["gzip", "-dc", str(source)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        raise SdError("gzip is not available.") from exc
    created = False
    written = 0
    try:
        with open(destination, "xb") as dst:
            created = True
            while chunk := proc.stdout.read(_CHUNK):
                dst.write(chunk)
                written += len(chunk)
                if progress is not None:
                    progress(written, max(written, 1))
            dst.flush()
            os.fsync(dst.fileno())
        if proc.wait() != 0:
            raise SdError("The gzip file could not be read.")
    except OSError as exc:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if created:
            destination.unlink(missing_ok=True)
        if exc.errno == errno.ENOSPC:
            raise SdError("There is not enough free space.") from exc
        raise SdError("The gzip file could not be read.") from exc
    except Exception:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def _run(args: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(args, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise SdError(f"{args[0]} is not available.") from exc

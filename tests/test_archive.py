"""Gzip and tar extraction stay inside the selected folder."""

import base64
import gzip
import io
import tarfile

import pytest

from bigsigner import archive, sdcard


def _gzip_with_name(name, payload):
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, filename=name, mode="wb", mtime=0) as handle:
        handle.write(payload)
    return buffer.getvalue()


def _tar_gz(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload in entries:
            if payload is None:
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
                continue
            if isinstance(payload, tuple):
                info = tarfile.TarInfo(name)
                info.type = tarfile.SYMTYPE
                info.linkname = payload[1]
                archive.addfile(info)
                continue
            data = payload if isinstance(payload, bytes) else payload.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_plain_gzip_ignores_an_absolute_header_name():
    encoded = base64.b64encode(_gzip_with_name("/etc/passwd", b"secret")).decode()
    sdcard.mount_memory({"files": {"notes.gz": {"base64": encoded}}, "dirs": ["safe"]})
    archive.extract_gzip("notes.gz", "safe")
    assert sdcard.read_bytes("safe/notes") == b"secret"
    assert not sdcard.path_exists("etc/passwd")


def test_tar_gzip_extracts_folders_and_refuses_escapes():
    sdcard.mount_memory({"files": {}, "dirs": ["out"]})
    sdcard.create_file("tree.tar.gz", _tar_gz([("nested", None), ("nested/inside.txt", b"yes")]))
    archive.extract_gzip("tree.tar.gz", "out")
    assert sdcard.read_bytes("out/nested/inside.txt") == b"yes"
    for name, payload in (
        ("/etc/passwd", b"no"),
        ("../escape.txt", b"no"),
        ("link", ("symlink", "/tmp/outside")),
    ):
        sdcard.write_bytes("bad.tar.gz", _tar_gz([("ok.txt", b"kept"), (name, payload)]))
        with pytest.raises(sdcard.SdError, match="outside the selected folder"):
            archive.extract_gzip("bad.tar.gz", "out")
        assert not sdcard.file_exists("out/ok.txt")
        assert sdcard.read_bytes("out/nested/inside.txt") == b"yes"


def _break_checksum(data: bytes) -> bytes:
    broken = bytearray(data)
    broken[-8] ^= 0xFF
    return bytes(broken)


def test_gunzip_refuses_a_bad_checksum_before_writing():
    sdcard.mount_memory({"files": {}, "dirs": ["out"]})
    sdcard.create_file("notes.gz", _break_checksum(gzip.compress(b"secret")))
    with pytest.raises(sdcard.SdError, match="checksum"):
        archive.extract_gzip("notes.gz", "out")
    assert sdcard.list_folder("out") == []
    sdcard.create_file("tree.tar.gz", _break_checksum(_tar_gz([("nested/inside.txt", b"yes")])))
    with pytest.raises(sdcard.SdError, match="checksum"):
        archive.extract_gzip("tree.tar.gz", "out")
    assert sdcard.list_folder("out") == []


def test_disk_gzip_round_trip_uses_the_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("BIGSIGNER_SDCARD_PATH", str(tmp_path))
    sdcard.unmount_memory()
    sdcard.create_file("notes.txt", b"hello")
    sdcard.create_directory("out")
    archive.gzip_file("notes.txt", "out/notes.txt.gz")
    assert gzip.decompress(sdcard.read_bytes("out/notes.txt.gz")) == b"hello"
    archive.extract_gzip("out/notes.txt.gz", "out")
    assert sdcard.read_bytes("out/notes.txt") == b"hello"
    sdcard.create_file("tree.tar.gz", _tar_gz([("sub/file.txt", b"tree")]))
    archive.extract_gzip("tree.tar.gz", "out")
    assert sdcard.read_bytes("out/sub/file.txt") == b"tree"
    sdcard.create_file("bad.tar.gz", _tar_gz([("/etc/passwd", b"no")]))
    with pytest.raises(sdcard.SdError, match="outside the selected folder"):
        archive.extract_gzip("bad.tar.gz", "out")
    assert not (tmp_path / "etc" / "passwd").exists()
    assert list(tmp_path.rglob("passwd")) == []
    sdcard.create_file("broken.tar.gz", _break_checksum(_tar_gz([("sub/leaked.txt", b"no")])))
    with pytest.raises(sdcard.SdError, match="checksum"):
        archive.extract_gzip("broken.tar.gz", "out")
    assert not (tmp_path / "out" / "sub" / "leaked.txt").exists()
    assert list(tmp_path.rglob("leaked.txt")) == []

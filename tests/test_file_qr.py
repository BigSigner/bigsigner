"""The gzip and base64 QR parts reassemble with the command shown on screen."""

import subprocess
from pathlib import Path

from bigsigner.file_qr import PART_CHARS, gzip_base64, plain_base64, recovery_command, shell_quote, shell_words, spaced_parts


def test_parts_are_400_characters_with_a_space_prefix_and_an_index_suffix():
    encoded = "A" * (PART_CHARS + 1)
    parts = spaced_parts(encoded)
    assert parts == [" " * 3 + "A" * PART_CHARS, " " * 3 + "A" + " "]
    assert "".join(part.strip(" ") for part in parts) == encoded


def test_recovery_command_quotes_the_original_file_name():
    command = (
        "filename='notes.txt'\n"
        "cat file-part-* | tr -d ' ' | base64 -d > \"${filename}.gz\"\n"
        "gzip -t \"${filename}.gz\" && gunzip \"${filename}.gz\""
    )
    assert recovery_command("notes.txt") == command
    name = "my file's \"data\" $*.bin"
    quoted = "'my file'\\''s \"data\" $*.bin'"
    assert shell_quote(name) == quoted
    assignment = "filename=" + quoted
    assert recovery_command(name).split("\n")[0] == assignment
    assert shell_words(assignment) == [assignment]


def test_shell_command_restores_text_and_a_quoted_binary_name(tmp_path):
    text = b"line\n" * 200
    value = 1
    binary = bytearray()
    for _ in range(1500):
        value = (value * 1103515245 + 12345) & 0x7FFFFFFF
        binary.append(value & 0xFF)
    _restore(tmp_path / "text", text, "notes.txt")
    _restore(tmp_path / "binary", bytes(binary), "my file's \"data\" $*.bin")
    assert plain_base64(b"\x00\xff") == "AP8="


def _restore(folder: Path, data: bytes, name: str):
    folder.mkdir()
    parts = spaced_parts(gzip_base64(data))
    assert len(parts) >= 1
    for index, part in enumerate(parts):
        (folder / f"file-part-{index:02d}").write_text(part, encoding="ascii")
    completed = subprocess.run(
        ["bash", "-c", recovery_command(name)],
        cwd=folder,
        check=False,
        capture_output=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert (folder / name).read_bytes() == data
    assert not (folder / f"{name}.gz").exists()


def test_a_failed_gzip_check_does_not_write_the_file(tmp_path):
    (tmp_path / "file-part-00").write_text("bm90LWEtcGtlei1maWxl", encoding="ascii")
    completed = subprocess.run(
        ["bash", "-c", recovery_command("notes.txt")],
        cwd=tmp_path,
        check=False,
        capture_output=True,
    )
    assert completed.returncode != 0
    assert (tmp_path / "notes.txt.gz").is_file()
    assert not (tmp_path / "notes.txt").exists()

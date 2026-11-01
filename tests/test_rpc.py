import base64
import os
import stat

import pytest

from bigsigner.rpc import apply_line, command_of, feed_lines, format_line, main, open_rpc_pipe, split_line, write_pipe
from bigsigner.session import SessionError
from bigsigner.ui.app import App

ABANDON = (
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about"
)


def test_a_seed_line_keeps_an_optional_passphrase():
    line, fingerprint = format_line(ABANDON.replace(" ", ", "), "secret")
    command, rest = command_of(line)
    words, passphrase = split_line(rest)
    assert command == "addseed"
    assert words == ABANDON
    assert passphrase == "secret"
    assert fingerprint != format_line(ABANDON, None)[1]
    assert len(fingerprint) == 8


def test_the_abandon_seed_has_the_known_fingerprint():
    _line, fingerprint = format_line(ABANDON, None)
    assert fingerprint == "73c5da0a"


def test_a_bad_checksum_is_refused_before_the_pipe():
    with pytest.raises(SessionError, match="checksum"):
        format_line(" ".join(["abandon"] * 12), None)


def test_an_overlong_line_is_dropped():
    lines, overflow = feed_lines(bytearray(), b"x" * 5000)
    assert lines == []
    assert overflow is True
    lines, overflow = feed_lines(bytearray(b"abandon "), b"about\n")
    assert lines == ["abandon about"]
    assert overflow is False


def test_the_command_writes_one_line_and_prints_only_the_fingerprint(tmp_path, capsys):
    path = tmp_path / "seed"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert main(["--pipe", str(path), "addseed", *ABANDON.split()]) == 0
        data = os.read(reader, 4096)
    finally:
        os.close(reader)
    captured = capsys.readouterr()
    assert captured.err.strip() == "73c5da0a"
    assert "abandon" not in captured.err
    assert captured.out == ""
    assert data.decode() == f"addseed {ABANDON}\n"


def test_format_prints_the_line_without_repeating_it_on_stderr(capsys):
    assert main(["--format", "addseed", *ABANDON.split()]) == 0
    captured = capsys.readouterr()
    assert captured.out == f"addseed {ABANDON}\n"
    assert captured.err.strip() == "73c5da0a"


def test_a_base64_line_is_written_to_the_pipe(tmp_path, capsys):
    coded = base64.b64encode(f"addseed {ABANDON}".encode()).decode()
    path = tmp_path / "seed"
    os.mkfifo(path)
    reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert main(["--pipe", str(path), "--b64", coded]) == 0
        data = os.read(reader, 4096)
    finally:
        os.close(reader)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "abandon" not in captured.err
    assert data.decode() == f"addseed {ABANDON}\n"


def test_a_line_without_the_command_does_not_load_the_seed():
    app = App()
    app.screen = "keys"
    report = apply_line(app, ABANDON)
    assert report == "command refused: abandon"
    assert app.session.fingerprints == {}
    loaded = apply_line(app, f"addseed {ABANDON}")
    assert loaded == "seed 73c5da0a"
    assert app.screen == "key"


def test_another_command_is_sent_without_a_fingerprint(capsys):
    assert main(["--format", "addwallet", "native"]) == 0
    captured = capsys.readouterr()
    assert captured.out == "addwallet native\n"
    assert captured.err == ""


def test_a_passphrase_after_addseed_is_not_a_word(capsys):
    assert main(["--format", "addseed", "--passphrase", "hello", *ABANDON.split()]) == 0
    captured = capsys.readouterr()
    command, rest = command_of(captured.out.strip())
    words, passphrase = split_line(rest)
    assert command == "addseed"
    assert words == ABANDON
    assert passphrase == "hello"
    assert "hello" not in captured.err


def test_a_passphrase_belongs_on_addseed():
    assert main(["--format", "addwallet", "--passphrase", "secret"]) == 1


def test_the_panel_opens_its_command_pipe(tmp_path, monkeypatch):
    path = tmp_path / "rpc"
    monkeypatch.setenv("BIGSIGNER_RPC", str(path))
    opened = open_rpc_pipe()
    assert opened is not None
    handle, opened_path = opened
    try:
        assert opened_path == str(path)
        assert stat.S_ISFIFO(os.stat(path).st_mode)
    finally:
        os.close(handle)


def test_the_command_pipe_can_be_turned_off(monkeypatch):
    monkeypatch.setenv("BIGSIGNER_RPC", "off")
    assert open_rpc_pipe() is None


def test_a_seed_that_is_already_loaded_stays():
    app = App()
    app.screen = "keys"
    assert apply_line(app, f"addseed {ABANDON}") == "seed 73c5da0a"
    assert apply_line(app, f"addseed {ABANDON}") == "seed already loaded"
    assert len(app.session.fingerprints) == 1


def test_a_missing_reader_is_an_error(tmp_path):
    path = tmp_path / "seed"
    os.mkfifo(path)
    with pytest.raises(SystemExit, match="Nothing is reading"):
        write_pipe(str(path), ABANDON)


def test_an_injected_seed_waits_on_the_boot_screen():
    app = App()
    assert app.screen == "boot"
    report = app.inject_mnemonic(ABANDON)
    assert app.screen == "boot"
    assert report == "seed 73c5da0a"
    assert "abandon" not in report
    assert app.selected_fp.hex() == "73c5da0a"


def test_an_injected_seed_opens_the_key_once_the_panel_is_up():
    app = App()
    app.screen = "keys"
    app.menu = True
    report = app.inject_mnemonic(ABANDON + "\tsecret")
    assert app.screen == "key"
    assert app.menu is False
    assert report.startswith("seed ")
    assert "secret" not in report
    assert "The seed was added successfully." in app.notice


def test_a_rejected_seed_stays_on_the_current_screen():
    app = App()
    app.screen = "keys"
    report = app.inject_mnemonic("abandon abandon")
    assert app.screen == "keys"
    assert report.startswith("seed refused:")
    assert "abandon" not in report
    assert "12, 18, or 24" in app.notice

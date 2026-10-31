"""Send one command to a running panel.

The panel reads the pipe named by ``BIGSIGNER_RPC``. Each line starts with a
command word. ``injectseed`` is one command: it is followed by the mnemonic,
and a tab and then a passphrase is optional. The pipe is in RAM. Nothing is
written to the SD card.

On the device, after the panel has been started with that variable:

    python -m bigsigner.rpc injectseed word word ... word
    python -m bigsigner.rpc injectseed --passphrase "secret" word word ... word

From the computer, ``docs/scripts/rpc.sh`` in bigsigner-os starts that panel
over SSH when it is not already listening, then writes the same line.
Do not use either command on a device that holds real funds.
"""

import argparse
import base64
import binascii
import errno
import os
import stat
import sys

from .session import Session, SessionError

# One line, including a passphrase. Longer input is dropped unread.
MAX_LINE = 4096
DEFAULT_PIPE = "/tmp/bigsigner-rpc"


def command_of(line: str) -> tuple[str, str]:
    """The first word, and the rest of the line with its passphrase tab intact."""
    text = line.strip()
    command, separator, rest = text.partition(" ")
    if separator:
        rest = rest.lstrip(" ")
    return command, rest


def split_line(line: str) -> tuple[str, str | None]:
    """The mnemonic and the optional passphrase. The command word is already removed."""
    text = line.rstrip("\r\n")
    passphrase = None
    if "\t" in text:
        text, passphrase = text.split("\t", 1)
        if passphrase == "":
            passphrase = None
    return text.strip(), passphrase


def command_refusal(command: str) -> str:
    """A log line for a command this panel does not handle. The rest of the line stays out."""
    if command.isascii() and command.isidentifier() and len(command) <= 32:
        return f"command refused: {command}"
    return "command refused"


def apply_line(app, line: str) -> str:
    """Run one pipe line. The log text has no mnemonic and no passphrase."""
    command, rest = command_of(line)
    if command == "injectseed":
        return app.inject_mnemonic(rest)
    return command_refusal(command)


def feed_lines(pending: bytearray, chunk: bytes) -> tuple[list[str], bool]:
    """Complete lines from one read, and whether an overlong line was dropped."""
    pending.extend(chunk)
    lines = []
    overflow = False
    while True:
        newline = pending.find(b"\n")
        if newline == -1:
            if len(pending) > MAX_LINE:
                pending.clear()
                overflow = True
            break
        if newline > MAX_LINE:
            del pending[: newline + 1]
            overflow = True
            continue
        raw = bytes(pending[:newline])
        del pending[: newline + 1]
        text = raw.decode("utf-8", "replace").strip("\r")
        if text.strip():
            lines.append(text)
    return lines, overflow


def format_line(words: str, passphrase: str | None = None) -> tuple[str, str]:
    """Validate a seed and return the injectseed line and the fingerprint hex.

    Commas are spaces. The checksum is checked. The passphrase is the BIP39
    passphrase, one line, with no tab characters.
    """
    text = words[:-1] if words.endswith("\n") else words
    text = text[:-1] if text.endswith("\r") else text
    if "\n" in text or "\r" in text:
        raise SessionError("The seed must be one line.")
    if passphrase is not None and ("\n" in passphrase or "\r" in passphrase or "\t" in passphrase):
        raise SessionError("The passphrase must be one line.")
    session = Session()
    added = session.add_mnemonic(text, passphrase)
    key = session.fingerprints[added["fingerprint"]].keys[0]
    mnemonic = " ".join(key.mnemonic)
    stored = key.passphrase
    body = mnemonic if stored is None else f"{mnemonic}\t{stored}"
    line = f"injectseed {body}"
    if len(line.encode("utf-8")) > MAX_LINE:
        raise SessionError("The seed line is too long.")
    return line, added["fingerprint"].hex()


def format_command(command: str, rest: str) -> tuple[str, str | None]:
    """One pipe line, and the fingerprint when the command is injectseed."""
    if command == "injectseed":
        words, passphrase = split_line(rest)
        return format_line(words, passphrase)
    if not (command.isascii() and command.isidentifier() and len(command) <= 32):
        raise SessionError(command_refusal(command))
    if "\n" in rest or "\r" in rest:
        raise SessionError("The command must be one line.")
    line = command if rest == "" else f"{command} {rest}"
    if len(line.encode("utf-8")) > MAX_LINE:
        raise SessionError("The command line is too long.")
    return line, None


def open_rpc_pipe():
    """The command pipe and its path. None when BIGSIGNER_RPC is off.

    An empty value uses /tmp/bigsigner-rpc and creates that fifo. The panel
    opens it at startup, so a later command does not replace the process.
    """
    raw = os.environ.get("BIGSIGNER_RPC", "").strip()
    if raw.lower() in {"0", "off", "none"}:
        return None
    path = raw or DEFAULT_PIPE
    if os.path.exists(path):
        if not stat.S_ISFIFO(os.stat(path).st_mode):
            return None
    else:
        try:
            os.mkfifo(path, 0o600)
        except FileExistsError:
            if not stat.S_ISFIFO(os.stat(path).st_mode):
                return None
        except OSError:
            return None
    try:
        return os.open(path, os.O_RDWR | os.O_NONBLOCK), path
    except OSError:
        return None


def write_pipe(path: str, line: str) -> None:
    """Write one line to the panel's pipe. Fail if the panel is not reading it."""
    payload = (line + "\n").encode("utf-8")
    try:
        handle = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
    except FileNotFoundError:
        raise SystemExit(f"No pipe at {path}.") from None
    except OSError as exc:
        if exc.errno == errno.ENXIO:
            raise SystemExit(
                f"Nothing is reading {path}. The panel opens this pipe when it starts."
            ) from None
        raise SystemExit(f"Cannot open {path}: {exc.strerror}") from None
    try:
        view = payload
        while view:
            wrote = os.write(handle, view)
            if wrote <= 0:
                raise SystemExit(f"The write to {path} did not finish.")
            view = view[wrote:]
    finally:
        os.close(handle)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m bigsigner.rpc",
        description="Write one command to the panel pipe. Secrets are not printed.",
    )
    parser.add_argument("--passphrase", default=None, help="BIP39 passphrase for injectseed. One line, no tab.")
    parser.add_argument("--pipe", default=None, help=f"pipe path (default {DEFAULT_PIPE}, or BIGSIGNER_RPC)")
    parser.add_argument("--format", action="store_true", help="print the pipe line to stdout and do not open the pipe")
    parser.add_argument("--b64", default=None, help="base64 of a pipe line already produced by --format")
    parser.add_argument("command", nargs="?", help="command word, for example injectseed")
    parser.add_argument("words", nargs="*", help="arguments for that command; injectseed reads stdin when omitted")
    args = parser.parse_args(argv)
    if args.b64 is not None and (args.command or args.words or args.passphrase is not None):
        parser.error("--b64 is the whole line, so it takes no command and no --passphrase")
    if args.b64 is None and not args.command:
        parser.error("name a command, for example injectseed")
    try:
        if args.b64 is not None:
            decoded = base64.b64decode(args.b64).decode("utf-8")
            command, rest = command_of(decoded)
            line, fingerprint = format_command(command, rest)
        elif args.command == "injectseed":
            text = " ".join(args.words) if args.words else sys.stdin.read()
            line, fingerprint = format_line(text, args.passphrase)
        else:
            if args.passphrase is not None:
                raise SessionError("The passphrase is only for injectseed.")
            line, fingerprint = format_command(args.command, " ".join(args.words))
    except (SessionError, binascii.Error, UnicodeDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if fingerprint:
        print(fingerprint, file=sys.stderr)
    if args.format:
        sys.stdout.write(line + "\n")
        return 0
    path = args.pipe or os.environ.get("BIGSIGNER_RPC", "").strip() or DEFAULT_PIPE
    write_pipe(path, line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

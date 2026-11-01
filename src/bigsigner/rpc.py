"""Send one command to a running panel.

The panel reads the pipe named by ``BIGSIGNER_RPC``. Each line starts with a
command word. This command writes that line as it was typed. The panel checks
it. ``addseed`` is one command: it is followed by the mnemonic. Twelve, 18, or
24 words are the seed. Thirteen, 19, or 25 words mean the last word is the
passphrase, and that word does not have to be in the word list. The pipe is in
RAM. Nothing is written to the SD card.

On the device, after the panel has been started with that variable:

    python -m bigsigner.rpc addseed word word ... word
    python -m bigsigner.rpc addseed word word ... word passphrase

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

# One line, including a passphrase. Longer input is dropped unread.
MAX_LINE = 4096
DEFAULT_PIPE = "/tmp/bigsigner-rpc"


def command_of(line: str) -> tuple[str, str]:
    """The first word, and the rest of the line."""
    text = line.strip()
    command, separator, rest = text.partition(" ")
    if separator:
        rest = rest.lstrip(" ")
    return command, rest


def split_line(line: str) -> tuple[str, str | None]:
    """The mnemonic and the optional passphrase. The command word is already removed.

    Twelve, 18, or 24 words are the mnemonic. Thirteen, 19, or 25 words mean the
    last word is the passphrase. That word does not have to be in the word list.
    """
    parts = line.replace(",", " ").split()
    if len(parts) in (13, 19, 25):
        return " ".join(parts[:-1]), parts[-1]
    return " ".join(parts), None


def command_refusal(command: str) -> str:
    """A log line for a command this panel does not handle. The rest of the line stays out."""
    if command.isascii() and command.isidentifier() and len(command) <= 32:
        return f"command refused: {command}"
    return "command refused"


def apply_line(app, line: str) -> str:
    """Run one pipe line. The log text has no mnemonic and no passphrase."""
    command, rest = command_of(line)
    if command == "addseed":
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
    parser.add_argument("--pipe", default=None, help=f"pipe path (default {DEFAULT_PIPE}, or BIGSIGNER_RPC)")
    parser.add_argument("--format", action="store_true", help="print the pipe line to stdout and do not open the pipe")
    parser.add_argument("--b64", default=None, help="base64 of a pipe line already produced by --format")
    parser.add_argument("command", nargs="?", help="command word, for example addseed")
    parser.add_argument("parameters", nargs=argparse.REMAINDER, help="arguments for that command")
    args = parser.parse_args(argv)
    if args.b64 is not None and (args.command or args.parameters):
        parser.error("--b64 is the whole line, so it takes no command")
    if args.b64 is None and not args.command:
        parser.error("name a command, for example addseed")
    try:
        if args.b64 is not None:
            line = base64.b64decode(args.b64).decode("utf-8").strip("\r\n")
        else:
            line = args.command if not args.parameters else f"{args.command} {' '.join(args.parameters)}"
    except (binascii.Error, UnicodeDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.format:
        sys.stdout.write(line + "\n")
        return 0
    path = args.pipe or os.environ.get("BIGSIGNER_RPC", "").strip() or DEFAULT_PIPE
    write_pipe(path, line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

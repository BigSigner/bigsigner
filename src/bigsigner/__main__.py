"""Run the browser emulator, or the panel when a framebuffer is present."""

import os

from .emulator.server import serve
from .hardware.display import framebuffer_available
from .hardware.panel import run_panel


def main():
    if os.environ.get("BIGSIGNER_EMULATOR") == "1" or not framebuffer_available():
        serve(emulator_port())
        return
    run_panel()


def emulator_port():
    raw = os.environ.get("BIGSIGNER_PORT", "8765")
    if not raw.isdigit() or not 1 <= int(raw) <= 65535:
        raise SystemExit(f"BIGSIGNER_PORT must be a number from 1 to 65535, not {raw!r}.")
    return int(raw)


if __name__ == "__main__":
    main()

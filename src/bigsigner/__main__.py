"""Run the panel when a framebuffer is present."""

from .hardware.display import framebuffer_available
from .hardware.panel import run_panel


def main():
    if not framebuffer_available():
        raise SystemExit(
            "No HDMI framebuffer at /dev/fb0. "
            "Build the browser emulator with: python -m bigsigner.bundle"
        )
    run_panel()


if __name__ == "__main__":
    main()

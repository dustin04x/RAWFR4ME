#!/usr/bin/env python3
"""Capture real Repeater terminal frames through a PTY.

The real binary is launched with persistence disabled, Ctrl+3 opens the
Repeater workspace, and the frames are saved as text (and PNG when PIL is
available) beside the existing screenshot evidence.

Run with:
    python3 scripts/capture_repeater_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import PtyApp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument(
        "--captures-dir", default=str(REPO / "docs/screenshots/repeater")
    )
    parser.add_argument("--no-png", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    captures = Path(args.captures_dir)
    for size in args.sizes.split(","):
        width, height = (int(value) for value in size.lower().split("x"))
        print(f"== PTY {width}x{height} ==")
        app = PtyApp(
            binary=binary,
            args=["--no-persist"],
            width=width,
            height=height,
            cwd=REPO,
        )
        app.start()
        try:
            app.wait_for("Proxy")
            # Ctrl+3 as an explicit CSI-u key event. A bare 0x13 byte is
            # terminal-dependent and is not reliably Ctrl+3.
            app.send(b"\x1b[51;5u")
            app.wait_for("ENGINE READY")
            app.wait_for("REQUEST")
            text = app.capture(captures, "01_workspace", not args.no_png)
            if "RESPONSE" not in text and width < 84:
                raise AssertionError("narrow Repeater split did not render RESPONSE")
            print(f"captured {width}x{height}")
        finally:
            app.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

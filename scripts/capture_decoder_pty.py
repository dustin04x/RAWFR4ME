#!/usr/bin/env python3
"""Capture real Decoder terminal frames through a PTY.

The real binary is launched with persistence disabled. Ctrl+6 opens the
Decoder, a Base64 document is typed, "Base64 decode" and "JSON pretty" are
added, and the pipeline is executed. Frames are saved as text (and PNG when
PIL is available) beside the existing screenshot evidence.

Run with:
    python3 scripts/capture_decoder_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import PtyApp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
INPUT = "eyJza3UiOiJMQU1QLTAxIiwicXVhbnRpdHkiOjF9"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument(
        "--captures-dir", default=str(REPO / "docs/screenshots/decoder")
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
            # Ctrl+6 as an explicit CSI-u key event.
            app.send(b"\x1b[54;5u")
            app.wait_for("Decoder")
            app.key(b"\r")
            app.wait_for("INPUT")
            app.send(INPUT)
            # Leave editing and return focus to the content pane. Two Tabs are
            # deterministic under the PTY; a bare ESC is not delivered here.
            app.key(b"\t", b"\t")
            # Base64 encode is selected initially; move to Base64 decode.
            # The TUI enables the kitty keyboard protocol, so use CSI-u/CSI 1;1
            # cursor form rather than a bare ESC [ C sequence.
            app.key(b"\x1b[1;1C", "a")
            # Advance from Base64 decode to JSON pretty and append it.
            for _ in range(12):
                app.key(b"\x1b[1;1C")
            app.key("a", b"\x1b[13;5u")
            text = app.wait_for("LAMP-01")
            if "JSON pretty" not in text or "OUTPUT" not in text:
                raise AssertionError("Decoder pipeline/output did not render")
            app.capture(captures, "01_workspace", not args.no_png)
            print(f"captured {width}x{height}")
        finally:
            app.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

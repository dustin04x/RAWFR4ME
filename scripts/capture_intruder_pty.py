#!/usr/bin/env python3
"""Capture real Intruder terminal frames through a PTY.

Nothing here is a mock: the packaged binary starts its own proxy, a real request
is forwarded to a local origin through that proxy, the captured request is sent
from History to Intruder, a position is marked, the plan is confirmed, and the
attack runs against the local origin. The frames written to
docs/screenshots/intruder/ are the terminal contents at each step.

Run with:
    python3 scripts/capture_intruder_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import http.server
import socket
import sys
import threading
import time
from pathlib import Path

# Importing the shared PTY harness must not leave __pycache__ in the repo.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import PtyApp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent

# Kitty CSI-u sequences: the terminal is in enhanced keyboard mode, so a bare
# control byte is not a reliable Ctrl+digit/Ctrl+Enter.
CTRL_2 = b"\x1b[50;5u"
CTRL_5 = b"\x1b[53;5u"
CTRL_ENTER = b"\x1b[13;5u"
DOWN = b"\x1b[B"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Origin:
    """Local HTTP origin whose status depends on the payload value."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:  # noqa: N802 - http.server API
                origin.hits.append(self.path)
                value = ""
                if "q=" in self.path:
                    value = self.path.split("q=", 1)[1]
                if value == "false":
                    status, body = 404, b"not found"
                elif value == "example":
                    status, body = 500, b"origin error"
                else:
                    body = f"value={value}\n".encode()
                    status = 200
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("X-Origin", "local-lab")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args: object) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def forward_through_proxy(proxy_port: int, origin_port: int) -> None:
    """Sends one real request through RAWFRAME's proxy to the local origin."""
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=10)
    conn.request(
        "GET",
        f"http://127.0.0.1:{origin_port}/search?q=seed",
        headers={"Host": f"127.0.0.1:{origin_port}", "User-Agent": "rawframe-evidence"},
    )
    response = conn.getresponse()
    response.read()
    conn.close()
    if response.status != 200:
        raise AssertionError(f"proxy did not forward the seed request: {response.status}")


def capture_size(
    binary: Path,
    width: int,
    height: int,
    directory: Path,
    save_png: bool,
) -> list[str]:
    origin = Origin()
    origin.start()
    proxy_port = free_port()
    app = PtyApp(
        binary=binary,
        args=[
            "--no-persist",
            "--port",
            str(proxy_port),
            "--scope",
            f"http://127.0.0.1:{origin.port}",
            "--allow-private-upstreams",
        ],
        width=width,
        height=height,
        cwd=REPO,
    )
    captured: list[str] = []
    app.start()
    try:
        app.wait_for("Proxy")
        app.send("p")
        app.wait_for("LISTENING", timeout=20)
        forward_through_proxy(proxy_port, origin.port)
        app.wait_for("/search", timeout=20)

        # Real capture -> History -> Intruder, exercising the transfer path.
        app.send(CTRL_2)
        app.wait_for("HISTORY", timeout=20)
        # Newest first: Home selects the request just captured (id 1000, the only
        # LIVE row). Narrow terminals have no inspector, so the row is the proof.
        app.send(b"\x1b[H")  # Home
        app.wait_for("/search?q=se", timeout=20)
        frame = app.screen.text()
        if "1000" not in frame or "LIVE" not in frame:
            raise AssertionError(
                f"{width}x{height} did not select the live capture; screen:\n{frame}"
            )
        app.send("i")
        app.wait_for("INTRUDER", timeout=20)
        app.wait_for("POSITIONS", timeout=20)

        # Move from PATH to the QUERY value and mark it.
        app.send(DOWN)
        app.send(b"M")
        app.wait_for("8 REQUESTS", timeout=20)
        setup = app.capture(directory, "01_setup", save_png)
        for expected in ("POSITIONS", "PREVIEW", "8 REQUESTS", "payloads"):
            if expected not in setup:
                raise AssertionError(f"{width}x{height} setup is missing {expected!r}")
        captured.append("01_setup")

        app.send(CTRL_ENTER)
        confirm = app.wait_for("Start Intruder attack?", timeout=20)
        for expected in ("requests", "scope", "authorized"):
            if expected not in confirm:
                raise AssertionError(
                    f"{width}x{height} confirmation is missing {expected!r}"
                )
        app.capture(directory, "02_confirm", save_png)
        captured.append("02_confirm")

        app.send(b"y")
        app.wait_for("RUNNING", timeout=20)
        time.sleep(1.2)
        app.capture(directory, "03_progress", save_png)
        captured.append("03_progress")

        app.wait_for("FINISHED", timeout=60)
        results = app.capture(directory, "04_results", save_png)
        captured.append("04_results")
        # The local origin answers 200, 404, and 500 for the built-in values.
        # Narrow terminals show fewer table rows, so the fixture-status check is
        # only asserted where those rows are on screen.
        expected_tokens = ["RESPONSE", "8/8", "FINISHED"]
        if width >= 100:
            expected_tokens += ["404", "500"]
        for expected in expected_tokens:
            if expected not in results:
                raise AssertionError(
                    f"{width}x{height} results are missing {expected!r}"
                )

        if len(origin.hits) < 8:
            raise AssertionError(
                f"origin saw {len(origin.hits)} requests, expected at least 8"
            )
    finally:
        app.stop()
        origin.stop()
    return captured


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument(
        "--captures-dir", default=str(REPO / "docs/screenshots/intruder")
    )
    parser.add_argument("--no-png", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")
    directory = Path(args.captures_dir)
    for size in args.sizes.split(","):
        width, height = (int(value) for value in size.lower().split("x"))
        print(f"== PTY {width}x{height} ==")
        frames = capture_size(binary, width, height, directory, not args.no_png)
        print(f"captured {width}x{height}: {', '.join(frames)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

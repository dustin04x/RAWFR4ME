#!/usr/bin/env python3
"""Capture real PTY evidence for HTTP/2 negotiation in the TUI.

The flow is end to end and uses no mocks:

1. `cargo run --example h2_origin` starts a local TLS origin that only offers
   the `h2` ALPN protocol.
2. The packaged RAWFRAME binary runs in a pseudo-terminal with TLS interception
   enabled and the origin's CA as the upstream trust bundle.
3. `curl --http2` sends real CONNECT + TLS + HTTP/2 requests through the proxy,
   and its reported `%{http_version}` must be `2`.
4. The TUI frames are captured as text (and PNG when the shared renderer can
   find a suitable font) under `docs/screenshots/http2/`.

Requirements: Python 3.9+ with `cryptography` (for the shared PTY helpers) and a
curl build with HTTP/2 support. Run with:
    python3 scripts/capture_http2_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from tui_tls_pty import REPO, Checks, PtyApp, free_port  # noqa: E402

CAPTURES = REPO / "docs" / "screenshots" / "http2"


def start_origin(work: Path) -> tuple[subprocess.Popen, int, Path]:
    example = REPO / "target" / "debug" / "examples" / "h2_origin"
    cert = work / "origin-ca.pem"
    process = subprocess.Popen(
        [str(example), str(cert)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert process.stdout is not None
    port = None
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            if process.poll() is not None:
                raise AssertionError("h2_origin exited before READY")
            continue
        if line.startswith("ADDR="):
            port = int(line.strip().rsplit(":", 1)[1])
        if line.startswith("READY"):
            break
    if port is None or not cert.exists():
        process.kill()
        raise AssertionError("h2_origin did not become ready")
    return process, port, cert


def curl_http2(
    proxy_port: int,
    origin_port: int,
    ca_cert: Path,
    path: str,
    data: str | None = None,
) -> tuple[str, str]:
    command = [
        "curl",
        "--http2",
        "--silent",
        "--show-error",
        "--proxy",
        f"http://127.0.0.1:{proxy_port}",
        "--cacert",
        str(ca_cert),
        "--write-out",
        "\n__HTTP_VERSION__=%{http_version} __STATUS__=%{http_code}\n",
    ]
    if data is not None:
        command += ["--data", data]
    command.append(f"https://localhost:{origin_port}{path}")
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    if result.returncode != 0:
        raise AssertionError(f"curl failed: {result.stderr.strip()}")
    return result.stdout, result.stderr


def run_size(binary: Path, width: int, height: int, keep_png: bool) -> int:
    checks = Checks()
    work = Path(tempfile.mkdtemp(prefix="rawframe-http2-pty-"))
    origin, origin_port, origin_ca = start_origin(work)
    ca_dir = work / "ca"
    ca_dir.mkdir()
    proxy_port = free_port()
    log_file = work / "rawframe.log"
    app = PtyApp(
        binary=binary,
        args=[
            "--bind",
            "127.0.0.1",
            "--port",
            str(proxy_port),
            "--scope",
            f"https://localhost:{origin_port}",
            "--allow-private-upstreams",
            "--tls-intercept",
            "--tls-ca-dir",
            str(ca_dir),
            "--tls-upstream-ca",
            str(origin_ca),
            "--no-persist",
            "--no-mouse",
            "--log-file",
            str(log_file),
        ],
        width=width,
        height=height,
        cwd=REPO,
    )
    try:
        app.start()
        app.wait_for("RAWFRAME")
        app.key("p")
        app.wait_for("LISTENING", timeout=20)

        ca_cert = ca_dir / "rawframe-ca.crt.pem"
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not ca_cert.exists():
            app.pump(0.1)
        checks(ca_cert.exists(), "local interception CA is ready")

        get_body, _ = curl_http2(proxy_port, origin_port, ca_cert, "/h2-one")
        checks("__HTTP_VERSION__=2" in get_body, "client-facing leg negotiated HTTP/2")
        checks("__STATUS__=200" in get_body, "HTTP/2 GET returned 200")
        checks(
            "version=HTTP/2.0" in get_body and "path=/h2-one" in get_body,
            "the HTTP/2 origin received the request as HTTP/2",
        )

        post_body, _ = curl_http2(
            proxy_port, origin_port, ca_cert, "/h2-two", data="payload=two"
        )
        checks("__HTTP_VERSION__=2" in post_body, "HTTP/2 POST negotiated HTTP/2")
        checks(
            "method=POST" in post_body and "body=payload=two" in post_body,
            "HTTP/2 request body reached the origin intact",
        )

        text = app.wait_for("/h2-one", timeout=30)
        print(text)
        checks("h2 /h2-one" in text, "proxy rows label the HTTP/2 exchange")
        app.capture(CAPTURES, "01_proxy_http2", keep_png)

        # The inspector is only present at wide sizes; where it exists it must
        # show the negotiated protocol next to the captured request.
        if width >= 84:
            app.key(b"\x1b[H")  # Home: newest row
            app.key("\r")
            inspected = app.wait_for("HTTP/2", timeout=20)
            checks("HTTP/2" in inspected, "inspector reports the negotiated protocol")
            app.capture(CAPTURES, "02_inspector_http2", keep_png)

        app.key("\x0b")  # Ctrl+K command palette
        app.wait_for("Go to HTTP History", timeout=10)
        app.key("history", "\r")
        app.wait_for("HTTP HISTORY", timeout=20)
        history_text = app.wait_for("/h2-two", timeout=20)
        checks(
            "h2 localhost" in history_text or "PROTOCOL" in history_text,
            "history exposes the HTTP/2 protocol at this width",
        )
        checks(
            "1001" in history_text and "1003" in history_text,
            "both HTTP/2 exchanges are in history",
        )
        app.capture(CAPTURES, "03_history_http2", keep_png)

        raw = bytes(app.raw)
        checks(b"PRIVATE KEY" not in raw, "PTY output never contained key material")
        print(f"  captured {checks.count} checks at {width}x{height}")
        return checks.count
    finally:
        app.stop()
        origin.kill()
        origin.wait(timeout=5)
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument("--no-png", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        print(f"missing binary: {binary}", file=sys.stderr)
        return 2
    if shutil.which("curl") is None:
        print("curl is required for HTTP/2 evidence", file=sys.stderr)
        return 2
    version = subprocess.run(["curl", "--version"], capture_output=True, text=True).stdout
    if "HTTP2" not in version:
        print("curl without HTTP/2 support cannot produce this evidence", file=sys.stderr)
        return 2

    build = subprocess.run(
        ["cargo", "build", "-p", "rawframe-proxy", "--example", "h2_origin"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )
    if build.returncode != 0:
        print(build.stderr, file=sys.stderr)
        return 2

    total = 0
    for spec in args.sizes.split(","):
        width, height = (int(part) for part in spec.strip().lower().split("x"))
        print(f"HTTP/2 PTY evidence at {width}x{height}")
        total += run_size(binary, width, height, not args.no_png)
    print(f"HTTP/2 PTY evidence complete: {total} checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

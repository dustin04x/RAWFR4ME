#!/usr/bin/env python3
"""Generate the README screenshot gallery from the real RAWFRAME binary.

Every image is produced by launching the release-path application inside a real
PTY at 140x40, driving it with ordinary keyboard input, and rendering the ANSI
cells the application emitted. No UI text or colours are synthesised here.

The script refuses to copy stale images: the destination gallery is cleared
first, every source frame is checked for expected workspace text, dimensions and
genuine semantic colours, and only then is a PNG copied into
``docs/screenshots/readme``.

Usage:
    python3 scripts/capture_readme_screenshots.py
    python3 scripts/capture_readme_screenshots.py --no-build
    RAWFRAME_MONO_FONT=/path/to/JetBrainsMono-Regular.ttf \
        python3 scripts/capture_readme_screenshots.py

Requirements: Python 3.9+, PIL, and the existing PTY capture dependencies.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import (  # noqa: E402
    CELL_WIDTH_FLOOR,
    LINE_HEIGHT,
    PADDING,
    PtyApp,
    find_mono_font,
)

REPO = Path(__file__).resolve().parent.parent
GALLERY = REPO / "docs" / "screenshots" / "readme"
SIZE = "140x40"

# The gallery must not borrow screenshots from a previous run. Names are listed
# explicitly so unrelated files in the directory are never deleted.
GALLERY_NAMES = (
    "proxy-main",
    "history-inspector",
    "repeater",
    "intruder",
    "decoder",
    "websocket",
)

# Exact RGB values from the TUI's violet theme palette
# (crates/rawframe-tui/src/theme.rs). A capture that cannot show these pixels is
# not a genuine render of the application's colours.
EXPECTED_COLOURS = {
    "accent": (167, 139, 250),
    "success": (74, 222, 128),
    "warning": (251, 191, 36),
    "danger": (248, 113, 113),
}

GRAPHITE_BACKGROUNDS = ((11, 11, 15), (16, 16, 22), (22, 22, 30))


class DemoHandler(http.server.BaseHTTPRequestHandler):
    """Small local HTTP origin for realistic proxy traffic."""

    routes = {
        ("GET", "/v1/orders"): (
            200,
            {"orders": [{"id": 1041, "sku": "LAMP-01", "state": "packed"}]},
        ),
        ("POST", "/v1/session"): (
            201,
            {"session": "demo", "operator": "local", "expires_in": 3600},
        ),
        ("GET", "/api/search"): (
            200,
            {"query": "lamp", "results": 3, "next": "/api/search?page=2"},
        ),
        ("GET", "/v1/admin"): (
            403,
            {"error": "forbidden", "detail": "operator role required"},
        ),
        ("DELETE", "/v1/orders/41"): (204, None),
        ("GET", "/health"): (200, {"status": "ok", "uptime_s": 1284}),
    }

    def _respond(self) -> None:
        path = self.path.split("?", 1)[0]
        status, payload = self.routes.get(
            (self.command, path), (404, {"error": "not found"})
        )
        self.send_response(status)
        self.send_header("Server", "rawframe-demo/1.0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Request-Id", f"demo-{abs(hash(path)) % 10000:04d}")
        if payload is None:
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_DELETE = _respond

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def proxy_request(port: int, method: str, path: str) -> int:
    for attempt in range(3):
        try:
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            connection.request(
                method,
                path,
                body=b'{"sku":"LAMP-01","quantity":1}' if method == "POST" else None,
                headers={
                    "Host": path.split("/", 3)[2] if "//" in path else "127.0.0.1",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()
            response.read()
            connection.close()
            return response.status
        except (OSError, http.client.HTTPException):
            if attempt == 2:
                raise
            time.sleep(0.2)
    raise AssertionError("unreachable")


def capture_proxy_and_history(binary: Path, work: Path, database: Path) -> None:
    """Start the proxy, create local traffic, then inspect it in both views."""
    origin_port = free_port()
    proxy_port = free_port()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", origin_port), DemoHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    requests: list[tuple[str, str]] = [
        ("GET", f"http://127.0.0.1:{origin_port}/v1/orders?page=2"),
        ("GET", f"http://127.0.0.1:{origin_port}/health"),
        ("POST", f"http://127.0.0.1:{origin_port}/v1/session"),
        ("GET", f"http://127.0.0.1:{origin_port}/api/search?q=lamp"),
        ("GET", f"http://127.0.0.1:{origin_port}/v1/admin"),
        ("DELETE", f"http://127.0.0.1:{origin_port}/v1/orders/41"),
        ("GET", f"http://127.0.0.1:{origin_port}/v1/orders?page=3"),
        ("GET", f"http://127.0.0.1:{origin_port}/api/search?q=desk"),
        ("GET", f"http://127.0.0.1:{origin_port}/v1/admin"),
        ("POST", f"http://127.0.0.1:{origin_port}/v1/session"),
        ("GET", f"http://127.0.0.1:{origin_port}/health"),
        ("GET", f"http://127.0.0.1:{origin_port}/v1/orders?page=4"),
    ]

    app = PtyApp(
        binary=binary,
        args=[
            "--bind",
            "127.0.0.1",
            "--port",
            str(proxy_port),
            "--scope",
            f"http://127.0.0.1:{origin_port}",
            "--allow-private-upstreams",
            "--db",
            str(database),
            "--session-name",
            "readme-demo",
            "--project",
            "RAWFRAME demo",
            "--no-mouse",
            "--log-file",
            str(work / "proxy.log"),
        ],
        width=140,
        height=40,
        cwd=REPO,
    )
    app.start()
    try:
        app.wait_for("RAWFRAME", timeout=20)
        app.send("p")
        app.wait_for("LISTENING", timeout=20)
        for method, url in requests:
            proxy_request(proxy_port, method, url)
        app.wait_for("/v1/orders", timeout=20)
        app.wait_stable()

        # Select the first captured request and open the protocol inspector.
        app.send(b"\x1b[H")
        app.key(b"\r")
        text = app.wait_for("Headers", timeout=10)
        if "No request selected" in text:
            raise AssertionError("proxy inspector did not open after selecting a row")
        app.capture(work, "proxy-main", True)

        # The same traffic, in the history workspace with the inspector visible.
        app.send(b"\x1b[50;5u")  # Ctrl+2
        app.wait_for("HTTP HISTORY", timeout=15)
        # Keep the published history view focused on the real demonstration
        # captures instead of the built-in simulated fixtures.
        app.send(b"/")
        app.send("127.0.0.1")
        app.send(b"\r")
        text = app.wait_for("12 shown", timeout=10)
        app.send(b"\x1b[H")
        app.key(b"\r")
        text = app.wait_for("Headers", timeout=10)
        if "No request selected" in text:
            raise AssertionError("history inspector did not open")
        app.capture(work, "history-inspector", True)
    finally:
        app.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def run_script(name: str, extra: list[str]) -> None:
    command = [sys.executable, str(REPO / "scripts" / name), *extra]
    print(f"  running {name} {' '.join(extra)}", flush=True)
    result = subprocess.run(
        command,
        cwd=REPO,
        text=True,
        capture_output=True,
        env=os.environ.copy(),
    )
    if result.returncode != 0:
        tail = (result.stdout + result.stderr).strip().splitlines()[-40:]
        raise AssertionError(f"{name} failed:\n" + "\n".join(tail))
    for line in result.stdout.strip().splitlines()[-4:]:
        print(f"    {line}")


def source_png(directory: Path, stem: str) -> tuple[Path, Path]:
    png = directory / f"{stem}.png"
    txt = directory / f"{stem}.txt"
    if not png.is_file() or png.stat().st_size == 0:
        raise AssertionError(f"missing or empty screenshot: {png}")
    if not txt.is_file():
        raise AssertionError(f"missing text capture: {txt}")
    return png, txt


def minimum_frame_size(size: str) -> tuple[int, int]:
    """Lower bounds derived from the renderer and the requested PTY grid.

    Trailing blank rows are stripped by ``splitlines``, so the floor allows a
    couple of missing rows rather than demanding an exact height.
    """
    cols, rows = (int(part) for part in size.split("x"))
    pad2 = PADDING * 2
    return (cols - 2) * CELL_WIDTH_FLOOR + pad2, (rows - 2) * LINE_HEIGHT + pad2


def verify_png(
    path: Path, markers: list[str], text: str, minimum: tuple[int, int]
) -> dict[str, object]:
    try:
        from PIL import Image
    except ImportError as exc:  # pragma: no cover - environment failure
        raise SystemExit("Pillow is required to verify screenshots") from exc

    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise AssertionError(f"{path.name}: text capture lacks {missing}")

    with Image.open(path) as image:
        image = image.convert("RGB")
        width, height = image.size
        colour_counts = image.getcolors(maxcolors=2_000_000)
    if colour_counts is None:
        raise AssertionError(f"{path.name}: too many colours to verify")
    counts = {colour: count for count, colour in colour_counts}
    unique = len(counts)
    if width < minimum[0] or height < minimum[1]:
        raise AssertionError(
            f"{path.name}: image {width}x{height} is smaller than the renderer "
            f"minimum {minimum[0]}x{minimum[1]}"
        )
    if unique < 120:
        raise AssertionError(f"{path.name}: only {unique} colours; likely blank or monochrome")

    present = [
        name for name, colour in EXPECTED_COLOURS.items() if counts.get(colour, 0) >= 40
    ]
    if "accent" not in present:
        raise AssertionError(f"{path.name}: no genuine violet accent pixels")
    if len(present) < 2:
        raise AssertionError(
            f"{path.name}: semantic colours missing (found {present}); "
            "the PNG may be a monochrome dump"
        )
    graphite = sum(counts.get(colour, 0) for colour in GRAPHITE_BACKGROUNDS)
    if graphite < (width * height) // 3:
        raise AssertionError(f"{path.name}: graphite background coverage is too low")
    return {
        "width": width,
        "height": height,
        "unique_colours": unique,
        "semantic_colours_present": present,
    }


def copy_capture(png: Path, txt: Path, name: str) -> Path:
    destination = GALLERY / f"{name}.png"
    shutil.copyfile(png, destination)
    text = txt.read_text(errors="replace")
    (GALLERY / f"{name}.txt").write_text(text)
    provenance = png.with_suffix(".font.txt")
    if provenance.is_file():
        shutil.copyfile(provenance, GALLERY / f"{name}.font.txt")
    return destination


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep-work", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not args.no_build:
        print("Building the workspace binary…", flush=True)
        subprocess.run(["cargo", "build", "--workspace"], cwd=REPO, check=True)
    if not binary.is_file():
        raise SystemExit(f"binary not found: {binary}")

    font = find_mono_font()
    if font is None:
        raise SystemExit(
            "No monospace font with box-drawing coverage found. "
            "Set RAWFRAME_MONO_FONT to a JetBrains Mono / Iosevka / DejaVu path."
        )

    GALLERY.mkdir(parents=True, exist_ok=True)
    for name in GALLERY_NAMES:
        for suffix in (".png", ".txt", ".font.txt"):
            candidate = GALLERY / f"{name}{suffix}"
            if candidate.exists():
                candidate.unlink()

    work_root = Path(tempfile.mkdtemp(prefix="rawframe-readme-"))
    if args.keep_work:
        print(f"Working directory: {work_root}")
    try:
        print("Capturing proxy and history with local demonstration traffic…", flush=True)
        capture_proxy_and_history(binary, work_root, work_root / "readme.db")

        common = ["--binary", str(binary), "--sizes", SIZE]
        jobs = (
            ("repeater", "capture_repeater_pty.py"),
            ("decoder", "capture_decoder_pty.py"),
            ("websocket", "capture_websocket_pty.py"),
            ("intruder", "capture_intruder_pty.py"),
        )
        for directory, script in jobs:
            print(f"Capturing {directory}…", flush=True)
            run_script(
                script,
                common + ["--captures-dir", str(work_root / directory)],
            )

        plan = {
            "proxy-main": (
                work_root,
                "140x40_proxy-main",
                ["TRAFFIC", "INSPECTOR", "GET", "200"],
            ),
            "history-inspector": (
                work_root,
                "140x40_history-inspector",
                ["HTTP HISTORY", "INSPECTOR", "Headers", "200"],
            ),
            "repeater": (
                work_root / "repeater",
                "140x40_01_workspace",
                ["REPEATER", "REQUEST", "RESPONSE", "ENGINE READY"],
            ),
            "intruder": (
                work_root / "intruder",
                "140x40_04_results",
                ["INTRUDER", "FINISHED", "RESULTS"],
            ),
            "decoder": (
                work_root / "decoder",
                "140x40_01_workspace",
                ["DECODER", "OUTPUT", "LAMP-01"],
            ),
            "websocket": (
                work_root / "websocket",
                "140x40_03_echo",
                ["WEBSOCKET", "FRAMES", "echo:ping"],
            ),
        }

        manifest: dict[str, object] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "binary": str(binary),
            "terminal": SIZE,
            "renderer": "real PTY -> ANSI cell grid -> Pillow",
            "font": str(font),
            "font_size": 14,
            "gallery": str(GALLERY.relative_to(REPO)),
            "captures": [],
        }
        for name, (directory, stem, markers) in plan.items():
            png, txt = source_png(directory, stem)
            text = txt.read_text(errors="replace")
            checks = verify_png(png, markers, text, minimum_frame_size(SIZE))
            destination = copy_capture(png, txt, name)
            manifest["captures"].append(  # type: ignore[index]
                {
                    "name": name,
                    "file": str(destination.relative_to(REPO)),
                    "source": str(png),
                    "sha256": sha256(destination),
                    **checks,
                }
            )
            print(
                f"  {name}: {checks['width']}x{checks['height']}, "
                f"{checks['unique_colours']} colours, {checks['semantic_colours_present']}"
            )

        (GALLERY / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"\nGallery ready: {GALLERY.relative_to(REPO)}")
        return 0
    finally:
        if not args.keep_work:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

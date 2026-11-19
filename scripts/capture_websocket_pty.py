#!/usr/bin/env python3
"""Capture real WebSocket workspace frames through a PTY.

The packaged binary starts its own proxy, a real RFC 6455 client upgrades
through that proxy to a local echo server, the captured frames appear in the
WebSocket workspace, and the WebSocket Repeater opens a second authored session
that sends a text frame and receives the echo. The terminal contents at each
step are written to docs/screenshots/websocket/.

Run with:
    python3 scripts/capture_websocket_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import socket
import struct
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import PtyApp  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

CTRL_7 = b"\x1b[55;5u"
CTRL_ENTER = b"\x1b[13;5u"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


def read_http_head(sock: socket.socket) -> bytes:
    head = b""
    while not head.endswith(b"\r\n\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("peer closed during handshake")
        head += chunk
    return head


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    opcode = first & 0x0F
    masked = bool(second & 0x80)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def send_frame(sock: socket.socket, opcode: int, payload: bytes, masked: bool) -> None:
    header = bytes([0x80 | opcode])
    mask_bit = 0x80 if masked else 0
    if len(payload) <= 125:
        header += bytes([mask_bit | len(payload)])
    elif len(payload) <= 0xFFFF:
        header += bytes([mask_bit | 126]) + struct.pack("!H", len(payload))
    else:
        header += bytes([mask_bit | 127]) + struct.pack("!Q", len(payload))
    if masked:
        key = os.urandom(4)
        payload = bytes(byte ^ key[index % 4] for index, byte in enumerate(payload))
        header += key
    sock.sendall(header + payload)


class EchoServer:
    """Minimal RFC 6455 echo server used as the real upstream."""

    def __init__(self) -> None:
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = self.listener.getsockname()[1]
        self.stopping = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _serve(self) -> None:
        while not self.stopping:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            head = read_http_head(connection)
            key = b""
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"sec-websocket-key:"):
                    key = line.split(b":", 1)[1].strip()
            accept = base64.b64encode(hashlib.sha1(key + GUID.encode()).digest())
            connection.sendall(
                b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
            )
            while True:
                opcode, payload = read_frame(connection)
                if opcode == 0x8:
                    send_frame(connection, 0x8, payload, masked=False)
                    return
                if opcode == 0x1:
                    send_frame(connection, 0x1, b"echo:" + payload, masked=False)
        except (ConnectionError, OSError):
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.stopping = True
        try:
            self.listener.close()
        except OSError:
            pass


def seed_through_proxy(proxy_port: int, ws_port: int) -> None:
    """Performs a real upgrade through the proxy and exchanges one frame."""
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            f"GET http://127.0.0.1:{ws_port}/chat HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{ws_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        sock.sendall(request.encode())
        head = read_http_head(sock)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise AssertionError(f"proxy did not upgrade the WebSocket: {head!r}")
        send_frame(sock, 0x1, b"seed", masked=True)
        opcode, payload = read_frame(sock)
        if opcode != 0x1 or payload != b"echo:seed":
            raise AssertionError(f"unexpected relayed echo: {opcode} {payload!r}")
        send_frame(sock, 0x8, b"\x03\xe8", masked=True)


def capture_size(
    binary: Path,
    width: int,
    height: int,
    directory: Path,
    save_png: bool,
) -> list[str]:
    echo = EchoServer()
    echo.start()
    proxy_port = free_port()
    app = PtyApp(
        binary=binary,
        args=[
            "--no-persist",
            "--port",
            str(proxy_port),
            "--scope",
            f"http://127.0.0.1:{echo.port}",
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

        seed_through_proxy(proxy_port, echo.port)
        app.send(CTRL_7)
        app.wait_for("FRAMES", timeout=20)
        app.wait_for("seed", timeout=20)
        frames = app.capture(directory, "01_frames", save_png)
        captured.append("01_frames")
        for expected in ("WebSocket", "CONNECTIONS", "FRAMES", "seed"):
            if expected not in frames:
                raise AssertionError(f"{width}x{height} frames view is missing {expected!r}")

        # Open an authored session against the same target.
        app.send("o")
        app.wait_for("2 connections", timeout=20)
        repeater = app.capture(directory, "02_repeater", save_png)
        captured.append("02_repeater")
        if "2 connections" not in repeater:
            raise AssertionError(
                f"{width}x{height} did not show the authored session: {repeater!r}"
            )

        app.send("t")
        app.wait_for("COMPOSE TEXT FRAME", timeout=10)
        app.send("ping")
        app.send(CTRL_ENTER)
        app.wait_for("echo:ping", timeout=20)
        echo_frame = app.capture(directory, "03_echo", save_png)
        captured.append("03_echo")
        for expected in ("echo:ping", "FRAMES"):
            if expected not in echo_frame:
                raise AssertionError(f"{width}x{height} echo view is missing {expected!r}")
    finally:
        app.stop()
        echo.stop()
    return captured


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument(
        "--captures-dir", default=str(REPO / "docs/screenshots/websocket")
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

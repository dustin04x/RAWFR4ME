#!/usr/bin/env python3
"""Capture and verify the real passive findings workflow through RAWFRAME.

The script drives the actual binary under a PTY, captures local HTTP and
WebSocket traffic through the proxy, then asserts against both the rendered TUI
and the SQLite rows written by the storage worker. Nothing is injected into the
findings table.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import re
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from tui_tls_pty import PtyApp, REPO  # noqa: E402

SECRETS = [
    "fixture-secret",
    "fixture-password-secret",
    "fixture-debug-secret",
    "fixture-ws-secret",
    "192.168.10.8",
    "/srv/private/app.py",
]
EXPECTED_RULES = {
    "http.cookie_missing_secure",
    "http.cookie_missing_httponly",
    "http.plaintext_credentials",
    "http.response_error_disclosure",
    "http.private_address_disclosure",
    "websocket.plaintext_transport",
    "websocket.sensitive_message",
}


class Origin(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(
                hashlib.sha1(
                    (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()
                ).digest()
            ).decode()
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            while True:
                head = self.rfile.read(2)
                if len(head) != 2 or head[0] & 0x0F == 8:
                    return
                length = head[1] & 0x7F
                if length == 126:
                    length = int.from_bytes(self.rfile.read(2), "big")
                if length >= 126:
                    return
                mask = self.rfile.read(4) if head[1] & 0x80 else b""
                payload = self.rfile.read(length)
                if mask:
                    payload = bytes(
                        value ^ mask[index % 4] for index, value in enumerate(payload)
                    )
                self.wfile.write(bytes([0x81, len(payload)]) + payload)
                self.wfile.flush()
        if self.path == "/safe":
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Set-Cookie", "safe=value; Secure; HttpOnly; SameSite=Strict"
            )
        elif self.path == "/disclosure":
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", "LocalFixture/2.4")
            self.send_header("X-Debug-Token", "fixture-debug-secret")
            self.end_headers()
            self.wfile.write(
                b"Traceback (most recent call last): /srv/private/app.py 192.168.10.8"
            )
            return
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=fixture-secret; Path=/")
        self.end_headers()
        self.wfile.write(b"<html>local fixture</html>")

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>submitted</html>")

    def log_message(self, *_args):
        pass


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def seed(proxy_port: int, origin_port: int, path: str) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
        sock.sendall(
            (
                f"GET http://localhost:{origin_port}{path} HTTP/1.1\r\n"
                f"Host: localhost:{origin_port}\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        while sock.recv(4096):
            pass


def seed_post(proxy_port: int, origin_port: int) -> None:
    body = b"username=analyst&password=fixture-password-secret"
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
        sock.sendall(
            (
                f"POST http://localhost:{origin_port}/login HTTP/1.1\r\n"
                f"Host: localhost:{origin_port}\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
            ).encode()
            + body
        )
        while sock.recv(4096):
            pass


def seed_websocket(proxy_port: int, origin_port: int) -> None:
    key = base64.b64encode(b"0123456789abcdef").decode()
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=10) as sock:
        request = (
            f"GET http://localhost:{origin_port}/chat HTTP/1.1\r\n"
            f"Host: localhost:{origin_port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "Origin: http://example.invalid\r\n\r\n"
        )
        sock.sendall(request.encode())
        data = b""
        while b"\r\n\r\n" not in data:
            data += sock.recv(4096)
        if b"101" not in data.split(b"\r\n", 1)[0]:
            raise AssertionError("local WebSocket handshake failed")
        value = b'{"access_token":"fixture-ws-secret"}'
        mask = b"abcd"
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(value))
        sock.sendall(bytes([0x81, 0x80 | len(value)]) + mask + masked)
        header = sock.recv(2)
        if len(header) != 2:
            raise AssertionError("WebSocket response message was not captured")
        length = header[1] & 0x7F
        payload = sock.recv(length)
        if payload != value:
            raise AssertionError("local WebSocket message did not round trip")
        sock.sendall(b"\x88\x80abcd")


def sqlite_rows(db: Path, query: str) -> list[tuple]:
    connection = sqlite3.connect(db, timeout=5)
    try:
        return connection.execute(query).fetchall()
    finally:
        connection.close()


def wait_for_traffic(db: Path, minimum: int, timeout: float = 15.0) -> int:
    deadline = time.monotonic() + timeout
    count = 0
    while time.monotonic() < deadline:
        try:
            count = sqlite_rows(db, "SELECT COUNT(*) FROM traffic")[0][0]
            if count >= minimum:
                return count
        except sqlite3.Error:
            pass
        time.sleep(0.2)
    raise AssertionError(f"only {count} transactions persisted, wanted {minimum}")


def wait_for_status(db: Path, status: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = sqlite_rows(db, "SELECT status FROM findings")
        if any(value == status for (value,) in rows):
            return
        time.sleep(0.2)
    raise AssertionError(f"finding status {status!r} was not persisted")


def finding_rows(db: Path) -> list[dict]:
    rows = sqlite_rows(db, "SELECT finding_json FROM findings")
    return [json.loads(value) for (value,) in rows]


def table_rules(text: str) -> list[str]:
    """Rows in the findings table, excluding the inspector's rule line."""
    return [
        line
        for line in text.splitlines()
        if re.search(r"(http|websocket)\.[a-z_]+", line)
        and ("http://" in line or "https://" in line)
    ]


def assert_search_visible(text: str, wanted: str, absent: str) -> None:
    rows = table_rules(text)
    if not any(wanted in line for line in rows):
        raise AssertionError(f"search did not show {wanted}: {rows}")
    if any(absent in line for line in rows):
        raise AssertionError(f"search still showed {absent}: {rows}")


def start_app(
    binary: Path,
    db: Path,
    width: int,
    height: int,
    session_name: str,
    proxy_port: int,
    origin_port: int,
) -> PtyApp:
    common = [
        "--bind",
        "127.0.0.1",
        "--port",
        str(proxy_port),
        "--scope",
        f"http://localhost:{origin_port}",
        "--allow-private-upstreams",
        "--db",
        str(db),
        "--project",
        "M11 local passive demo",
        "--persist-bodies",
        "--no-mouse",
        "--session-name",
        session_name,
    ]
    app = PtyApp(
        binary=binary,
        args=common,
        width=width,
        height=height,
        cwd=REPO,
    )
    app.start()
    app.wait_for("RAWFRAME", timeout=20)
    app.key("p")
    app.wait_for("LISTENING", timeout=20)
    time.sleep(0.5)
    return app


def capture_size(
    binary: Path, captures: Path, width: int, height: int, save_png: bool
) -> None:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    temporary = tempfile.TemporaryDirectory(prefix="rawframe-analysis-pty-")
    db = Path(temporary.name) / "session.db"
    first_proxy_port = free_port()
    first_app = start_app(
        binary,
        db,
        width,
        height,
        f"analysis-first-{width}x{height}",
        first_proxy_port,
        origin_port,
    )
    try:
        seed(first_proxy_port, origin_port, "/weak")
        seed_post(first_proxy_port, origin_port)
        seed(first_proxy_port, origin_port, "/disclosure")
        seed_websocket(first_proxy_port, origin_port)
        wait_for_traffic(db, 4)
    finally:
        first_app.stop()
        server.shutdown()
        server.server_close()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    proxy_port = free_port()
    app = start_app(
        binary,
        db,
        width,
        height,
        f"analysis-second-{width}x{height}",
        proxy_port,
        origin_port,
    )
    try:
        seed(proxy_port, origin_port, "/safe")
        seed_websocket(proxy_port, origin_port)
        wait_for_traffic(db, 6)

        app.send(b"\x1b[56;5u")
        app.wait_for("SECURITY FINDINGS", timeout=30)
        app.key("P")
        app.wait_for("PROJECT ANALYSIS COMPLETE", timeout=30)
        text = app.wait_for("http.plaintext_cred", timeout=30)
        app.capture(captures, "01_findings", save_png)

        rows = finding_rows(db)
        if not rows:
            raise AssertionError("project analysis produced no findings")
        observed = {finding["rule_id"] for finding in rows}
        missing = EXPECTED_RULES - observed
        if missing:
            raise AssertionError(f"missing evidence-backed rules: {sorted(missing)}")
        session_ids = {finding["session_id"] for finding in rows}
        if len(session_ids) != 2:
            raise AssertionError(f"findings did not cover two sessions: {session_ids}")

        traffic_by_session: dict[str, set[int]] = {}
        for session_id, traffic_id in sqlite_rows(
            db, "SELECT session_id, traffic_id FROM traffic"
        ):
            traffic_by_session.setdefault(session_id, set()).add(traffic_id)
        for finding in rows:
            session_id = finding["session_id"]
            if session_id not in traffic_by_session:
                raise AssertionError(f"finding used unknown session {session_id}")
            references = {evidence["traffic_id"] for evidence in finding["evidence"]}
            references.update(finding["related_traffic"])
            if not references:
                raise AssertionError("finding had no traffic reference")
            if not references <= traffic_by_session[session_id]:
                raise AssertionError(
                    f"finding used non-original traffic IDs: {references - traffic_by_session[session_id]}"
                )
        fingerprints = [(finding["session_id"], finding["fingerprint"]) for finding in rows]
        if len(fingerprints) != len(set(fingerprints)):
            raise AssertionError("duplicate finding fingerprints were persisted")

        # Search filters the real list and is then cleared.
        app.key("/", *"http.plaintext", "\r")
        search_text = app.wait_for("SEARCH: http.plaintext", timeout=10)
        assert_search_visible(search_text, "http.plaintext_cred", "websocket.plaintext")
        app.capture(captures, "02_search", save_png)
        app.key("/", *(["\x7f"] * len("http.plaintext")), "\r")
        app.wait_for("SECURITY FINDINGS", absent="SEARCH:", timeout=10)

        # Severity filtering: None -> Critical -> High -> Medium.
        app.key("s", "s", "s")
        severity_text = app.wait_for("MED", timeout=10)
        severity_rows = table_rules(severity_text)
        if not severity_rows or any("MED" not in line for line in severity_rows):
            raise AssertionError(f"severity filter leaked non-medium rows: {severity_rows}")
        app.capture(captures, "03_severity_medium", save_png)
        app.key("s", "s", "s")  # Medium -> Low -> Informational -> None

        # Acknowledge the selected medium finding and verify real persistence.
        app.key("a")
        wait_for_status(db, "acknowledged")
        app.wait_for("Acknowledged", timeout=10)
        app.capture(captures, "04_acknowledged", save_png)

        # Status filter: None -> New -> Open -> Acknowledged.
        app.key("t", "t", "t")
        status_text = app.wait_for("ACK", timeout=10)
        status_rows = table_rules(status_text)
        if not any("websocket.plaintext" in line for line in status_rows):
            raise AssertionError(f"acknowledged finding was filtered out: {status_rows}")
        if any("http.plaintext_cred" in line for line in status_rows):
            raise AssertionError(f"status filter leaked a new finding: {status_rows}")
        app.capture(captures, "05_status_acknowledged", save_png)
        app.key("t", "t", "t", "t")  # Acknowledged -> ... -> None

        # Reopen the same finding and verify the persisted transition.
        app.key("O")
        wait_for_status(db, "reopened")
        app.wait_for("Reopened", timeout=10)
        app.key("t", "t", "t", "t", "t", "t")
        reopened_text = app.wait_for("REOPENED", timeout=10)
        if not any("websocket.plaintext" in line for line in table_rules(reopened_text)):
            raise AssertionError("reopened status filter did not show the finding")
        app.capture(captures, "06_reopened", save_png)
        app.key("t")  # Reopened -> None

        # Related-traffic navigation must select the restored /chat row.
        app.key("v")
        history_text = app.wait_for("RAWFRAME  |  History", timeout=15)
        if "HTTP HISTORY" not in history_text or "/chat" not in history_text:
            raise AssertionError("related navigation did not open the captured /chat row")
        app.capture(captures, "07_related_traffic", save_png)

        # Export all JSON and verify it contains the analyzed, redacted model.
        app.send(b"\x1b[56;5u")
        app.wait_for("SECURITY FINDINGS", timeout=15)
        app.key("E")
        app.wait_for("Exported", timeout=20)
        app.capture(captures, "08_export", save_png)
        reports = sorted(
            Path(temporary.name).glob("rawframe-findings-*.json"),
            key=lambda path: path.stat().st_mtime,
        )
        if not reports:
            raise AssertionError("TUI did not write its JSON findings export")
        report_text = reports[-1].read_text()
        report = json.loads(report_text)
        report_findings = report.get("findings") or []
        if len(report_findings) < len(rows):
            raise AssertionError(
                f"export had {len(report_findings)} findings, database had {len(rows)}"
            )
        if not EXPECTED_RULES <= {finding["rule_id"] for finding in report_findings}:
            raise AssertionError("export omitted expected engine-generated rules")
        for finding in report_findings:
            if not finding.get("session_id"):
                raise AssertionError("exported finding lost its session identity")
        for secret in SECRETS:
            if secret in report_text:
                raise AssertionError(f"export exposed {secret!r}")
    finally:
        app.stop()
        server.shutdown()
        server.server_close()

    # A fresh process must restore the analyst lifecycle from SQLite.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    restart = start_app(
        binary,
        db,
        width,
        height,
        f"analysis-restart-{width}x{height}",
        free_port(),
        origin_port,
    )
    try:
        restart.send(b"\x1b[56;5u")
        restart.wait_for("SECURITY FINDINGS", timeout=20)
        restart.key("P")
        restart.wait_for("PROJECT ANALYSIS COMPLETE", timeout=30)
        restart.key("t", "t", "t", "t", "t", "t")
        restart_text = restart.wait_for("REOPENED", timeout=20)
        if "websocket.plaintext" not in restart_text:
            raise AssertionError("restarted finding was not the persisted observation")
        restart.capture(captures, "09_restart_persisted", save_png)
    finally:
        restart.stop()
        server.shutdown()
        server.server_close()

    rows = finding_rows(db)
    if not any(finding["status"] == "reopened" for finding in rows):
        raise AssertionError("reopened lifecycle state did not survive restart")
    serialized = "\n".join(json.dumps(row) for row in rows)
    for secret in SECRETS:
        if secret in serialized:
            raise AssertionError(f"persisted findings exposed {secret!r}")
    temporary.cleanup()
    print(f"captured and verified {width}x{height}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument("--sizes", default="140x40,100x30,80x24")
    parser.add_argument(
        "--captures-dir", default=str(REPO / "docs/screenshots/analysis")
    )
    parser.add_argument("--no-png", action="store_true")
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    captures = Path(args.captures_dir)
    for size in args.sizes.split(","):
        width, height = (int(value) for value in size.lower().split("x"))
        capture_size(binary, captures, width, height, not args.no_png)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

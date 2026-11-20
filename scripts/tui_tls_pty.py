#!/usr/bin/env python3
"""Drive RAWFRAME through a real PTY and verify HTTPS interception end to end.

The test launches the packaged binary, uses the actual Settings controls to
enable/disable TLS interception, and sends real CONNECT/TLS traffic through the
proxy to local HTTPS origins. It saves the terminal frames it saw so the TUI
evidence can be reviewed without a terminal recording.

Requirements: Python 3.9+, `cryptography`, and (optional, for PNG frames) PIL.
Run with:
    python3 scripts/tui_tls_pty.py --binary target/debug/rawframe
"""

from __future__ import annotations

import argparse
import codecs
import datetime as dt
import fcntl
import http.server
import os
import pty
import re
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
except ImportError:  # pragma: no cover - reported by main
    x509 = None

REPO = Path(__file__).resolve().parent.parent

# Every glyph the panels use: box drawing, block/bar characters, arrows, the
# position marker, and the footer's check/carriage-return pair. A face missing
# any of these renders replacement boxes into published evidence, so font
# discovery asks fontconfig for full coverage before falling back.
GLYPH_PROBE = "─│╭╮╰╯├┼▌█░▒✓↵§·↑↓→←…"

# Monospace font discovery is deliberately portable: an explicit override, a
# coverage-checked fontconfig answer, then the usual Debian/Arch/Fedora/macOS/
# Windows locations. PNG frames are optional evidence, so a machine without any
# match still produces the mandatory text frames.
FONT_CANDIDATES = (
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/usr/share/fonts/liberation-mono/LiberationMono-Regular.ttf",
    "/usr/share/fonts/noto/NotoSansMono-Regular.ttf",
    "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
    "/usr/share/fonts/Adwaita/AdwaitaMono-Regular.ttf",
    "/usr/share/fonts/TTF/FiraCodeNerdFontMono-Regular.ttf",
    "/usr/share/fonts/TTF/JetBrainsMonoNerdFontMono-Regular.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/Library/Fonts/Menlo.ttc",
    "C:/Windows/Fonts/consola.ttf",
)


def _font_covers(path: Path) -> bool:
    """True when fontconfig reports every probe glyph in this font's charset."""
    if not shutil.which("fc-list"):
        # Without fontconfig there is nothing authoritative to check; accept the
        # candidate rather than losing PNG evidence entirely.
        return True
    try:
        result = subprocess.run(
            ["fc-list", f":file={path}", "-f", "%{charset}\n"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    line = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    ranges: list[tuple[int, int]] = []
    for token in line.split():
        low, _, high = token.partition("-")
        try:
            ranges.append((int(low, 16), int(high or low, 16)))
        except ValueError:
            continue
    if not ranges:
        return False
    return all(any(low <= ord(ch) <= high for low, high in ranges) for ch in GLYPH_PROBE)


def _fc_match(pattern: str) -> Path | None:
    if not shutil.which("fc-match"):
        return None
    try:
        result = subprocess.run(
            ["fc-match", "-f", "%{file}", pattern],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    match = result.stdout.strip()
    return Path(match) if match and Path(match).is_file() else None


def find_mono_font() -> Path | None:
    """Returns a usable monospace font path, or None when none is installed."""
    override = os.environ.get("RAWFRAME_MONO_FONT")
    if override and Path(override).is_file():
        return Path(override)

    charset = " ".join(f"{ord(ch):04x}" for ch in GLYPH_PROBE)
    covered = _fc_match(f"monospace:charset={charset}")
    if covered is not None and _font_covers(covered):
        return covered

    for candidate in FONT_CANDIDATES:
        path = Path(candidate)
        if path.is_file() and _font_covers(path):
            return path

    if covered is not None:
        return covered
    fallback = _fc_match("monospace")
    if fallback is not None:
        return fallback
    for candidate in FONT_CANDIDATES:
        if Path(candidate).is_file():
            return Path(candidate)
    return None


def char_width(ch: str) -> int:
    if not ch:
        return 0
    if unicodedata.combining(ch):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1


# Standard ANSI colours, used only when a capture falls back to the 8/16-colour
# SGR codes instead of truecolor.
ANSI_BASE = (
    (0, 0, 0),
    (205, 49, 49),
    (13, 188, 121),
    (229, 229, 16),
    (36, 114, 200),
    (188, 63, 188),
    (17, 168, 205),
    (229, 229, 229),
    (102, 102, 102),
    (241, 76, 76),
    (35, 209, 139),
    (245, 245, 67),
    (59, 142, 234),
    (214, 112, 214),
    (41, 184, 219),
    (255, 255, 255),
)


def xterm256(index: int) -> tuple[int, int, int]:
    """Maps an xterm-256 palette index to RGB."""
    if 0 <= index < 16:
        return ANSI_BASE[index]
    if 16 <= index < 232:
        value = index - 16
        steps = (0, 95, 135, 175, 215, 255)
        return (
            steps[value // 36],
            steps[(value % 36) // 6],
            steps[value % 6],
        )
    if 232 <= index < 256:
        level = 8 + (index - 232) * 10
        return (level, level, level)
    return (255, 255, 255)


class Screen:
    """Small ANSI terminal emulator for the subset ratatui emits."""

    def __init__(self, width: int, height: int):
        self.width = width
        self.height = height
        self.grid = [[" "] * width for _ in range(height)]
        # Per-cell SGR colours. ``None`` means "terminal default", which the
        # renderer maps to the documented graphite palette.
        self.fg_grid = [[None] * width for _ in range(height)]
        self.bg_grid = [[None] * width for _ in range(height)]
        self.fg = None
        self.bg = None
        self.x = 0
        self.y = 0
        self.pending = ""
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")

    def clear(self) -> None:
        self.grid = [[" "] * self.width for _ in range(self.height)]
        self.fg_grid = [[None] * self.width for _ in range(self.height)]
        self.bg_grid = [[None] * self.width for _ in range(self.height)]
        self.x = self.y = 0

    def _erase(self, row: int, column: int) -> None:
        self.grid[row][column] = " "
        self.fg_grid[row][column] = self.fg
        self.bg_grid[row][column] = self.bg

    def _reset_row(self, row: int) -> None:
        self.grid[row] = [" "] * self.width
        self.fg_grid[row] = [self.fg] * self.width
        self.bg_grid[row] = [self.bg] * self.width

    def _scroll_or_clamp(self) -> None:
        if self.y >= self.height:
            self.grid.pop(0)
            self.fg_grid.pop(0)
            self.bg_grid.pop(0)
            self.grid.append([" "] * self.width)
            self.fg_grid.append([None] * self.width)
            self.bg_grid.append([None] * self.width)
            self.y = self.height - 1

    def _put(self, ch: str) -> None:
        width = char_width(ch)
        if width == 0:
            return
        if self.x + width > self.width:
            self.x = 0
            self.y += 1
            self._scroll_or_clamp()
        self.grid[self.y][self.x] = ch
        self.fg_grid[self.y][self.x] = self.fg
        self.bg_grid[self.y][self.x] = self.bg
        if width == 2 and self.x + 1 < self.width:
            self.grid[self.y][self.x + 1] = ""
            self.fg_grid[self.y][self.x + 1] = self.fg
            self.bg_grid[self.y][self.x + 1] = self.bg
        self.x += width
        if self.x >= self.width:
            self.x = self.width - 1

    def _csi(self, params: str, final: str) -> None:
        private = params.startswith("?")
        if private:
            params = params[1:]
        raw = [p for p in params.split(";") if p != ""]
        nums = [int(p) if p.isdigit() else 0 for p in raw]

        def n(index: int, default: int = 1) -> int:
            value = nums[index] if index < len(nums) else default
            return value if value else default

        if final in ("H", "f"):
            self.y = max(0, min(self.height - 1, n(0) - 1))
            self.x = max(0, min(self.width - 1, n(1) - 1))
        elif final == "A":
            self.y = max(0, self.y - n(0))
        elif final == "B":
            self.y = min(self.height - 1, self.y + n(0))
        elif final == "C":
            self.x = min(self.width - 1, self.x + n(0))
        elif final == "D":
            self.x = max(0, self.x - n(0))
        elif final == "G":
            self.x = max(0, min(self.width - 1, n(0) - 1))
        elif final == "d":
            self.y = max(0, min(self.height - 1, n(0) - 1))
        elif final == "J":
            mode = nums[0] if nums else 0
            if mode in (2, 3):
                self.clear()
            elif mode == 0:
                for x in range(self.x, self.width):
                    self._erase(self.y, x)
                for y in range(self.y + 1, self.height):
                    self._reset_row(y)
            elif mode == 1:
                for y in range(0, self.y):
                    self._reset_row(y)
                for x in range(0, self.x + 1):
                    self._erase(self.y, x)
        elif final == "K":
            mode = nums[0] if nums else 0
            if mode == 0:
                for x in range(self.x, self.width):
                    self._erase(self.y, x)
            elif mode == 1:
                for x in range(0, self.x + 1):
                    self._erase(self.y, x)
            elif mode == 2:
                self._reset_row(self.y)
        elif final == "m":
            self._sgr(nums if raw else [0])
        elif final in ("h", "l") and private:
            mode = params
            if mode in ("1049", "47", "1047") and final == "h":
                self.clear()

    def _sgr(self, nums: list[int]) -> None:
        """Applies an SGR parameter list to the current pen.

        ratatui emits select-graphic-rendition sequences for every cell run, so
        tracking them is what makes the rendered PNG carry the application's
        real colours instead of a single flat fill.
        """
        index = 0
        while index < len(nums):
            code = nums[index]
            if code == 0:
                self.fg = None
                self.bg = None
            elif code == 39:
                self.fg = None
            elif code == 49:
                self.bg = None
            elif code in (38, 48):
                target = "fg" if code == 38 else "bg"
                if index + 1 < len(nums):
                    mode = nums[index + 1]
                    if mode == 2 and index + 4 < len(nums):
                        setattr(
                            self,
                            target,
                            (nums[index + 2], nums[index + 3], nums[index + 4]),
                        )
                        index += 4
                    elif mode == 5 and index + 2 < len(nums):
                        setattr(self, target, xterm256(nums[index + 2]))
                        index += 2
            elif 30 <= code <= 37:
                self.fg = ANSI_BASE[code - 30]
            elif 90 <= code <= 97:
                self.fg = ANSI_BASE[code - 90 + 8]
            elif 40 <= code <= 47:
                self.bg = ANSI_BASE[code - 40]
            elif 100 <= code <= 107:
                self.bg = ANSI_BASE[code - 100 + 8]
            index += 1

    def feed(self, data: bytes) -> None:
        text = self.pending + self.decoder.decode(data)
        self.pending = ""
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                if i + 1 >= len(text):
                    self.pending = text[i:]
                    return
                nxt = text[i + 1]
                if nxt == "[":
                    j = i + 2
                    while j < len(text) and not ("@" <= text[j] <= "~"):
                        j += 1
                    if j >= len(text):
                        self.pending = text[i:]
                        return
                    self._csi(text[i + 2 : j], text[j])
                    i = j + 1
                elif nxt == "]":
                    end_bel = text.find("\x07", i + 2)
                    end_st = text.find("\x1b\\", i + 2)
                    ends = [p for p in (end_bel, end_st) if p >= 0]
                    if not ends:
                        self.pending = text[i:]
                        return
                    end = min(ends)
                    i = end + (1 if end == end_bel else 2)
                elif nxt in "()":
                    if i + 2 >= len(text):
                        self.pending = text[i:]
                        return
                    i += 3
                else:
                    i += 2
                continue
            if ch == "\r":
                self.x = 0
            elif ch == "\n":
                self.y += 1
                self._scroll_or_clamp()
            elif ch == "\b":
                self.x = max(0, self.x - 1)
            elif ch == "\t":
                self.x = min(self.width - 1, (self.x // 8 + 1) * 8)
            elif ch >= " ":
                self._put(ch)
            i += 1

    def lines(self) -> list[str]:
        return ["".join(row).rstrip() for row in self.grid]

    def text(self) -> str:
        return "\n".join(self.lines())


@dataclass
class PtyApp:
    binary: Path
    args: list[str]
    width: int
    height: int
    cwd: Path
    env: dict[str, str] = field(default_factory=dict)
    process: subprocess.Popen | None = None
    master: int | None = None
    screen: Screen | None = None
    raw: bytearray = field(default_factory=bytearray)

    def start(self) -> None:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", self.height, self.width, 0, 0))
        env = os.environ.copy()
        env.update(
            {
                "TERM": "xterm-256color",
                "COLORTERM": "truecolor",
                "NO_COLOR": "",
                "RUST_BACKTRACE": "1",
            }
        )
        env.update(self.env)
        self.process = subprocess.Popen(
            [str(self.binary), *self.args],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            cwd=self.cwd,
            env=env,
            close_fds=True,
        )
        os.close(slave)
        self.master = master
        os.set_blocking(master, False)
        self.screen = Screen(self.width, self.height)

    def pump(self, duration: float = 0.05) -> bool:
        assert self.master is not None and self.screen is not None
        end = time.monotonic() + duration
        got = False
        while time.monotonic() < end:
            ready, _, _ = select.select([self.master], [], [], max(0, end - time.monotonic()))
            if not ready:
                continue
            try:
                data = os.read(self.master, 65536)
            except OSError:
                return got
            if not data:
                return got
            self.raw.extend(data)
            self.screen.feed(data)
            got = True
        return got

    def wait_for(self, needle: str, timeout: float = 10.0, absent: str | None = None) -> str:
        assert self.screen is not None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.pump()
            text = self.screen.text()
            if needle in text and (absent is None or absent not in text):
                return text
            if self.process and self.process.poll() is not None:
                raise AssertionError(f"TUI exited while waiting for {needle!r}:\n{text}")
        raise AssertionError(f"timed out waiting for {needle!r}; screen:\n{self.screen.text()}")

    def wait_stable(self, timeout: float = 2.0, quiet: float = 0.35) -> str:
        assert self.screen is not None
        deadline = time.monotonic() + timeout
        last_change = time.monotonic()
        previous = self.screen.text()
        while time.monotonic() < deadline:
            self.pump(0.05)
            current = self.screen.text()
            if current != previous:
                previous = current
                last_change = time.monotonic()
            elif time.monotonic() - last_change >= quiet:
                break
        return previous

    def send(self, data: bytes | str) -> None:
        assert self.master is not None
        if isinstance(data, str):
            data = data.encode()
        os.write(self.master, data)

    def key(self, *parts: bytes | str) -> None:
        for part in parts:
            self.send(part)
            time.sleep(0.08)

    def capture(self, directory: Path | None, name: str, save_png: bool) -> str:
        text = self.wait_stable()
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
            stem = f"{self.width}x{self.height}_{name}"
            (directory / f"{stem}.txt").write_text(text + "\n")
            if save_png:
                save_screen(self.screen, directory / f"{stem}.png")
        return text

    def stop(self) -> None:
        if self.process is None:
            return
        if self.master is not None and self.process.poll() is None:
            try:
                self.send("\x03")
                self.process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        if self.master is not None:
            try:
                os.close(self.master)
            except OSError:
                pass
            self.master = None


# Rasterisation constants. The verifier in capture_readme_screenshots.py reads
# these so the size floor it enforces is derived from the actual renderer
# rather than a hardcoded guess.
FONT_SIZE = 14
LINE_HEIGHT = 20
PADDING = 12
# Conservative average glyph advance for a 14pt monospace face, used only to
# derive a lower bound on a plausible frame width.
CELL_WIDTH_FLOOR = 7


DEFAULT_FG = (226, 232, 240)
DEFAULT_BG = (11, 11, 15)


def save_screen(screen: Screen, path: Path) -> None:
    """Rasterises the emulated cell grid, one paint operation per cell.

    Every cell carries the foreground and background the application emitted, so
    the resulting PNG shows the real theme colours (graphite surfaces, violet
    accents, semantic status colours) rather than a single flat text fill.
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return
    mono = find_mono_font()
    if mono is None:
        return
    font = ImageFont.truetype(str(mono), FONT_SIZE)
    cell_w = max(1.0, font.getlength("M"))
    pad2 = PADDING * 2
    # The trailing slack keeps the final column's glyph from touching the edge:
    # ``getlength`` reports the advance of one glyph, which can be a fraction of
    # a pixel narrower than the cell the app actually used.
    width = int(round(cell_w * screen.width)) + pad2 + 4
    height = screen.height * LINE_HEIGHT + pad2
    image = Image.new("RGB", (width, height), DEFAULT_BG)
    draw = ImageDraw.Draw(image)
    for row in range(screen.height):
        top = PADDING + row * LINE_HEIGHT
        for column in range(screen.width):
            ch = screen.grid[row][column]
            bg = screen.bg_grid[row][column] or DEFAULT_BG
            if bg != DEFAULT_BG:
                left = PADDING + int(round(column * cell_w))
                draw.rectangle(
                    [left, top, left + int(round(cell_w)) - 1, top + LINE_HEIGHT - 1],
                    fill=bg,
                )
            if not ch or ch == " ":
                continue
            fg = screen.fg_grid[row][column] or DEFAULT_FG
            draw.text(
                (PADDING + int(round(column * cell_w)), top - 1),
                ch,
                font=font,
                fill=fg,
            )
    image.save(path)


def save_frame(text: str, path: Path) -> None:
    """Rasterises plain text with no colour information (fallback path)."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return
    mono = find_mono_font()
    if mono is None:
        return
    font = ImageFont.truetype(str(mono), FONT_SIZE)
    lines = text.splitlines() or [""]
    pad2 = PADDING * 2
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    width = max(640, int(max(probe.textlength(line, font=font) for line in lines)) + pad2)
    height = max(200, len(lines) * LINE_HEIGHT + pad2)
    image = Image.new("RGB", (width, height), DEFAULT_BG)
    draw = ImageDraw.Draw(image)
    for index, line in enumerate(lines):
        draw.text(
            (PADDING, PADDING + index * LINE_HEIGHT),
            line,
            font=font,
            fill=DEFAULT_FG,
        )
    image.save(path)


# ---------------------------------------------------------------------------
# Local PKI / HTTPS origins


def make_pki(root: Path) -> dict[str, Path]:
    assert x509 is not None
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RAWFRAME PTY test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "RAWFRAME PTY test CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path = root / "origin-ca.pem"
    ca_key_path = root / "origin-ca.key.pem"
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )

    def leaf(name: str, sans: list[x509.GeneralName]) -> tuple[Path, Path]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        cert_path = root / f"{name}.pem"
        key_path = root / f"{name}.key.pem"
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )
        return cert_path, key_path

    good_cert, good_key = leaf(
        "good",
        [
            x509.DNSName("localhost"),
            x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1")),
        ],
    )
    bad_cert, bad_key = leaf(
        "wrong-host", [x509.DNSName("wrong-host.invalid")]
    )
    return {
        "ca_cert": ca_cert_path,
        "good_cert": good_cert,
        "good_key": good_key,
        "bad_cert": bad_cert,
        "bad_key": bad_key,
    }


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        body = f"origin:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_args) -> None:
        pass


class HttpsOrigin:
    def __init__(self, cert: Path, key: Path):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        self.server.daemon_threads = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        context.set_alpn_protocols(["http/1.1"])
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


# ---------------------------------------------------------------------------
# Client helpers


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def read_headers(sock: socket.socket) -> tuple[int, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            break
        data.extend(chunk)
    head = bytes(data).split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
    status = int(match.group(1)) if match else 0
    return status, bytes(data)


def connect_tunnel(proxy_port: int, host: str, port: int) -> tuple[socket.socket, int, bytes]:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    sock.settimeout(10)
    request = (
        f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    )
    sock.sendall(request.encode())
    status, headers = read_headers(sock)
    return sock, status, headers


def client_context(cafile: Path | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["http/1.1"])
    if cafile is not None:
        context.load_verify_locations(cafile)
    return context


def https_get(
    proxy_port: int,
    target_port: int,
    path: str,
    cafile: Path | None,
    *,
    host: str = "localhost",
    expect_connect: int = 200,
) -> tuple[int, bytes]:
    sock, status, headers = connect_tunnel(proxy_port, host, target_port)
    if status != expect_connect:
        sock.close()
        raise AssertionError(f"CONNECT returned {status}, expected {expect_connect}: {headers!r}")
    tls = client_context(cafile).wrap_socket(sock, server_hostname=host)
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}:{target_port}\r\n"
        "Connection: close\r\n\r\n"
    )
    tls.sendall(request.encode())
    data = bytearray()
    while True:
        chunk = tls.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
    tls.close()
    head = bytes(data).split(b"\r\n", 1)[0]
    match = re.match(rb"HTTP/1\.1 (\d{3})", head)
    return (int(match.group(1)) if match else 0), bytes(data)


# ---------------------------------------------------------------------------
# Flow


class Checks:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)
        self.count += 1
        print(f"  PASS {message}")


def app_args(
    proxy_port: int,
    origin: HttpsOrigin,
    bad_origin: HttpsOrigin,
    ca_dir: Path,
    upstream_ca: Path,
    log_file: Path,
) -> list[str]:
    return [
        "--bind",
        "127.0.0.1",
        "--port",
        str(proxy_port),
        "--scope",
        f"https://localhost:{origin.port}",
        "--scope",
        f"https://localhost:{bad_origin.port}",
        "--allow-private-upstreams",
        "--tls-ca-dir",
        str(ca_dir),
        "--tls-upstream-ca",
        str(upstream_ca),
        "--no-mouse",
        "--log-file",
        str(log_file),
    ]


def goto_settings(app: PtyApp) -> None:
    app.key(b"\x1c")  # Ctrl+4
    app.wait_for("Settings")


def goto_proxy(app: PtyApp) -> None:
    # The sidebar disappears at narrow widths, so navigate through the command
    # palette exactly as an operator would.
    app.key(b"\x0b")  # Ctrl+K
    app.wait_for("Go to Proxy", timeout=10)
    app.key("proxy", "\r")
    app.wait_for("Stop proxy", timeout=10)


def enable_tls(app: PtyApp) -> None:
    goto_settings(app)
    # Settings starts at BindAddress; TLS interception is the fourth entry.
    app.key(b"\x1b[B", b"\x1b[B", b"\x1b[B", "\r")
    app.wait_for("● ON", timeout=15)


def disable_tls(app: PtyApp) -> None:
    goto_settings(app)
    # The CA row may have been selected during the fingerprint check; return to
    # the TLS toggle before activating it.
    app.key(b"\x1b[H", b"\x1b[B", b"\x1b[B", b"\x1b[B")
    app.wait_for("HTTPS TLS interception", timeout=10)
    app.key("\r")
    app.wait_for("○ OFF", timeout=10)


def run_flow(
    binary: Path,
    width: int,
    height: int,
    captures: Path | None,
    keep_png: bool,
) -> int:
    checks = Checks()
    work = Path(tempfile.mkdtemp(prefix="rawframe-tui-tls-"))
    ca_dir = work / "ca"
    ca_dir.mkdir()
    pki = make_pki(work)
    good = HttpsOrigin(pki["good_cert"], pki["good_key"])
    bad = HttpsOrigin(pki["bad_cert"], pki["bad_key"])
    proxy_port = free_port()
    log_file = work / "rawframe.log"
    app = PtyApp(
        binary=binary,
        args=app_args(proxy_port, good, bad, ca_dir, pki["ca_cert"], log_file),
        width=width,
        height=height,
        cwd=REPO,
    )
    try:
        app.start()
        app.wait_for("RAWFRAME")
        app.capture(captures, "01_stopped_tls_off", keep_png)

        app.key("p")
        app.wait_for("LISTENING", timeout=15)
        app.capture(captures, "02_listening_tls_off", keep_png)
        text = app.screen.text()
        checks("HTTPS CONNECT" in text and "opaque" in text, "listening state says CONNECT is opaque")
        checks("TLS DECRYPTED" not in text, "no decrypted marker while TLS is off")

        goto_settings(app)
        app.capture(captures, "03_settings_tls_off_ca_missing", keep_png)
        text = app.screen.text()
        checks("TLS interception" in text, "TLS interception control is visible")
        checks("not initialised" in text or "○ OFF" in text, "CA/TLS state is off before enable")
        goto_proxy(app)

        # Existing session opened while interception is off. It must stay an
        # opaque relay even after TLS interception is enabled.
        existing, status, headers = connect_tunnel(proxy_port, "localhost", good.port)
        checks(status == 200, f"opaque CONNECT established before enabling ({status})")
        app.wait_for("TUNNEL", timeout=10)
        pre_enable = app.screen.text()
        checks("TLS DECRYPTED" not in pre_enable, "opaque tunnel is not labelled decrypted")
        checks("CONNECT" in pre_enable, "opaque tunnel is labelled CONNECT")
        app.capture(captures, "04_opaque_tunnel_before_enable", keep_png)

        enable_tls(app)
        deadline = time.monotonic() + 10
        ca_cert = ca_dir / "rawframe-ca.crt.pem"
        ca_key = ca_dir / "rawframe-ca.key.pem"
        while time.monotonic() < deadline and not (ca_cert.exists() and ca_key.exists()):
            app.pump(0.1)
        checks(ca_cert.exists() and ca_key.exists(), "enabling TLS generated local CA material")
        checks(oct(ca_key.stat().st_mode & 0o777) == "0o600", "CA private key is owner-only (0600)")
        checks("TLS interception ON" in app.screen.text() or "● ON" in app.screen.text(), "TUI shows TLS interception ON")
        app.capture(captures, "05_settings_tls_on_ca_ready", keep_png)

        # Certificates/fingerprint are reachable from the Settings control.
        app.key(b"\x1b[F", b"\x1b[A", b"\x1b[A", "\r")  # End, Up (fingerprint), Up (CA), Enter
        app.wait_for("CA certificate:", timeout=5)
        ca_text = app.wait_stable()
        checks("rawframe-ca.crt.pem" in ca_text, "CA certificate path is readable in the TUI")
        # The compact fingerprint row remains readable at narrow widths, where
        # the details pane is deliberately hidden.
        app.key(b"\x1b[B")
        ca_text = app.wait_stable()
        checks(
            re.search(r"SHA256:[A-Za-z0-9+/=]{8,}", ca_text) is not None,
            "CA fingerprint is readable in the TUI",
        )
        checks("PRIVATE KEY" not in ca_text, "no private key material is displayed")
        app.capture(captures, "06_ca_path_and_fingerprint", keep_png)
        goto_proxy(app)

        # Finish the pre-enable tunnel with a real TLS request. Because its
        # session snapshot predates enabling, it must remain opaque.
        existing_tls = client_context(pki["ca_cert"]).wrap_socket(
            existing, server_hostname="localhost"
        )
        existing_tls.sendall(
            f"GET /existing-opaque HTTP/1.1\r\nHost: localhost:{good.port}\r\n"
            "Connection: close\r\n\r\n".encode()
        )
        existing_body = b""
        while True:
            chunk = existing_tls.recv(65536)
            if not chunk:
                break
            existing_body += chunk
        existing_tls.close()
        checks(b"origin:/existing-opaque" in existing_body, "pre-enable tunnel still relays HTTPS")

        # New post-enable CONNECT is decrypted and enters the queue.
        status, body = https_get(proxy_port, good.port, "/secure", ca_cert)
        checks(status == 200 and b"origin:/secure" in body, "decrypted HTTPS request succeeds")
        # The TUI repaints on a 250 ms cadence; under a loaded CI machine the
        # decrypted row can take a few seconds to appear, so wait for the row
        # itself rather than a single frame after a short fixed delay.
        text = app.wait_for("/secure", timeout=30)
        checks("TLS DECRYPTED" in text or "GET" in text, "decrypted request appears in the TUI queue")
        checks("/existing-opaque" not in text, "existing opaque session is not shown as decrypted")
        checks("PRIVATE KEY" not in text, "decrypted traffic view contains no key material")
        app.capture(captures, "07_decrypted_https", keep_png)

        # Upstream certificate verification failure is a failed CONNECT entry,
        # never a successful decrypted capture.
        sock, status, headers = connect_tunnel(proxy_port, "localhost", bad.port)
        sock.close()
        checks(status == 502, f"upstream verification failure is rejected ({status})")
        app.wait_for("TUNNEL FAILED", timeout=10)
        text = app.screen.text()
        checks("localhost" in text, "verification failure names the destination")
        # Select the newest failed CONNECT and open the inspector so the
        # actionable verification reason is part of the evidence.
        app.key(b"\x1b[H", "\r", b"\x1b[C")
        failure_view = app.wait_stable()
        app.capture(captures, "08_upstream_verify_failure", keep_png)
        if width >= 100:
            checks(
                "upstream TLS verification" in " ".join(failure_view.split()),
                "inspector exposes the upstream verification failure reason",
            )

        # A client that does not trust the local CA must fail the TLS handshake.
        sock, status, _ = connect_tunnel(proxy_port, "localhost", good.port)
        checks(status == 200, "intercepted CONNECT established for client-handshake test")
        handshake_failed = False
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.set_alpn_protocols(["http/1.1"])
            tls = context.wrap_socket(sock, server_hostname="localhost")
            tls.close()
        except ssl.SSLError:
            handshake_failed = True
            sock.close()
        checks(handshake_failed, "untrusted client fails the interception TLS handshake")
        app.wait_for("Client TLS", timeout=10)
        app.capture(captures, "09_client_tls_handshake_failure", keep_png)

        # Disable through Settings; a new CONNECT must be opaque again.
        disable_tls(app)
        app.wait_for("TLS interception disabled", timeout=10)
        goto_proxy(app)
        status, body = https_get(proxy_port, good.port, "/after-disable", pki["ca_cert"])
        checks(status == 200 and b"origin:/after-disable" in body, "opaque HTTPS works after disable")
        app.wait_for("TUNNEL", timeout=10)
        time.sleep(0.6)
        app.pump(0.4)
        text = app.screen.text()
        checks("/after-disable" not in text, "new post-disable CONNECT is not decrypted into the queue")
        app.capture(captures, "10_new_connect_opaque_after_disable", keep_png)

        # No CA private key was ever present in terminal output.
        raw = bytes(app.raw)
        checks(b"PRIVATE KEY" not in raw, "PTY output never contained private key material")
        return checks.count
    finally:
        app.stop()
        good.close()
        bad.close()
        shutil.rmtree(work, ignore_errors=True)


def run_invalid_ca(
    binary: Path, width: int, height: int, captures: Path | None, keep_png: bool
) -> int:
    checks = Checks()
    work = Path(tempfile.mkdtemp(prefix="rawframe-tui-badca-"))
    ca_dir = work / "ca"
    ca_dir.mkdir()
    cert = ca_dir / "rawframe-ca.crt.pem"
    key = ca_dir / "rawframe-ca.key.pem"
    cert.write_text("not a certificate\n")
    key.write_text("not a key\n")
    cert_before = cert.read_bytes()
    key_before = key.read_bytes()
    proxy_port = free_port()
    app = PtyApp(
        binary=binary,
        args=[
            "--bind",
            "127.0.0.1",
            "--port",
            str(proxy_port),
            "--tls-ca-dir",
            str(ca_dir),
            "--scope",
            "https://localhost:1",
            "--no-mouse",
            "--log-file",
            str(work / "rawframe.log"),
        ],
        width=width,
        height=height,
        cwd=REPO,
    )
    try:
        app.start()
        app.wait_for("RAWFRAME")
        app.key("p")
        app.wait_for("LISTENING", timeout=15)
        enable_tls(app)
        app.wait_for("could not be enabled", timeout=10)
        text = app.screen.text()
        checks("TLS interception" in text and "OFF" in text, "invalid CA leaves interception off")
        checks("PRIVATE KEY" not in text, "invalid CA error shows no key material")
        checks(cert.read_bytes() == cert_before, "invalid CA certificate is not replaced")
        checks(key.read_bytes() == key_before, "invalid CA key is not replaced")
        app.capture(captures, "11_invalid_ca_not_replaced", keep_png)
        return checks.count
    finally:
        app.stop()
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(REPO / "target/debug/rawframe"))
    parser.add_argument(
        "--sizes",
        default="140x40,100x30,80x24",
        help="comma-separated COLSxROWS PTY sizes",
    )
    parser.add_argument(
        "--captures-dir",
        default=str(REPO / "docs/screenshots/tls"),
        help="directory for genuine terminal frames (empty string disables)",
    )
    parser.add_argument("--no-png", action="store_true")
    parser.add_argument("--invalid-ca-only", action="store_true")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    if not binary.exists():
        print(f"binary not found: {binary}", file=sys.stderr)
        return 2
    if x509 is None:
        print("python cryptography module is required", file=sys.stderr)
        return 2
    captures = Path(args.captures_dir) if args.captures_dir else None

    total = 0
    for size in args.sizes.split(","):
        width, height = (int(value) for value in size.lower().split("x"))
        print(f"== PTY {width}x{height} ==")
        if not args.invalid_ca_only:
            total += run_flow(binary, width, height, captures, not args.no_png)
        total += run_invalid_ca(binary, width, height, captures, not args.no_png)
    print(f"ALL PASS ({total} checks)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)

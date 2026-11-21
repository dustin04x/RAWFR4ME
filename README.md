# RAWFRAME

Terminal-native HTTP interception and security testing workbench.

[![Mintlify Docs](https://img.shields.io/badge/docs-mintlify-8B5CF6?style=for-the-badge)](https://rawframe.mintlify.site)
[![License: MIT](https://img.shields.io/badge/License-MIT-8B5CF6?style=for-the-badge)](https://github.com/dustin04x/RAWFR4ME/blob/main/LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.89+-8B5CF6?style=for-the-badge)](https://www.rust-lang.org)
[![GitHub](https://img.shields.io/badge/GitHub-rawframe-8B5CF6?style=for-the-badge)](https://github.com/dustin04x/RAWFR4ME)

**Current release: 1.0.0** — the first stable release. See [CHANGELOG.md](CHANGELOG.md).

RAWFRAME is an open-source Rust workspace for authorized HTTP/1.1, HTTP/2, and WebSocket testing from the terminal. It provides a local forward proxy, opaque HTTPS tunnelling, opt-in TLS interception, durable SQLite history, and a live request workbench inside a keyboard-driven TUI.

**Intended only for systems you own or are explicitly authorized to test.**

## Quick start

```bash
# Terminal 1: a local upstream
python3 -m http.server 8000 --bind 127.0.0.1

# Terminal 2: RAWFRAME, authorizing only this local upstream
rawframe --port 8080 --scope http://127.0.0.1:8000 --allow-private-upstreams

# Terminal 3: send a request through the proxy
curl --noproxy '' -x http://127.0.0.1:8080 http://127.0.0.1:8000/
```

Press `P` on the Proxy workspace to start.

## Installation

### Prebuilt releases

Linux x86_64 builds are attached to each [GitHub Release](https://github.com/dustin04x/RAWFR4ME/releases/download/v1.0.0/):

```bash
curl -LO https://github.com/dustin04x/RAWFR4ME/releases/download/v1.0.0/rawframe-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/dustin04x/RAWFR4ME/releases/download/v1.0.0/rawframe-v1.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum --check rawframe-v1.0.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf rawframe-v1.0.0-x86_64-unknown-linux-gnu.tar.gz
install -m 755 rawframe ~/.local/bin/rawframe
```

### Build from source

```bash
git clone https://github.com/dustin04x/RAWFR4ME.git
cd RAWFR4ME
cargo build --workspace --release
./target/release/rawframe --version
```

## 📚 Docs

Full documentation is available at **[https://rawframe.mintlify.site](https://rawframe.mintlify.site)** — a professional Mintlify site with 237 pages covering all RAWFRAME features, architecture, security model, CLI reference, and user guides.

### Quick navigation

| Section | What you'll find |
| --- | --- |
| [Overview](https://rawframe.mintlify.site) | Project summary and quick-start |
| [Getting Started](https://rawframe.mintlify.site/getting-started) | Installation, first proxy session, and basics |
| [Core Concepts](https://rawframe.mintlify.site/core-concepts) | Proxy architecture, TLS interception, scope policies |
| [Features](https://rawframe.mintlify.site/features) | Proxy, Repeater, Intruder, Decoder, WebSocket |
| [Security](https://rawframe.mintlify.site/security) | Threat model, default-deny, TLS trust, redaction |
| [Architecture](https://rawframe.mintlify.site/architecture) | Nine-crate workspace, dependency flow, request lifecycle |
| [Configuration](https://rawframe.mintlify.site/configuration) | CLI flags, environment variables, terminal behavior |
| [CLI Reference](https://rawframe.mintlify.site/cli) | All options, subcommands, exit codes, keyboard shortcuts |
| [Troubleshooting](https://rawframe.mintlify.site/troubleshooting) | Common issues, fixes, and FAQ |
| [Reference](https://rawframe.mintlify.site/reference) | Glossary, data formats, error reference, version history |

### Mintlify site features

- 🎨 **Maple theme** with graphite surfaces and violet accent (`#8B5CF6`)
- 📱 **Responsive** — works on mobile, tablet, and desktop
- 🔍 **Full-text search** across all 237 pages
- 🌓 **Light & dark themes** with automatic color adaptation
- 📚 **Keyboard navigation** — `Cmd/Ctrl + K` for command palette
- 📄 **Export** — JSON Lines, Markdown, and HTML exports
- 🔗 **Deep links** — share exact pages with anyone

---

## Usage examples

**Persisted history**

```bash
# Default database
rawframe --scope http://127.0.0.1:8000 --allow-private-upstreams

# A named database and session
rawframe --db ./engagement.db --project acme --session-name baseline

# Export as redacted JSON Lines
rawframe --db ~/.local/share/rawframe/rawframe.db --export-history ./engagement-history.jsonl
```

**Repeater**

1. Start with explicit scope: `rawframe --scope http://127.0.0.1:8000 --allow-private-upstreams`
2. Press `Ctrl+3`, then `Enter`/`E` to edit the request line
3. Press `Ctrl+Enter` or `S` to send; `C` cancels
4. `1`–`6` switch Raw, Headers, Body, Pretty JSON, Hex, and Compare views

**Intruder**

1. Capture or open a request, then press `I` to send it to Intruder
2. In Setup press `M` to wrap a value in `§…§`, enable/disable positions with `Space`
3. Choose a strategy and press `Ctrl+Enter` to confirm — nothing sends before you confirm

## License

MIT. See [LICENSE](LICENSE).
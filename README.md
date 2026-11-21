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

## Docs

Full documentation is available at **[https://rawframe.mintlify.site](https://rawframe.mintlify.site)** — a professional Mintlify site with 237 pages covering all RAWFRAME features, architecture, security model, CLI reference, and user guides.

## License

MIT. See [LICENSE](LICENSE).
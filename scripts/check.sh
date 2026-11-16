#!/usr/bin/env bash
# RAWFRAME quality gate. Run from the repository root.
set -euo pipefail

cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

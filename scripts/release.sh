#!/usr/bin/env bash
set -e

# Crates to be published. Order is significant; later crates can only rely on earlier crates
CRATE_DIRS=(proto tink prf mac aead daead streaming signature integration/awskms rinkey)

# Release crates in dependency order. Assumes `cargo login` has been done.
for dir in "${CRATE_DIRS[@]}"; do
    cargo release --manifest-path "$dir/Cargo.toml"
done

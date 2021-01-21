#!/usr/bin/env bash
set -e

# Crates to be published. Order is significant; later crates can only rely on earlier crates
CRATE_DIRS=(proto core prf mac aead daead streaming signature integration/awskms integration/gcpkms rinkey)

# Release crates in dependency order. Assumes `cargo login` has been done.
for dir in "${CRATE_DIRS[@]}"; do
    cargo publish --manifest-path "$dir/Cargo.toml"
done

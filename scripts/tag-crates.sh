#!/usr/bin/env bash
set -e

# Retrieve the crate name from a directory.
function crate_name() {
    local dir="$1"
    grep name "$dir/Cargo.toml" | sed 's/name = "\(.*\)"/\1/'
}

# Retrieve the crate version from a directory.
function crate_version() {
    local dir="$1"
    grep -E "^version" "$dir/Cargo.toml" | sed 's/version = "\(.*\)"/\1/'
}

# Add tags for all released crates based on version field in Cargo.toml
RELEASED_CRATE_DIRS=(proto core prf mac aead daead streaming signature integration/awskms integration/gcpkms rinkey)
for dir in "${RELEASED_CRATE_DIRS[@]}"; do
    crate_name=$(crate_name "$dir")
    crate_version=$(crate_version "$dir")
    crate_tag="${crate_name}-${crate_version}"
    echo "Add tag $crate_tag"
    git tag "$crate_tag"
done

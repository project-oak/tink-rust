#!/usr/bin/env bash
set -e

VERSION="$1"
DEP_VERSION="$2"
if [ "$VERSION" == "" ] || [ "$DEP_VERSION" == "" ]; then
    echo "Usage: rev-up.sh <new_version> <version_dep>"
    exit 1
fi

# Retrieve the crate name from a directory.
function crate_name() {
    local dir="$1"
    grep name "$dir/Cargo.toml" | sed 's/name = "\(.*\)"/\1/'
}

# All available crates.
CRATE_DIRS=(proto core prf mac aead daead streaming signature integration/awskms integration/gcpkms rinkey tests testing examples/aead examples/daead examples/keygen examples/keymgr examples/kms examples/mac examples/signature examples/streaming)

for dir in "${CRATE_DIRS[@]}"; do
    echo "Update $dir to $VERSION"

    sed -i '.orig' "s/^version = \".*\"$/version = \"$VERSION\"/" "$dir/Cargo.toml"
    sed -i '.orig' "s/^tink\(.*\) = \"^.*\"$/tink\1 = \"^$DEP_VERSION\"/" "$dir/Cargo.toml"
    sed -i '.orig' "s/^tink-core = { version = \"^[^\"]*\",\(.*\)$/tink-core = { version = \"^$DEP_VERSION\",\1/" "$dir/Cargo.toml"
    rm "$dir/Cargo.toml.orig"

    git add "$dir/Cargo.toml"
done

cargo clippy --all-targets
git add Cargo.lock

git commit -m "Update crate versions to $VERSION"
git tag "v$VERSION"

# Also add tags for all released crates (in case they move independently)
RELEASED_CRATE_DIRS=(proto core prf mac aead daead streaming signature integration/awskms integration/gcpkms rinkey)
for dir in "${RELEASED_CRATE_DIRS[@]}"; do
    crate_name=$(crate_name "$dir")
    crate_tag="${crate_name}-${VERSION}"
    echo "Add tag $crate_tag"
    git tag "$crate_tag"
done

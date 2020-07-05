#!/usr/bin/env bash
# Copyright 2020 The Tink-Rust Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o xtrace
set -o pipefail

# Update the gh-pages branch. Note that `cargo doc` is **not deterministic** so
# this should only be done when there is a real change.
readonly RUST_BRANCH=${1:-main}
readonly RUST_GH_BRANCH=gh-pages

if [ -z "${FORCE+x}" ]; then
  readonly PREV_COMMIT=$(git log --oneline -n 1 ${RUST_GH_BRANCH} | sed 's/.*branch at \([0-9a-f]*\)/\1/')
  readonly CHANGES=$(git diff "${PREV_COMMIT}..${RUST_BRANCH}" | grep -e '[+-]//[/!]')

  if [ -z "${CHANGES}" ]; then
    echo "No doc comment changes found in ${PREV_COMMIT}..${RUST_BRANCH} subdir rust/"
    exit 0
  fi
fi

git switch "${RUST_BRANCH}"
readonly RUST_BRANCH_SHA1=$(git rev-parse --short HEAD)
readonly RUST_BRANCH_SUBJECT=$(git log -n 1 --format=format:%s)
readonly COMMIT_MESSAGE=$(cat <<-END
Update Rust docs to ${RUST_BRANCH} branch at ${RUST_BRANCH_SHA1}

Auto-generated from commit ${RUST_BRANCH_SHA1} ("${RUST_BRANCH_SUBJECT}").
END
)

readonly TGZ_FILE="/tmp/tink-rust-doc-${RUST_BRANCH_SHA1}.tgz"
# Build Cargo docs and save them off outside the repo
(
    rm -rf target/doc
    cargo doc --no-deps
    cargo deadlinks
    cd target/doc || exit
    tar czf "${TGZ_FILE}" ./*
)

# Shift to ${RUST_GH_BRANCH} branch and replace contents of (just) ./rust/
git switch ${RUST_GH_BRANCH}

readonly DOC_DIR=rust
rm -rf ${DOC_DIR}
mkdir ${DOC_DIR}
(
    cd "${DOC_DIR}" || exit
    tar xzf "${TGZ_FILE}"
)

# Commit any differences
git add "${DOC_DIR}"
git commit --message="${COMMIT_MESSAGE}"
git switch "${RUST_BRANCH}"

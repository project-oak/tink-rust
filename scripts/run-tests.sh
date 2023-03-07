#!/bin/bash
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
set -o xtrace

realpath() {
    [[ $1 = /* ]] && echo "$1" || echo "$PWD/${1#./}"
}

readonly SCRIPTS_DIR=$(realpath "$(dirname "$0")")
readonly TINK_RUST_DIR=${TINK_RUST_DIR:-${SCRIPTS_DIR}/..}

# Location of upstream Tink testing directory.
readonly TINK_TESTING_DIR=${TINK_TESTING_DIR:-${SCRIPTS_DIR}/../../tink/testing}


echo "Upstream Tink testing code expected in ${TINK_TESTING_DIR}"
echo "Tink Rust code expected in ${TINK_RUST_DIR}"

cargo build --package=tink-testing-server

cd "${TINK_TESTING_DIR}/cross_language"
(
    cd ../cc
    bazel build --copt="-Wno-error=array-parameter" --copt="-Wno-error=stringop-overflow" :testing_server
    cd ../go
    bazel build :testing_server
    cd ../java_src
    bazel build :testing_server :testing_server_deploy.jar
    cd ../python
    bazel build --copt="-Wno-error=array-parameter" --copt="-Wno-error=stringop-overflow" :testing_server
)

bazel test \
      --copt="-Wno-error=array-parameter" --copt="-Wno-error=stringop-overflow" \
      --cache_test_results=no --test_output=errors \
      :aead_test \
      :aead_consistency_test \
      :deterministic_aead_test \
      :key_generation_consistency_test \
      :key_version_test \
      :hybrid_encryption_test \
      :json_test \
      :mac_test \
      :prf_set_test \
      :signature_test \
      :streaming_aead_test \
      --test_env testing_dir="${TINK_TESTING_DIR}" \
      --test_env TINK_RUST_DIR="${TINK_RUST_DIR}" \
      --test_env TINK_SRC_PATH="${TINK_TESTING_DIR}/.." \
      "$@"

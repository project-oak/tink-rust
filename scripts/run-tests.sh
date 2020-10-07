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

readonly SCRIPTS_DIR="$(dirname "$0")"

# Location of upstream Tink repo.
readonly TINK_DIR=${TINK_DIR:-${SCRIPTS_DIR}/../../tink}

cargo build --package=tink-testing-server

cd ${TINK_DIR}/testing/cross_language
(
    cd ../cc
    bazel build :testing_server
    cd ../go
    bazel build :testing_server
    cd ../java_src
    bazel build :testing_server :testing_server_deploy.jar
    cd ../python
    bazel build :testing_server
)

bazel test --cache_test_results=no \
      :aead_test \
      :aead_consistency_test \
      :deterministic_aead_test \
      :key_generation_consistency_test \
      :json_test \
      :mac_test \
      :prf_set_test \
      :signature_test \
      --test_env testing_dir=${PWD}/.. \
      $@

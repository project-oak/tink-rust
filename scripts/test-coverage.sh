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

export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=0 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"

cargo build --all --exclude tink-testing-server
cargo test --all --exclude tink-testing-server

grcov ./target/debug/ \
      --source-dir=. \
      --ignore-not-existing \
      --excl-line="(panic!|unreachable!|#\\[derive\\()" \
      --excl-start=LCOV_EXCL_START \
      --excl-stop=LCOV_EXCL_STOP \
      --output-type=lcov \
      --output-path=./target/debug/lcov.info

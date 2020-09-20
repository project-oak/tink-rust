// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

use std::{env, path::PathBuf};

// Environment variable names that are expected to contain key URI and credentials file information.
const KEY_URI_ENV: &str = "TINK_GCP_TEST_KEY_URI";
const CRED_FILE_ENV: &str = "TINK_GCP_TEST_CREDENTIALS";

// Default values for key URI and credentials file.
const DEFAULT_KEY_URI: &str = "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key";
const DEFAULT_CRED_FILE: &str = "../../testdata/credential.json";

pub fn key_uri() -> String {
    match env::var(KEY_URI_ENV) {
        Ok(val) => val,
        Err(_) => DEFAULT_KEY_URI.to_string(),
    }
}

pub fn cred_file() -> PathBuf {
    match env::var(CRED_FILE_ENV) {
        Ok(val) => PathBuf::from(val),
        Err(_) => [env!("CARGO_MANIFEST_DIR"), DEFAULT_CRED_FILE]
            .iter()
            .collect(),
    }
}

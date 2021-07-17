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

use serde::Deserialize;

#[derive(Deserialize)]
pub struct AeadTest {
    #[serde(flatten)]
    pub case: tink_tests::WycheproofCase,
    #[serde(with = "tink_tests::hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub iv: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub aad: Vec<u8>,
    #[serde(rename = "msg", with = "tink_tests::hex_string")]
    pub message: Vec<u8>,
    #[serde(rename = "ct", with = "tink_tests::hex_string")]
    pub ciphertext: Vec<u8>,
    pub tag: String,
}

#[derive(Deserialize)]
pub struct AeadGroup {
    #[serde(flatten)]
    pub group: tink_tests::WycheproofGroup,
    pub tests: Vec<AeadTest>,
}

#[derive(Deserialize)]
struct AeadSuite {
    #[serde(flatten)]
    pub suite: tink_tests::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<AeadGroup>,
}

#[test]
fn test_wycheproof_parsing() {
    let bytes = tink_tests::wycheproof_data("testvectors/aes_gcm_test.json");
    let suite: AeadSuite = serde_json::from_slice(&bytes).unwrap();

    assert_eq!("AES-GCM", suite.suite.algorithm);
    assert!(!suite.test_groups[0].tests[0].key.is_empty());
}

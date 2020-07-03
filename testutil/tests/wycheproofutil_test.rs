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

#[test]
fn test_wycheproof_parsing() {
    #[derive(Deserialize)]
    struct AeadTest {
        #[serde(flatten)]
        pub case: tink_testutil::WycheproofCase,
        pub key: String,
        pub iv: String,
        pub aad: String,
        #[serde(rename = "msg")]
        pub message: String,
        #[serde(rename = "ct")]
        pub ciphertext: String,
        pub tag: String,
    }

    #[derive(Deserialize)]
    struct AeadGroup {
        #[serde(flatten)]
        pub group: tink_testutil::WycheproofGroup,
        pub tests: Vec<AeadTest>,
    }

    #[derive(Deserialize)]
    struct AeadSuite {
        #[serde(flatten)]
        pub suite: tink_testutil::WycheproofSuite,
        #[serde(rename = "testGroups")]
        pub test_groups: Vec<AeadGroup>,
    }

    let bytes = tink_testutil::wycheproof_data("testvectors/aes_gcm_test.json");
    let suite: AeadSuite = serde_json::from_slice(&bytes).unwrap();

    assert_eq!("AES-GCM", suite.suite.algorithm);
    assert!(!suite.test_groups[0].tests[0].key.is_empty());
}

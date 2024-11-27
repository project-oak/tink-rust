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

//! Helpers for retrieving Wycheproof test vectors.

use serde::Deserialize;

/// `WycheproofSuite` represents the common elements of the top level object in a Wycheproof json
/// file.
///
/// Implementations should embed (using `#[serde(flatten)]`) `WycheproofSuite` in a struct
/// that strongly types the `testGroups` field.  See tests/wycheproofutil_test.rs for an example.
#[derive(Debug, Deserialize)]
pub struct WycheproofSuite {
    pub algorithm: String,
    #[serde(rename = "generatorVersion")]
    pub generator_version: String,
    #[serde(rename = "numberOfTests")]
    pub number_of_tests: i32,
    pub notes: std::collections::HashMap<String, String>,
}

/// `WycheproofGroup` represents the common elements of a testGroups object in a Wycheproof suite.
///
/// Implementations should embed (using `#[serde(flatten)]`) WycheproofGroup in a struct that
/// strongly types its list of cases.  See tests/wycheproofutil_test.rs for an example.
#[derive(Debug, Deserialize)]
pub struct WycheproofGroup {
    #[serde(rename = "type")]
    pub group_type: String,
}

/// `WycheproofResult` represents the possible result values for a Wycheproof test case.
#[derive(Debug, PartialEq, Eq)]
pub enum WycheproofResult {
    /// Test case is valid, the crypto operation should succeed.
    Valid,
    /// Test case is invalid; the crypto operation should fail.
    Invalid,
    /// Test case is valid, but uses weak parameters; the crypto operation might succeed
    /// or fail depending on how strict the library is.
    Acceptable,
}

impl std::fmt::Display for WycheproofResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                WycheproofResult::Valid => "valid",
                WycheproofResult::Invalid => "invalid",
                WycheproofResult::Acceptable => "acceptable",
            }
        )
    }
}

/// `WycheproofCase` represents the common elements of a tests object in a Wycheproof group.
///
/// Implementations should embed (using `#[serde(flatten)]`) `WycheproofCase` in a struct that
/// contains fields specific to the test type.  See tests/wycheproofutil_test.rs for an example.
#[derive(Debug, Deserialize)]
pub struct WycheproofCase {
    #[serde(rename = "tcId")]
    pub case_id: i32,
    pub comment: String,
    #[serde(with = "wycheproof_result")]
    pub result: WycheproofResult,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// Retrieve Wycheproof test vectors from the given filename.
///
/// The location of the Wycheproof repository is assumed to be "../wycheproof/" relative to the
/// crate manifest file, but this can be overridden with the the `WYCHEPROOF_DIR` environment
/// variable.
pub fn wycheproof_data(filename: &str) -> Vec<u8> {
    let wycheproof_dir = match std::env::var("WYCHEPROOF_DIR") {
        Ok(d) => d,
        Err(_) => concat!(env!("CARGO_MANIFEST_DIR"), "/../wycheproof").to_string(),
    };
    std::fs::read(std::path::Path::new(&wycheproof_dir).join(filename)).unwrap_or_else(|_| {
        panic!(
            "Test vector file {} not found under $WYCHEPROOF_DIR={}; `git submodule update --init` needed?",
            filename, wycheproof_dir
        )
    })
}

pub mod hex_string {
    //! Manual JSON deserialization for hex strings.
    use serde::Deserialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        ::hex::decode(&s).map_err(|_e| {
            serde::de::Error::invalid_value(serde::de::Unexpected::Str(&s), &"hex data expected")
        })
    }
}

pub mod wycheproof_result {
    //! Manual JSON deserialization for a `result` enum.
    use serde::Deserialize;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<super::WycheproofResult, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.as_ref() {
            "valid" => Ok(super::WycheproofResult::Valid),
            "invalid" => Ok(super::WycheproofResult::Invalid),
            "acceptable" => Ok(super::WycheproofResult::Acceptable),
            _ => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Str(&s),
                &"unexpected result value",
            )),
        }
    }
}

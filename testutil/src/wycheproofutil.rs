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
/// file.  Implementations should embed (using `#[serde(flatten)]`) `WycheproofSuite` in a struct
/// that strongly types the `testGroups` field.  See tests/wycheproofutil_test.go for an example.
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
/// Implementations should embed (using `#[serde(flatten)]`) WycheproofGroup in a struct that
/// strongly types its list of cases.  See tests/wycheproofutil_test.go for an example.
#[derive(Debug, Deserialize)]
pub struct WycheproofGroup {
    #[serde(rename = "type")]
    pub group_type: String,
}

/// `WycheproofCase` represents the common elements of a tests object in a Wycheproof group.
/// Implementations should embed (using `#[serde(flatten)]`) `WycheproofCase` in a struct that
/// contains fields specific to the test type.  See tests/wycheproofutil_test.go for an example.
#[derive(Debug, Deserialize)]
pub struct WycheproofCase {
    #[serde(rename = "tcId")]
    pub case_id: i32,
    pub comment: String,
    pub result: String,
    #[serde(default)]
    pub flags: Vec<String>,
}

/// Retrieve Wycheproof test vectors from the given filename, assuming that
/// the location of the Wycheproof repository is given by the `WYCHEPROOF_DIR`
/// environment variable.
pub fn wycheproof_data(filename: &str) -> Vec<u8> {
    let wycheproof_dir = std::env::var("WYCHEPROOF_DIR")
        .expect("**TEST VECTORS NOT FOUND**: Please set WYCHEPROOF_DIR to the location of the Wycheproof repo.");
    std::fs::read(std::path::Path::new(&wycheproof_dir).join(filename)).unwrap_or_else(|_| {
        panic!(
            "Test vector file {} not found under $WYCHEPROOF_DIR={}",
            filename, wycheproof_dir
        )
    })
}

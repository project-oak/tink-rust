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

//! Common structures for AEAD Wycheproof test vectors.

use serde::Deserialize;
use tink_tests::hex_string;

#[derive(Debug, Deserialize)]
pub struct TestData {
    #[serde(flatten)]
    pub suite: tink_tests::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TestGroup {
    #[serde(flatten)]
    pub group: tink_tests::WycheproofGroup,
    #[serde(rename = "ivSize")]
    pub iv_size: u32,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    #[serde(rename = "tagSize")]
    pub tag_size: u32,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
pub struct TestCase {
    #[serde(flatten)]
    pub case: tink_tests::WycheproofCase,
    #[serde(with = "hex_string")]
    pub aad: Vec<u8>,
    #[serde(with = "hex_string")]
    pub ct: Vec<u8>,
    #[serde(with = "hex_string")]
    pub iv: Vec<u8>,
    #[serde(with = "hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "hex_string")]
    pub tag: Vec<u8>,
}

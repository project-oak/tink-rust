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

use lazy_static::lazy_static;
use maplit::hashmap;
use serde::Deserialize;
use std::collections::HashMap;
use tink_core::{subtle::random::get_random_bytes, Mac};

// Test vectors from RFC 4493.
const KEY_RFC4493: &[u8] = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
const DATA_RFC4493: &[u8] = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a\xae\x2d\x8a\x57\x1e\x03\xac\x9c\x9e\xb7\x6f\xac\x45\xaf\x8e\x51\x30\xc8\x1c\x46\xa3\x5c\xe4\x11\xe5\xfb\xc1\x19\x1a\x0a\x52\xef\xf6\x9f\x24\x45\xdf\x4f\x9b\x17\xad\x2b\x41\x7b\xe6\x6c\x37\x10";
lazy_static! {
    // An entry (l, e) in this map implies that a MAC of the first l bytes of DATA_RFC4493 (with key KEY_RFC4493) should
    // give output e.
    static ref EXPECTED: HashMap<usize, &'static str> = hashmap! {
        0 =>  "bb1d6929e95937287fa37d129b756746",
        16 => "070a16b46b4d4144f79bdd9dd04a287c",
        40 => "dfa66747de9ae63030ca32611497c827",
        64 => "51f0bebf7e3b9d92fc49741779363cfe",
    };
}

#[allow(dead_code)]
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
    #[serde(with = "tink_tests::hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub tag: Vec<u8>,
}

#[test]
fn test_vectors_wycheproof() {
    let filename = "testvectors/aes_cmac_test.json";
    println!("wycheproof file '{filename}'");
    let bytes = tink_tests::wycheproof_data(filename);
    let data: TestData = serde_json::from_slice(&bytes).unwrap();

    for g in &data.test_groups {
        println!(
            "   key info: key_size={}, tag_size={}",
            g.key_size, g.tag_size
        );
        for tc in &g.tests {
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            assert_eq!(tc.key.len() * 8, g.key_size as usize);
            assert_eq!(
                g.tag_size % 8,
                0,
                "Requested tag size for test case {} ({}) is not a multiple of 8, but {}",
                tc.case.case_id,
                tc.case.comment,
                g.tag_size
            );

            let valid = tc.case.result == tink_tests::WycheproofResult::Valid;
            let aes = match tink_mac::subtle::AesCmac::new(&tc.key, g.tag_size as usize / 8) {
                Err(e) => {
                    if valid {
                        panic!(
                            "Could not create AesCmac for test case {} ({}): {:?}",
                            tc.case.case_id, tc.case.comment, e
                        );
                    } else {
                        continue;
                    }
                }
                Ok(aes) => aes,
            };
            let res = aes.compute_mac(&tc.msg);
            if valid {
                assert!(
                    res.is_ok(),
                    "Could not compute AES-CMAC for test case {} ({})",
                    tc.case.case_id,
                    tc.case.comment,
                );
                assert_eq!(
                    res.unwrap(),
                    tc.tag,
                    "Computed AES-CMAC and expected for test case {} ({}) do not match",
                    tc.case.case_id,
                    tc.case.comment,
                );
            } else if res.is_ok() {
                assert_ne!(
                    res.unwrap(),
                    tc.tag,
                    "Compute AES-CMAC and invalid expected for test case {} ({}) match",
                    tc.case.case_id,
                    tc.case.comment
                );
            }
            let result = aes.verify_mac(&tc.tag, &tc.msg);
            if valid && result.is_err() {
                panic!(
                    "Could not verify MAC for test case {} ({})",
                    tc.case.case_id, tc.case.comment,
                );
            }
            if !valid && result.is_ok() {
                panic!(
                    "Verified invalid MAC for test case {} ({})",
                    tc.case.case_id, tc.case.comment
                );
            }
        }
    }
}

#[test]
fn test_cmac_basic() {
    let a = tink_mac::subtle::AesCmac::new(KEY_RFC4493, 16).unwrap();
    for (l, e) in EXPECTED.iter() {
        let output = a
            .compute_mac(&DATA_RFC4493[..*l])
            .expect("Error computing AES-CMAC");
        assert_eq!(
            hex::encode(output),
            *e,
            "Computation and test vector differ."
        );
        let exp = hex::decode(e).expect("Could not decode expected string");
        a.verify_mac(&exp, &DATA_RFC4493[..*l])
            .unwrap_or_else(|_| panic!("Verification of test vector {} failed", e));
    }
}

#[test]
fn test_new_cmac_with_invalid_input() {
    // key too short
    assert!(
        tink_mac::subtle::AesCmac::new(&get_random_bytes(1), 16).is_err(),
        "expect an error when key is too short"
    );
    // tag too short
    assert!(
        tink_mac::subtle::AesCmac::new(&get_random_bytes(16), 9).is_err(),
        "expect an error when tag size is too small"
    );
    // tag too big
    assert!(
        tink_mac::subtle::AesCmac::new(&get_random_bytes(16), 17).is_err(),
        "expect an error when tag size is too big"
    );
}

#[test]
fn test_cmac_compute_verify_with_empty_input() {
    let cipher = tink_mac::subtle::AesCmac::new(&get_random_bytes(16), 16).unwrap();
    let tag = cipher.compute_mac(&[]).unwrap();
    assert!(cipher.verify_mac(&tag, &[]).is_ok());
}

#[test]
fn test_cmac_verify_mac_with_invalid_input() {
    let cipher = tink_mac::subtle::AesCmac::new(&get_random_bytes(16), 16).unwrap();
    assert!(
        cipher.verify_mac(&[], &[0x01]).is_err(),
        "expect an error when mac is empty"
    );
    assert!(
        cipher.verify_mac(&[0x01], &[]).is_err(),
        "expect an error when data is empty"
    );
    assert!(cipher.verify_mac(&[], &[]).is_err());
}

#[test]
fn test_cmac_modification() {
    let a = tink_mac::subtle::AesCmac::new(KEY_RFC4493, 16).unwrap();
    for (l, e) in EXPECTED.iter() {
        let exp = hex::decode(e).expect("Could not decode expected string");
        for i in 0..exp.len() {
            for j in 0..8u8 {
                let mut not_expected = vec![0u8; 16];
                not_expected.copy_from_slice(&exp);
                not_expected[i] ^= 1 << j;
                assert!(a.verify_mac(&not_expected, &DATA_RFC4493[..*l]).is_err(),
                            "Verification of modified test vector did not fail. Test Vector {}, Modified: {}", e, hex::encode(not_expected));
            }
        }
    }
}

#[test]
fn test_cmac_truncation() {
    let a = tink_mac::subtle::AesCmac::new(KEY_RFC4493, 16).unwrap();
    for (l, e) in EXPECTED.iter() {
        let exp = hex::decode(e).expect("Could not decode expected string");
        for i in 1..exp.len() {
            let not_expected = &exp[..i];
            assert!(
                a.verify_mac(not_expected, &DATA_RFC4493[..*l]).is_err(),
                "Verification of truncated test vector did not fail. Test Vector {}, Modified: {}",
                e,
                hex::encode(not_expected)
            );
        }
    }
}

#[test]
fn test_cmac_smaller_tag_size() {
    for i in 10..=16usize {
        let a = tink_mac::subtle::AesCmac::new(KEY_RFC4493, i).unwrap();
        for (l, e) in EXPECTED.iter() {
            let exp = hex::decode(e).expect("Could not decode expected string");
            assert!(
                a.verify_mac(&exp[..i], &DATA_RFC4493[..*l]).is_ok(),
                "Verification of smaller tag test vector did fail. Test Vector {} i={} l={}",
                hex::encode(exp),
                i,
                l
            );
        }
    }
}

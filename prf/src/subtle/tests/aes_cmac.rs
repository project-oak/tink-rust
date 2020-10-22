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

use crate::subtle::AesCmacPrf;
use maplit::hashmap;
use serde::Deserialize;
use tink::Prf;

#[test]
fn test_vectors_rfc4493() {
    // Test vectors from RFC 4493.
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").expect("Could not decode key");
    let data= hex::decode("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710").expect("Could not decode data");
    let expected = hashmap! {
        0usize =>  "bb1d6929e95937287fa37d129b756746",
        16usize => "070a16b46b4d4144f79bdd9dd04a287c",
        40usize => "dfa66747de9ae63030ca32611497c827",
        64usize => "51f0bebf7e3b9d92fc49741779363cfe",
    };
    let a = AesCmacPrf::new(&key).expect("Could not create AesCmacPrf object");
    for (l, e) in expected {
        let output = a
            .compute_prf(&data[..l], 16)
            .expect("Error computing AES-CMAC");
        assert_eq!(
            hex::encode(output),
            e,
            "Computation and test vector differ."
        );
    }
}

#[derive(Debug, Deserialize)]
pub struct TestData {
    #[serde(flatten)]
    pub suite: tink_testutil::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
pub struct TestGroup {
    #[serde(flatten)]
    pub group: tink_testutil::WycheproofGroup,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    #[serde(rename = "tagSize")]
    pub tag_size: u32,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
pub struct TestCase {
    #[serde(flatten)]
    pub case: tink_testutil::WycheproofCase,
    #[serde(with = "tink_testutil::hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub tag: Vec<u8>,
}

#[test]
fn test_vectors_wycheproof() {
    let filename = "testvectors/aes_cmac_test.json";
    println!("wycheproof file '{}'", filename);
    let bytes = tink_testutil::wycheproof_data(filename);
    let data: TestData = serde_json::from_slice(&bytes).unwrap();

    for g in &data.test_groups {
        println!("   key info: key_size={}", g.key_size);
        for tc in &g.tests {
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            assert_eq!(tc.key.len() * 8, g.key_size as usize);

            let aes = AesCmacPrf::new(&tc.key);
            let valid = tc.case.result == tink_testutil::WycheproofResult::Valid;
            if valid && aes.is_err() {
                panic!(
                    "Could not create AesCmacPrf for test case {} ({})",
                    tc.case.case_id, tc.case.comment
                );
            }
            if !valid && aes.is_err() {
                continue;
            }
            assert_eq!(
                g.tag_size % 8,
                0,
                "Requested tag size for test case {} ({}) is not a multiple of 8, but {}",
                tc.case.case_id,
                tc.case.comment,
                g.tag_size
            );
            let res = match aes.unwrap().compute_prf(&tc.msg, (g.tag_size / 8) as usize) {
                Err(e) => {
                    assert!(
                        !valid,
                        "Could not compute AES-CMAC for test case {} ({}): {}",
                        tc.case.case_id, tc.case.comment, e
                    );
                    continue;
                }
                Ok(r) => r,
            };
            if valid {
                assert_eq!(
                    res, tc.tag,
                    "Computed AES-CMAC and expected for test case {} ({}) do not match",
                    tc.case.case_id, tc.case.comment
                );
            } else {
                assert_ne!(
                    res, tc.tag,
                    "Computed AES-CMAC and invalid expected for test case {} ({}) match",
                    tc.case.case_id, tc.case.comment
                )
            }
        }
    }
}

#[test]
fn test_validate_aes_cmac_prf_params() {
    assert!(
        crate::subtle::validate_aes_cmac_prf_params(32).is_ok(),
        "Unexpected error validating AES CMAC PRF Params"
    );
    assert!(
        crate::subtle::validate_aes_cmac_prf_params(2).is_err(),
        "Unexpected validation of too short key for AES CMAC PRF Params"
    );
}

#[test]
fn test_key_length() {
    assert!(
        AesCmacPrf::new(&[0x01, 0x02]).is_err(),
        "Expected NewAESCMACPRF to fail on short key"
    );
    assert!(
        AesCmacPrf::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10
        ])
        .is_ok(),
        "Expected NewAESCMACPRF to work on 16 byte key"
    );
    assert!(
        AesCmacPrf::new(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            0x0d, 0x0e, 0x0f, 0x10
        ])
        .is_ok(),
        "Expected NewAESCMACPRF to work on 32 byte key"
    );
}

#[test]
fn test_aes_cmac_prf_output_length() {
    let prf = AesCmacPrf::new(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ])
    .expect("Expected AesCmacPrf::new() to work on 32 byte key");
    for i in 0..=16usize {
        let output = prf.compute_prf(&[0x01, 0x02], i).unwrap_or_else(|_| {
            panic!(
                "Expected to be able to compute AES CMAC PRF with {} output length",
                i
            )
        });
        assert_eq!(
            output.len(),
            i,
            "Expected AES CMAC PRF to compute {} bytes, got {}",
            i,
            output.len()
        );
    }
    for i in 17..32usize {
        assert!(
            prf.compute_prf(&[0x01, 0x02], i).is_err(),
            "Expected not to be able to compute AES CMAC PRF with {} output length",
            i
        );
    }
}

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
use tink::{subtle::random::get_random_bytes, DeterministicAead};
use tink_testutil::WycheproofResult;

#[test]
fn test_aes_siv_encrypt_decrypt() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let msg = b"Some data to encrypt.";
    let aad = b"Additional data";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    let ct = a.encrypt_deterministically(msg, aad).unwrap();

    let pt = a
        .decrypt_deterministically(&ct, aad)
        .expect("Unexpected descryption error");
    assert_eq!(pt, msg, "Mismatched plaintexts");
}

#[test]
fn test_aes_siv_empty_plaintext() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let aad = b"Additional data";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    let ct = a
        .encrypt_deterministically(&[], aad)
        .expect("Unexpected encryption error");
    let pt = a
        .decrypt_deterministically(&ct, aad)
        .expect("Unexpected decryption error");
    assert!(pt.is_empty(), "Mismatched plaintexts");
}

#[test]
fn test_aes_siv_empty_additional_data() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    let ct = a
        .encrypt_deterministically(&[], &[])
        .expect("Unexpected encryption error");
    let pt = a
        .decrypt_deterministically(&ct, &[])
        .expect("Unexpected decryption error");
    assert!(pt.is_empty(), "Mismatched plaintexts");
}

#[test]
fn test_aes_siv_key_sizes() {
    let key_str =
        "198371900187498172316311acf81d238ff7619873a61983d619c87b63a1987f987131819803719b847126381cd763871638aa71638176328761287361231321812731321de508761437195ff231765aa4913219873ac6918639816312130011abc900bba11400187984719827431246bbab1231eb4145215ff7141436616beb9817298148712fed3aab61000ff123313e";
    let key = hex::decode(key_str).unwrap();

    for i in 0..key.len() {
        let result = tink_daead::subtle::AesSiv::new(&key[..i]);
        if i == tink_daead::subtle::AES_SIV_KEY_SIZE {
            assert!(
                result.is_ok(),
                "Rejected valid key size: {}, {:?}",
                i,
                result.err().unwrap()
            );
        } else {
            assert!(result.is_err(), "Allowed invalid key size: {}", i);
        }
    }
}

#[test]
fn test_aes_siv_message_sizes() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let aad = b"Additional data";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    for i in 0..1024 {
        let msg = get_random_bytes(i);
        let ct = a
            .encrypt_deterministically(&msg, aad)
            .expect("Unexpected encryption error");
        let pt = a
            .decrypt_deterministically(&ct, aad)
            .expect("Unexpected decryption error");
        assert_eq!(pt, msg, "Mismatched plaintexts");
    }

    for i in (1024..100000).step_by(5000) {
        let msg = get_random_bytes(i);
        let ct = a
            .encrypt_deterministically(&msg, aad)
            .expect("Unexpected encryption error");
        let pt = a
            .decrypt_deterministically(&ct, aad)
            .expect("Unexpected decryption error");
        assert_eq!(pt, msg, "Mismatched plaintexts");
    }
}

#[test]
fn test_aes_siv_additional_data_sizes() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let msg = b"Some data to encrypt.";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    for i in 0..1024 {
        let aad = get_random_bytes(i);
        let ct = a.encrypt_deterministically(msg, &aad).unwrap();
        let pt = a
            .decrypt_deterministically(&ct, &aad)
            .expect("Unexpected decryption error");
        assert_eq!(pt, msg, "Mismatched plaintexts");
    }
}

#[test]
fn test_aes_siv_ciphertext_modifications() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let aad = b"Additional data";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();

    for i in 0..50 {
        let msg = get_random_bytes(i);
        let mut ct = a.encrypt_deterministically(&msg, aad).unwrap();
        for j in 0..ct.len() {
            for b in 0..8 {
                ct[j] ^= 1 << b;
                assert!(
                    a.decrypt_deterministically(&ct, aad).is_err(),
                    "Modified ciphertext decrypted: byte {}, bit {}",
                    j,
                    b
                );
                ct[j] ^= 1 << b;
            }
        }
    }
}

#[test]
fn test_aes_siv_ciphertext_too_short() {
    let key_str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00112233445566778899aabbccddeefff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    let key = hex::decode(key_str).unwrap();
    let msg = b"Some data to encrypt.";
    let aad = b"additional data";

    let a = tink_daead::subtle::AesSiv::new(&key).unwrap();
    let ct = a.encrypt_deterministically(msg, aad).unwrap();

    let result = a.decrypt_deterministically(&ct[..2], aad);
    tink_testutil::expect_err(result, "too short");
}

#[derive(Debug, Deserialize)]
struct TestData {
    #[serde(flatten)]
    pub suite: tink_testutil::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(flatten)]
    pub group: tink_testutil::WycheproofGroup,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(flatten)]
    pub case: tink_testutil::WycheproofCase,
    #[serde(with = "tink_testutil::hex_string")]
    pub key: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub aad: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub ct: Vec<u8>,
}

#[test]
fn test_aes_siv_wycheproof_vectors() {
    let filename = "testvectors/aes_siv_cmac_test.json";
    println!("wycheproof file '{}'", filename);
    let bytes = tink_testutil::wycheproof_data(filename);
    let data: TestData = serde_json::from_slice(&bytes).unwrap();

    for g in &data.test_groups {
        if (g.key_size / 8) as usize != tink_daead::subtle::AES_SIV_KEY_SIZE {
            println!("   skipping tests for key_size={}", g.key_size);
            continue;
        }
        println!("   key info: key_size={}", g.key_size);
        for tc in &g.tests {
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            let a = tink_daead::subtle::AesSiv::new(&tc.key).expect("AesSiv::new() failed");

            // EncryptDeterministically should always succeed since msg and aad are valid inputs.
            let got_ct = a
                .encrypt_deterministically(&tc.msg, &tc.aad)
                .unwrap_or_else(|_| panic!("{}: unexpected encryption error", tc.case.case_id));
            match tc.case.result {
                WycheproofResult::Valid | WycheproofResult::Acceptable => {
                    assert_eq!(got_ct, tc.ct, "{}: incorrect encryption", tc.case.case_id);
                }
                WycheproofResult::Invalid => {
                    assert_ne!(got_ct, tc.ct, "{}: invalid encryption", tc.case.case_id);
                }
            }
            let pt_result = a.decrypt_deterministically(&tc.ct, &tc.aad);
            match tc.case.result {
                WycheproofResult::Valid | WycheproofResult::Acceptable => {
                    assert!(
                        pt_result.is_ok(),
                        "{}: unexpected decryption error: {:?}",
                        tc.case.case_id,
                        pt_result
                    );
                    assert_eq!(
                        tc.msg,
                        pt_result.unwrap(),
                        "{}: incorrect decryption",
                        tc.case.case_id
                    );
                }
                WycheproofResult::Invalid => {
                    assert!(
                        pt_result.is_err(),
                        "{}: decryption error expected",
                        tc.case.case_id
                    );
                }
            }
        }
    }
}

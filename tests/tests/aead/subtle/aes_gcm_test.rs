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

use super::wycheproof;
use std::collections::HashSet;
use tink_aead::subtle;
use tink_core::{subtle::random::get_random_bytes, Aead};
use tink_tests::WycheproofResult;

const KEY_SIZES: &[usize] = &[16, 32];

// Check that the tag size is always 128 bit.
#[test]
fn test_aes_gcm_tag_length() {
    for key_size in KEY_SIZES {
        let key = get_random_bytes(*key_size);
        let a = subtle::AesGcm::new(&key).unwrap();
        let ad = get_random_bytes(32);
        let pt = get_random_bytes(32);
        let ct = a.encrypt(&pt, &ad).unwrap();
        let actual_tag_size = ct.len() - subtle::AES_GCM_IV_SIZE - pt.len();
        assert_eq!(
            actual_tag_size,
            subtle::AES_GCM_TAG_SIZE,
            "tag size is not 128 bit, it is {} bit",
            actual_tag_size * 8
        );
    }
}

#[test]
fn test_aes_gcm_key_size() {
    for key_size in KEY_SIZES {
        subtle::AesGcm::new(&vec![0; *key_size])
            .unwrap_or_else(|_| panic!("unexpected error when key size is {} bytes", *key_size));
        assert!(
            subtle::AesGcm::new(&vec![0; *key_size + 1]).is_err(),
            "expect an error when key size is not supported {}",
            *key_size
        );
    }
}

#[test]
fn test_aes_gcm_encrypt_decrypt() {
    for key_size in KEY_SIZES {
        let key = get_random_bytes(*key_size);
        let a = subtle::AesGcm::new(&key).expect("unexpected error when creating new cipher");
        let ad = get_random_bytes(5);
        for pt_size in 0..75 {
            let pt = get_random_bytes(pt_size);
            let ct = a.encrypt(&pt, &ad).unwrap_or_else(|_| {
                panic!(
                    "unexpected error in encryption: key_size {}, pt_size {}",
                    key_size, pt_size
                )
            });
            let decrypted = a.decrypt(&ct, &ad).unwrap_or_else(|_| {
                panic!(
                    "unexpected error in decryption: keySize {}, ptSize {}",
                    key_size, pt_size
                )
            });
            assert_eq!(
                pt, decrypted,
                "decrypted text and plaintext don't match: key_size {key_size}, pt_size {pt_size}",
            );
        }
    }
}

#[test]
fn test_aes_gcm_long_messages() {
    let mut pt_size = 16;
    while pt_size <= 1 << 24 {
        let pt = get_random_bytes(pt_size);
        let ad = get_random_bytes(pt_size / 3);
        for key_size in KEY_SIZES {
            let key = get_random_bytes(*key_size);
            let a = subtle::AesGcm::new(&key).unwrap();
            let ct = a.encrypt(&pt, &ad).unwrap();
            let decrypted = a.decrypt(&ct, &ad).unwrap();
            assert_eq!(
                pt, decrypted,
                "decrypted text and plaintext don't match: key_size {key_size}, pt_size {pt_size}",
            );
        }
        pt_size += 9 * pt_size / 11
    }
}

#[test]
fn test_aes_gcm_modify_ciphertext() {
    let mut ad = get_random_bytes(33);
    let key = get_random_bytes(16);
    let pt = get_random_bytes(32);
    let a = subtle::AesGcm::new(&key).unwrap();
    let mut ct = a.encrypt(&pt, &ad).unwrap();
    // flipping bits
    for i in 0..ct.len() {
        let tmp = ct[i];
        for j in 0..8 {
            ct[i] ^= 1 << j;
            a.decrypt(&ct, &ad).expect_err(&format!(
                "expect an error when flipping bit of ciphertext: byte {i}, bit {j}",
            ));
            ct[i] = tmp;
        }
    }
    // truncated ciphertext
    for i in 1..ct.len() {
        a.decrypt(&ct[..i], &ad).expect_err(&format!(
            "expect an error ciphertext is truncated until byte {i}",
        ));
    }
    // modify additional authenticated data
    for i in 0..ad.len() {
        let tmp = ad[i];
        for j in 0..8 {
            ad[i] ^= 1 << j;
            a.decrypt(&ct, &ad).expect_err(&format!(
                "expect an error when flipping bit of ad: byte {i}, bit {j}",
            ));
            ad[i] = tmp;
        }
    }
}

// This is a very simple test for the randomness of the nonce. The test simply checks that the
// multiple ciphertexts of the same message are distinct.
#[test]
fn test_aes_gcm_random_nonce() {
    let n_sample = 1 << 17;
    let key = get_random_bytes(16);
    let pt = &[];
    let ad = &[];
    let a = subtle::AesGcm::new(&key).unwrap();
    let mut ct_set = HashSet::new();
    for i in 0..n_sample {
        let ct = a.encrypt(pt, ad).unwrap();
        let ct_hex = hex::encode(&ct);
        assert!(
            !ct_set.contains(&ct_hex),
            "nonce is repeated after {} samples",
            i
        );
        ct_set.insert(ct_hex);
    }
}

#[test]
fn test_aes_gcm_vectors() {
    let filename = "testvectors/aes_gcm_test.json";
    println!("wycheproof file '{filename}'");
    let bytes = tink_tests::wycheproof_data(filename);
    let data: wycheproof::TestData = serde_json::from_slice(&bytes).unwrap();
    assert_eq!("AES-GCM", data.suite.algorithm);

    for g in &data.test_groups {
        if subtle::validate_aes_key_size(g.key_size as usize / 8).is_err() {
            println!("   skipping tests for key_size={}", g.key_size);
            continue;
        }
        if g.iv_size as usize != subtle::AES_GCM_IV_SIZE * 8 {
            println!("   skipping tests for iv_size={}", g.iv_size);
            continue;
        }
        for tc in &g.tests {
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            let mut combined_ct = Vec::new();
            combined_ct.extend_from_slice(&tc.iv);
            combined_ct.extend_from_slice(&tc.ct);
            combined_ct.extend_from_slice(&tc.tag);

            // create cipher and do decryption
            let cipher = match subtle::AesGcm::new(&tc.key) {
                Ok(c) => c,
                Err(e) => panic!(
                    "cannot create new instance of AesGcm in test case {}: {:?}",
                    tc.case.case_id, e
                ),
            };
            let result = cipher.decrypt(&combined_ct, &tc.aad);
            match result {
                Err(e) => {
                    assert_ne!(
                        tc.case.result,
                        WycheproofResult::Valid,
                        "unexpected error in test case {}: {}",
                        tc.case.case_id,
                        e
                    );
                }
                Ok(decrypted) => {
                    assert_ne!(
                        tc.case.result,
                        WycheproofResult::Invalid,
                        "decrypted invalid test case {}",
                        tc.case.case_id
                    );
                    assert_eq!(
                        decrypted, tc.msg,
                        "incorrect decryption in test case {}",
                        tc.case.case_id,
                    );
                }
            }
        }
    }
}

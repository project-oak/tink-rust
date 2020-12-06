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

use super::{wycheproof::*, xchacha20poly1305_vectors::*};
use rand::{thread_rng, Rng};
use std::collections::HashSet;
use tink::{subtle::random::get_random_bytes, Aead};
use tink_aead::subtle;
use tink_testutil::WycheproofResult;

#[test]
fn test_x_cha_cha20_poly1305_encrypt_decrypt() {
    for (i, test) in X_CHA_CHA20_POLY1305_TESTS.iter().enumerate() {
        let key = hex::decode(&test.key).unwrap();
        let pt = hex::decode(&test.plaintext).unwrap();
        let aad = hex::decode(&test.aad).unwrap();
        let nonce = hex::decode(&test.nonce).unwrap();
        let out = hex::decode(&test.out).unwrap();
        let tag = hex::decode(&test.tag).unwrap();

        let x = subtle::XChaCha20Poly1305::new(&key).unwrap_or_else(|e| {
            panic!(
                "#{}, cannot create new instance of XChaCha20Poly1305: {}",
                i, e,
            )
        });

        x.encrypt(&pt, &aad)
            .unwrap_or_else(|e| panic!("#{}, unexpected encryption error: {:?}", i, e));

        let mut combined_ct = Vec::new();
        combined_ct.extend_from_slice(&nonce);
        combined_ct.extend_from_slice(&out);
        combined_ct.extend_from_slice(&tag);
        let got = x
            .decrypt(&combined_ct, &aad)
            .unwrap_or_else(|e| panic!("#{}, unexpected decryption error: {}", i, e));
        assert_eq!(
            pt,
            got,
            "#{}, plaintext's don't match: got {} vs {}",
            i,
            hex::encode(&got),
            hex::encode(&pt),
        );
    }
}

#[test]
fn test_x_cha_cha20_poly1305_empty_associated_data() {
    let key = get_random_bytes(subtle::CHA_CHA20_KEY_SIZE);
    let aad = &[];
    let bad_aad = &[1, 2, 3];

    let ca = subtle::XChaCha20Poly1305::new(&key).unwrap();

    for i in 0..75 {
        let pt = get_random_bytes(i);
        // Encrypting with aad as a 0-length slice
        {
            let ct = ca.encrypt(&pt, aad).unwrap_or_else(|e| {
                panic!(
                    "encrypt({}, {}) failed: {:?}",
                    hex::encode(&pt),
                    hex::encode(aad),
                    e
                )
            });
            let got = ca.decrypt(&ct, aad).unwrap_or_else(|e| {
                panic!(
                    "decrypt(encrypt({}, {})) failed: {:?}",
                    hex::encode(&pt),
                    hex::encode(aad),
                    e
                )
            });
            assert_eq!(
                pt,
                got,
                "decrypt(encrypt(pt, {})): plaintext's don't match",
                hex::encode(aad)
            );
        }
        let ct = ca
            .encrypt(&pt, &[])
            .unwrap_or_else(|e| panic!("encrypt({}, &[]) failed: {:?}", hex::encode(&pt), e));
        let got = ca.decrypt(&ct, &[]).unwrap_or_else(|e| {
            panic!(
                "decrypt(encrypt({}, &[])) failed: {:?}",
                hex::encode(&pt),
                e
            )
        });
        assert_eq!(
            pt, got,
            "decrypt(encrypt(pt, &[])): plaintext's don't match"
        );
        assert!(
            ca.decrypt(&ct, bad_aad).is_err(),
            "decrypt(encrypt(pt, bad_aad={})) unexpectedly Ok",
            hex::encode(bad_aad)
        );
    }
}

#[test]
fn test_x_cha_cha20_poly1305_long_messages() {
    let mut data_size = 16;
    // Encrypts and decrypts messages of size <= 8192.
    while data_size <= 1 << 24 {
        let pt = get_random_bytes(data_size);
        let aad = get_random_bytes(data_size / 3);
        let key = get_random_bytes(subtle::CHA_CHA20_KEY_SIZE);

        let ca = subtle::XChaCha20Poly1305::new(&key).unwrap();

        let ct = ca.encrypt(&pt, &aad).unwrap_or_else(|e| {
            panic!(
                "encrypt({}, {}) failed: {:?}",
                hex::encode(&pt),
                hex::encode(&aad),
                e
            )
        });
        let got = ca.decrypt(&ct, &aad).expect("decrypt() failed");
        assert_eq!(
            pt,
            got,
            "decrypt(encrypt(pt, {})): plaintext's don't match",
            hex::encode(&aad)
        );

        data_size += 9 * data_size / 11;
    }
}

#[test]
fn test_x_cha_cha20_poly1305_modify_ciphertext() {
    for (i, test) in X_CHA_CHA20_POLY1305_TESTS.iter().enumerate() {
        let key = hex::decode(&test.key).unwrap();
        let pt = hex::decode(&test.plaintext).unwrap();
        let mut aad = hex::decode(&test.aad).unwrap();

        let ca = subtle::XChaCha20Poly1305::new(&key).unwrap();

        let mut ct = ca
            .encrypt(&pt, &aad)
            .unwrap_or_else(|e| panic!("#{}: encrypt failed: {:?}", i, e));

        if !aad.is_empty() {
            let alter_aad_idx = thread_rng().gen_range(0, aad.len());
            aad[alter_aad_idx] ^= 0x80;
            assert!(
                ca.decrypt(&ct, &aad).is_err(),
                "#{}: Decrypt was successful after altering additional data",
                i
            );
            aad[alter_aad_idx] ^= 0x80;
        }

        let alter_ct_idx = thread_rng().gen_range(0, ct.len());
        ct[alter_ct_idx] ^= 0x80;
        assert!(
            ca.decrypt(&ct, &aad).is_err(),
            "#{}: Decrypt was successful after altering ciphertext",
            i
        );
        ct[alter_ct_idx] ^= 0x80;
    }
}

// This is a very simple test for the randomness of the nonce.
// The test simply checks that the multiple ciphertexts of the same message are distinct.
#[test]
fn test_x_cha_cha20_poly1305_random_nonce() {
    let key = get_random_bytes(subtle::X_CHA_CHA20_KEY_SIZE);
    let ca = subtle::XChaCha20Poly1305::new(&key).unwrap();

    let mut cts = HashSet::new();
    let pt = &[];
    let aad = &[];
    for _ in 0..1 << 10 {
        let ct = ca.encrypt(pt, aad).expect("test random nonce failed");
        let ct_hex = hex::encode(&ct);
        assert!(!cts.contains(&ct_hex), "duplicate ciphertext {}", ct_hex);
        cts.insert(ct_hex);
    }
}

#[test]
fn test_cha_cha20_poly1305_invalid_key() {
    let key = get_random_bytes(tink_aead::subtle::X_CHA_CHA20_KEY_SIZE - 1);
    let result = subtle::XChaCha20Poly1305::new(&key);
    tink_testutil::expect_err(result, "bad key length");
}

#[test]
fn test_x_cha_cha20_poly1305_wycheproof_vectors() {
    let filename = "testvectors/xchacha20_poly1305_test.json";
    println!("wycheproof file '{}'", filename);
    let bytes = tink_testutil::wycheproof_data(filename);
    let data: TestData = serde_json::from_slice(&bytes).unwrap();
    assert_eq!("XCHACHA20-POLY1305", data.suite.algorithm);

    for g in &data.test_groups {
        if (g.key_size / 8) as usize != tink_aead::subtle::X_CHA_CHA20_KEY_SIZE {
            println!(" skipping tests for key_size={}", g.key_size);
            continue;
        }
        if (g.iv_size / 8) as usize != tink_aead::subtle::X_CHA_CHA20_NONCE_SIZE {
            println!(" skipping tests for iv_size={}", g.iv_size);
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

            let ca = subtle::XChaCha20Poly1305::new(&tc.key).unwrap_or_else(|e| {
                panic!(
                    "#{}, cannot create new instance of XChaCha20Poly1305: {}",
                    tc.case.case_id, e
                )
            });
            ca.encrypt(&tc.msg, &tc.aad).unwrap_or_else(|e| {
                panic!("#{}, unexpected encryption error: {:?}", tc.case.case_id, e)
            });
            let result = ca.decrypt(&combined_ct, &tc.aad);
            match result {
                Err(e) => {
                    assert_ne!(
                        tc.case.result,
                        WycheproofResult::Valid,
                        "#{}, unexpected error: {}",
                        tc.case.case_id,
                        e
                    );
                }
                Ok(decrypted) => {
                    assert_ne!(
                        tc.case.result,
                        WycheproofResult::Invalid,
                        "#{}, decrypted invalid",
                        tc.case.case_id
                    );
                    assert_eq!(
                        decrypted, tc.msg,
                        "#{}, incorrect decryption",
                        tc.case.case_id
                    );
                }
            }
        }
    }
}

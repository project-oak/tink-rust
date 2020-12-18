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

use std::collections::HashSet;
use tink::subtle::random::get_random_bytes;
use tink_aead::{subtle, subtle::IndCpaCipher};

#[test]
fn test_new_aes_ctr() {
    let key = vec![0; 64];

    // Test various key sizes with a fixed IV size.
    for i in 0..64 {
        let k = &key[..i];
        let result = subtle::AesCtr::new(k, subtle::AES_CTR_MIN_IV_SIZE);
        match k.len() {
            16 | 32 => {
                // Valid key sizes.
                let c = match result {
                    Err(e) => panic!(
                        "want: valid cipher (key size={}), got: error {}",
                        k.len(),
                        e
                    ),
                    Ok(c) => c,
                };
                // Verify that the struct contents are correctly set.
                assert_eq!(c.key_len(), k.len());
                assert_eq!(c.iv_size, subtle::AES_CTR_MIN_IV_SIZE);
            }
            _ => {
                // Invalid key sizes.
                let err = match result {
                    Err(e) => e,
                    Ok(_) => panic!("AesCtr: unexpected success"),
                };
                assert!(format!("{}", err).contains(
                    "AesCtr: invalid AES key size; want 16 or 32"),
                        "wrong error message; want a String starting with \"AesCtr: invalid AES key size; want 16 or 32\", got {}", err);
            }
        }
    }

    // Test different IV sizes with a fixed key.
    for i in 0..64 {
        let k = &key[..16];
        let result = subtle::AesCtr::new(k, i);
        if i >= subtle::AES_CTR_MIN_IV_SIZE && i <= subtle::AES_BLOCK_SIZE_IN_BYTES {
            let c = result.unwrap_or_else(|e| {
                panic!("want: valid cipher (IV size={}), got: error {:?}", i, e)
            });
            assert_eq!(c.key_len(), k.len());
            assert_eq!(c.iv_size, i);
        } else {
            let err = match result {
                Err(e) => e,
                Ok(_) => panic!("want error for invalid IV size"),
            };
            assert!(format!("{:?}", err).contains("AesCtr: invalid IV size"));
        }
    }
}

#[test]
fn test_nist_test_vector() {
    // NIST SP 800-38A pp 55
    let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();

    // NIST IV
    let iv = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    // NIST ciphertext blocks
    let     c = "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee";
    let ciphertext = hex::decode(iv.to_owned() + c).unwrap();

    // NIST plaintext blocks
    let     p = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    let message = hex::decode(p).unwrap();

    let stream = subtle::AesCtr::new(&key, iv.len() / 2).expect("failed to create AesCtr instance");

    let plaintext = stream
        .decrypt(&ciphertext)
        .expect("failed to decrypt ciphertext");

    assert_eq!(plaintext, message);
}

#[test]
fn test_multiple_encrypt() {
    let key = get_random_bytes(16);

    let stream = subtle::AesCtr::new(&key, subtle::AES_CTR_MIN_IV_SIZE)
        .expect("failed to create AesCtr instance");

    let plaintext = b"Some data to encrypt.";
    let ct1 = stream.encrypt(plaintext).expect("encryption failed");
    let ct2 = stream.encrypt(plaintext).expect("encryption failed");
    assert_ne!(ct1, ct2, "the two ciphertexts cannot be equal");
    // Encrypt 100 times and verify that the result is 100 different ciphertexts.
    let mut ciphertexts = HashSet::new();
    for i in 0..100 {
        let c = stream
            .encrypt(&plaintext[..])
            .unwrap_or_else(|e| panic!("encryption failed for iteration {}, error: {}", i, e,));
        ciphertexts.insert(c);
    }

    assert_eq!(ciphertexts.len(), 100, "want 100 distinct ciphertexts");
}

#[test]
fn test_encrypt_decrypt() {
    let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();

    let stream = subtle::AesCtr::new(&key, subtle::AES_CTR_MIN_IV_SIZE)
        .expect("failed to get AesCtr instance");

    let message = b"Some data to encrypt.";
    let ciphertext = stream.encrypt(message).expect("encryption failed");

    assert_eq!(
        ciphertext.len(),
        message.len() + subtle::AES_CTR_MIN_IV_SIZE,
        "ciphertext incorrect size"
    );

    let plaintext = stream
        .decrypt(&ciphertext)
        .expect("decryption failed, error");

    assert_eq!(message.to_vec(), plaintext, "decryption result mismatch");
}

#[test]
fn test_decrypt_failure() {
    let key = get_random_bytes(16);

    let stream = subtle::AesCtr::new(&key, subtle::AES_CTR_MIN_IV_SIZE)
        .expect("failed to create AesCtr instance");

    let plaintext = b"Some data to encrypt.";
    let ct = stream.encrypt(plaintext).expect("encryption failed");

    let result = stream.decrypt(&ct[..2]);
    tink_testutil::expect_err(result, "ciphertext too short");
    let result = stream.decrypt(&[]);
    tink_testutil::expect_err(result, "ciphertext too short");
}

#[test]
fn test_encrypt_random_message() {
    let key = get_random_bytes(16);

    let stream = subtle::AesCtr::new(&key, subtle::AES_CTR_MIN_IV_SIZE)
        .expect("failed to instantiate AesCtr");

    for i in 0..256 {
        let message = get_random_bytes(i);
        let ciphertext = stream
            .encrypt(&message)
            .unwrap_or_else(|e| panic!("encryption failed at iteration {}, error: {}", i, e));
        assert_eq!(
            ciphertext.len(),
            message.len() + subtle::AES_CTR_MIN_IV_SIZE,
            "invalid ciphertext length for i = {}",
            i
        );

        let plaintext = stream
            .decrypt(&ciphertext)
            .unwrap_or_else(|e| panic!("decryption failed at iteration {}, error: {}", i, e));

        assert_eq!(
            plaintext, message,
            "plaintext doesn't match message, i = {}",
            i
        );
    }
}

#[test]
fn test_encrypt_random_key_and_message() {
    for i in 0..256 {
        let key = get_random_bytes(16);

        let stream = subtle::AesCtr::new(&key, subtle::AES_CTR_MIN_IV_SIZE)
            .expect("failed to instantiate AesCtr");

        let message = get_random_bytes(i);
        let ciphertext = stream
            .encrypt(&message)
            .unwrap_or_else(|e| panic!("encryption failed at iteration {}, error: {}", i, e));
        assert_eq!(
            ciphertext.len(),
            message.len() + subtle::AES_CTR_MIN_IV_SIZE,
            "invalid ciphertext length for i = {}",
            i
        );

        let plaintext = stream
            .decrypt(&ciphertext)
            .unwrap_or_else(|e| panic!("decryption failed at iteration {}, error: {}", i, e));

        assert_eq!(
            plaintext, message,
            "plaintext doesn't match message, i = {}",
            i
        );
    }
}

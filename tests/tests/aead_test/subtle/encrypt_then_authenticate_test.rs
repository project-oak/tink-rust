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

use tink_aead::subtle;
use tink_core::{subtle::random::get_random_bytes, TinkError};
use tink_proto::HashType;

fn create_aead_with_keys(
    encryption_key: &[u8],
    iv_size: usize,
    hash_algo: HashType,
    mac_key: &[u8],
    tag_size: usize,
) -> Result<Box<dyn tink_core::Aead>, TinkError> {
    let ctr = subtle::AesCtr::new(encryption_key, iv_size)?;
    let mac = tink_mac::subtle::Hmac::new(hash_algo, mac_key, tag_size)?;
    let p = subtle::EncryptThenAuthenticate::new(Box::new(ctr), Box::new(mac), tag_size)?;
    Ok(Box::new(p))
}

fn create_aead(
    key_size: usize,
    iv_size: usize,
    hash_algo: HashType,
    mac_key_size: usize,
    tag_size: usize,
) -> Result<Box<dyn tink_core::Aead>, TinkError> {
    let encryption_key = get_random_bytes(key_size);
    let mac_key = get_random_bytes(mac_key_size);
    create_aead_with_keys(&encryption_key, iv_size, hash_algo, &mac_key, tag_size)
}

// Copied from https://tools.ietf.org/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05.  We use CTR but the RFC uses CBC
// mode, so it's not possible to compare plaintexts. However, the tests are still valuable to ensure
// that we correcly compute HMAC over ciphertext and aad.
#[derive(Debug)]
struct RfcTestVector {
    mac_key: &'static str,
    encryption_key: &'static str,
    ciphertext: &'static str,
    aad: &'static str,
    hash_algo: HashType,
    iv_size: usize,
    tag_size: usize,
}

const RFC_TEST_VECTORS : &[RfcTestVector] = &[
    RfcTestVector{
        mac_key:      "000102030405060708090a0b0c0d0e0f",
        encryption_key:"101112131415161718191a1b1c1d1e1f",
        ciphertext: "1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db652c3fa36b0a7c5b3219fab3a30bc1c4",
        aad:"546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        hash_algo:  HashType::Sha256,
        iv_size:16,
        tag_size:16
    },
    RfcTestVector{
        mac_key:    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        encryption_key: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        ciphertext: "1af38c2dc2b96ffdd86694092341bc044affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f64dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5",
        aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
        hash_algo: HashType::Sha512,
        iv_size:16,
        tag_size:32
    },
];

#[test]
fn test_eta_rfc_test_vectors() {
    for v in RFC_TEST_VECTORS {
        let mac_key = hex::decode(&v.mac_key).unwrap();
        let encryption_key = hex::decode(&v.encryption_key).unwrap();
        let ciphertext = hex::decode(&v.ciphertext).unwrap();
        let aad = hex::decode(&v.aad).unwrap();

        let cipher = create_aead_with_keys(
            &encryption_key,
            v.iv_size,
            v.hash_algo,
            &mac_key,
            v.tag_size,
        )
        .expect("failed to create AEAD from RFC test vector");
        cipher
            .decrypt(&ciphertext, &aad)
            .unwrap_or_else(|e| panic!("decryption failed for RFC test vector {:?}: {:?}", v, e));
    }
}

#[test]
fn test_eta_encrypt_decrypt() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 16;

    let cipher = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size).unwrap();

    let message = b"Some data to encrypt.";
    let aad = b"Some data to authenticate.";

    let ciphertext = cipher
        .encrypt(&message[..], &aad[..])
        .expect("encryption failed");

    assert_eq!(
        ciphertext.len(),
        message.len() + iv_size + tag_size,
        "invalid ciphertext size"
    );

    // Use a clone of the object to decrypt
    let plaintext = cipher
        .box_clone()
        .decrypt(&ciphertext, &aad[..])
        .expect("decryption failed");
    assert_eq!(plaintext, message, "invalid plaintext");
}

#[test]
fn test_eta_encrypt_decrypt_random_message() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 16;

    let cipher = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size).unwrap();

    for i in 0..256 {
        let message = get_random_bytes(i);
        let aad = get_random_bytes(i);

        let ciphertext = cipher.encrypt(&message, &aad).expect("encryption failed");

        assert_eq!(
            ciphertext.len(),
            message.len() + iv_size + tag_size,
            "invalid ciphertext size"
        );

        let plaintext = cipher
            .decrypt(&ciphertext, &aad)
            .expect("decryption failed");
        assert_eq!(plaintext, message, "invalid plaintext");
    }
}

#[test]
fn test_eta_multiple_encrypt() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 16;

    let cipher = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size).unwrap();

    let message = b"Some data to encrypt.";
    let aad = b"Some data to authenticate.";

    let ciphertext1 = cipher
        .encrypt(&message[..], &aad[..])
        .expect("encryption failed");
    let ciphertext2 = cipher
        .encrypt(&message[..], &aad[..])
        .expect("encryption failed");

    assert_ne!(ciphertext1, ciphertext2, "ciphertexts must not be the same");
}

#[test]
fn test_eta_invalid_tag_size() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 9; // Invalid!
    let result = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size);
    tink_tests::expect_err(result, "tag size too small");

    // Repeat but with a direct call to `EncryptThenAuthenticate::new`.
    let ctr = subtle::AesCtr::new(&[0; 16], iv_size).unwrap();
    let mac = tink_mac::subtle::Hmac::new(HashType::Sha1, &[0; 16], 16).unwrap();
    let result = subtle::EncryptThenAuthenticate::new(Box::new(ctr), Box::new(mac), tag_size);
    tink_tests::expect_err(result, "tag size too small");
}

#[test]
fn test_eta_decrypt_modified_ciphertext() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 16;

    let cipher = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size).unwrap();

    let message = b"Some data to encrypt.";
    let aad = b"Some data to authenticate.";
    let ciphertext = cipher
        .encrypt(&message[..], &aad[..])
        .expect("encryption failed");

    // Modify the ciphertext and try to decrypt.
    let mut modct = Vec::with_capacity(ciphertext.len());
    modct.extend_from_slice(&ciphertext);
    for i in 0..ciphertext.len() * 8 {
        // Save the byte to be modified.
        let b = modct[i / 8];
        modct[i / 8] ^= 1 << (i % 8);
        assert_ne!(
            ciphertext, modct,
            "modified ciphertext shouldn't be the same as original"
        );
        cipher.decrypt(&modct, &aad[..]).expect_err(&format!(
            "successfully decrypted modified ciphertext (i = {})",
            i
        ));
        // Restore the modified byte.
        modct[i / 8] = b;
    }

    // Modify the additional authenticated data.
    let mut modaad = Vec::with_capacity(aad.len());
    modaad.extend_from_slice(&aad[..]);
    for i in 0..aad.len() * 8 {
        // Save the byte to be modified.
        let b = modaad[i / 8];
        modaad[i / 8] ^= 1 << (i % 8);
        assert_ne!(
            aad.to_vec(),
            modaad,
            "modified aad shouldn't be the same as aad"
        );
        cipher.decrypt(&ciphertext, &modaad).expect_err(&format!(
            "successfully decrypted with modified aad (i = {})",
            i
        ));
        // Restore the modified byte.
        modaad[i / 8] = b
    }

    // Truncate the ciphertext.
    for i in 1..ciphertext.len() {
        cipher
            .decrypt(&ciphertext[..(ciphertext.len() - i)], aad)
            .expect_err(&format!(
                "successfully decrypted truncated ciphertext (i = {})",
                i
            ));
    }
}

#[test]
fn test_eta_empty_params() {
    let key_size = 16;
    let iv_size = 12;
    let mac_key_size = 16;
    let tag_size = 16;

    let cipher = create_aead(key_size, iv_size, HashType::Sha1, mac_key_size, tag_size).unwrap();

    let message = b"Some data to encrypt.";
    cipher
        .encrypt(message, &[])
        .expect("encryption failed with empty aad");
    cipher
        .encrypt(&[], &[])
        .expect("encryption failed with empty ciphertext and aad");
}

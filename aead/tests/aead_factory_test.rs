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

use tink::{proto::OutputPrefixType, subtle::random::get_random_bytes, utils::wrap_err, TinkError};
use tink_aead::subtle;

#[test]
fn test_factory_multiple_keys() {
    tink_aead::init();
    // encrypt with non-raw key
    let keyset = tink_testutil::new_test_aes_gcm_keyset(OutputPrefixType::Tink);
    let primary_key = keyset.key[0].clone();
    let raw_key = keyset.key[1].clone();
    assert_ne!(
        primary_key.output_prefix_type,
        OutputPrefixType::Raw as i32,
        "expect a non-raw key"
    );
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();
    let a = tink_aead::new(&keyset_handle).expect("tink_aead::new failed");
    let expected_prefix = tink::cryptofmt::output_prefix(&primary_key).unwrap();
    validate_aead_factory_cipher(a.box_clone(), a.box_clone(), &expected_prefix)
        .expect("invalid cipher");

    // encrypt with a non-primary RAW key and decrypt with the keyset
    assert_eq!(
        raw_key.output_prefix_type,
        OutputPrefixType::Raw as i32,
        "expect a raw key"
    );

    let keyset2 = tink_testutil::new_keyset(raw_key.key_id, vec![raw_key]);
    let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();
    let a2 = tink_aead::new(&keyset_handle2).expect("tink_aead::new failed");
    validate_aead_factory_cipher(a2.box_clone(), a.box_clone(), &tink::cryptofmt::RAW_PREFIX)
        .expect("invalid cipher");

    // encrypt with a random key not in the keyset, decrypt with the keyset should fail
    let keyset2 = tink_testutil::new_test_aes_gcm_keyset(OutputPrefixType::Tink);
    let primary_key = keyset2.key[0].clone();
    let expected_prefix = tink::cryptofmt::output_prefix(&primary_key).unwrap();
    let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();
    let a2 = tink_aead::new(&keyset_handle2).expect("tink_aead::new failed");
    let result = validate_aead_factory_cipher(a2.box_clone(), a.box_clone(), &expected_prefix);
    assert!(result.is_err(), "expect decryption to fail with random key");
    assert!(
        format!("{:?}", result).contains("decryption failed"),
        "expect decryption to fail with random key: {:?}",
        result
    );
}

#[test]
fn test_factory_raw_key_as_primary() {
    tink_aead::init();
    let keyset = tink_testutil::new_test_aes_gcm_keyset(OutputPrefixType::Raw);
    assert_eq!(
        keyset.key[0].output_prefix_type,
        OutputPrefixType::Raw as i32,
        "primary key is not a raw key"
    );
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();

    let a = tink_aead::new(&keyset_handle).expect("cannot get primitive from keyset handle");
    validate_aead_factory_cipher(a.box_clone(), a.box_clone(), &tink::cryptofmt::RAW_PREFIX)
        .expect("invalid cipher");
}

fn validate_aead_factory_cipher(
    encrypt_cipher: Box<dyn tink::Aead>,
    decrypt_cipher: Box<dyn tink::Aead>,
    expected_prefix: &[u8],
) -> Result<(), TinkError> {
    let prefix_size = expected_prefix.len();
    // regular plaintext
    let pt = get_random_bytes(20);
    let ad = get_random_bytes(20);
    let ct = encrypt_cipher
        .encrypt(&pt, &ad)
        .map_err(|e| wrap_err("encryption failed with regular plaintext", e))?;
    let decrypted = decrypt_cipher
        .decrypt(&ct, &ad)
        .map_err(|e| wrap_err("decryption failed with regular plaintext", e))?;
    if decrypted != pt {
        return Err("decryption failed with regular plaintext".into());
    }
    if &ct[..prefix_size] != expected_prefix {
        return Err("incorrect prefix with regular plaintext".into());
    }
    if prefix_size + pt.len() + subtle::AES_GCM_IV_SIZE + subtle::AES_GCM_TAG_SIZE != ct.len() {
        return Err(
            "lengths of plaintext and ciphertext don't match with regular plaintext".into(),
        );
    }

    // short plaintext
    let pt = get_random_bytes(1);
    let ct = encrypt_cipher
        .encrypt(&pt, &ad)
        .map_err(|e| wrap_err("encryption failed with short plaintext", e))?;
    let decrypted = decrypt_cipher
        .decrypt(&ct, &ad)
        .map_err(|e| wrap_err("decryption failed with short plaintext", e))?;
    if decrypted != pt {
        return Err(format!(
            "decryption failed with short plaintext:  pt: {}, decrypted: {}",
            hex::encode(&pt),
            hex::encode(&decrypted)
        )
        .into());
    }
    if &ct[..prefix_size] != expected_prefix {
        return Err("incorrect prefix with short plaintext".into());
    }

    if prefix_size + pt.len() + subtle::AES_GCM_IV_SIZE + subtle::AES_GCM_TAG_SIZE != ct.len() {
        return Err("lengths of plaintext and ciphertext don't match with short plaintext".into());
    }
    Ok(())
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_signature::init();
    tink_aead::init();
    let wrong_kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template())
        .expect("failed to build keyset.Handle");

    assert!(
        tink_aead::new(&wrong_kh).is_err(),
        "calling new() with wrong keyset::Handle should fail"
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_aead::init();
    let good_kh = tink::keyset::Handle::new(&tink_aead::aes128_gcm_key_template())
        .expect("failed to build keyset::Handle");

    tink_aead::new(&good_kh).expect("calling new() with good keyset::Handle failed");
}

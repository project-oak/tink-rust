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

use std::error::Error;
use tink::subtle::random::get_random_bytes;

#[test]
fn test_factory_multiple_keys() {
    tink_daead::init();
    // encrypt with non-raw key.
    let keyset = tink_testutil::new_test_aes_siv_keyset(tink::proto::OutputPrefixType::Tink);
    let primary_key = keyset.key[0].clone();
    let raw_key = keyset.key[1].clone();
    assert!(
        primary_key.output_prefix_type != tink::proto::OutputPrefixType::Raw as i32,
        "expect a non-raw key"
    );
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();

    let d = tink_daead::new(&keyset_handle).unwrap();
    let expected_prefix = tink::cryptofmt::output_prefix(&primary_key).unwrap();
    assert!(validate_daead_factory_cipher(&d, &d, &expected_prefix).is_ok());

    // encrypt with a non-primary RAW key in keyset and decrypt with the keyset.
    {
        assert_eq!(
            raw_key.output_prefix_type,
            tink::proto::OutputPrefixType::Raw as i32,
            "expect a raw key"
        );
        let keyset2 = tink_testutil::new_keyset(raw_key.key_id, vec![raw_key]);
        let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();
        let d2 = tink_daead::new(&keyset_handle2).unwrap();
        assert!(validate_daead_factory_cipher(&d2, &d, &tink::cryptofmt::RAW_PREFIX).is_ok());
    }

    // encrypt with a random key from a new keyset, decrypt with the original keyset should fail.
    {
        let keyset2 = tink_testutil::new_test_aes_siv_keyset(tink::proto::OutputPrefixType::Tink);
        let new_pk = keyset2.key[0].clone();
        assert!(
            new_pk.output_prefix_type != tink::proto::OutputPrefixType::Raw as i32,
            "expect a non-raw key"
        );
        let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();
        let d2 = tink_daead::new(&keyset_handle2).unwrap();
        let expected_prefix = tink::cryptofmt::output_prefix(&new_pk).unwrap();
        assert!(
            validate_daead_factory_cipher(&d2, &d, &expected_prefix).is_err(),
            "expect decryption to fail with random key"
        );
    }
}

#[test]
fn test_factory_raw_key_as_primary() {
    tink_daead::init();
    let keyset = tink_testutil::new_test_aes_siv_keyset(tink::proto::OutputPrefixType::Raw);
    assert_eq!(
        keyset.key[0].output_prefix_type,
        tink::proto::OutputPrefixType::Raw as i32,
        "primary key is not a raw key"
    );
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();

    let d = tink_daead::new(&keyset_handle).expect("cannot get primitive from keyset handle");
    assert!(validate_daead_factory_cipher(&d, &d, &tink::cryptofmt::RAW_PREFIX).is_ok());
}

// Return an `Err` if decryption fails, panic if something else goes wrong.
#[allow(clippy::borrowed_box)]
fn validate_daead_factory_cipher<T: ?Sized>(
    encrypt_cipher: &Box<T>,
    decrypt_cipher: &Box<T>,
    expected_prefix: &[u8],
) -> Result<(), Box<dyn Error>>
where
    T: tink::DeterministicAead,
{
    let prefix_size = expected_prefix.len();
    // regular plaintext.
    let pt = get_random_bytes(20);
    let aad = get_random_bytes(20);
    let ct = encrypt_cipher
        .encrypt_deterministically(&pt, &aad)
        .expect("encryption failed");
    let decrypted = decrypt_cipher.decrypt_deterministically(&ct, &aad)?;
    assert_eq!(decrypted, pt, "decryption failed");
    assert_eq!(
        &ct[..prefix_size],
        expected_prefix,
        "incorrect prefix with regular plaintext"
    );

    // short plaintext.
    let pt = get_random_bytes(1);
    let ct = encrypt_cipher
        .encrypt_deterministically(&pt, &aad)
        .expect("encryption failed with short plaintext");
    let decrypted = decrypt_cipher.decrypt_deterministically(&ct, &aad)?;
    assert_eq!(decrypted, pt, "decryption failed with short plaintext");
    assert_eq!(
        &ct[..prefix_size],
        expected_prefix,
        "incorrect prefix with short plaintext"
    );
    Ok(())
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_daead::init();
    tink_signature::init();
    let wrong_kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();

    assert!(
        tink_daead::new(&wrong_kh).is_err(),
        "calling new() with wrong tink::keyset::Handle should fail"
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_daead::init();
    let good_kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();

    assert!(
        tink_daead::new(&good_kh).is_ok(),
        "calling new() with good tink::keyset::Handle failed"
    );
}

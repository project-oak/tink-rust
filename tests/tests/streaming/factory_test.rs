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

use tink_core::{utils::wrap_err, TinkError};

use super::common::encrypt_decrypt;

#[test]
fn test_factory_multiple_keys() {
    tink_streaming_aead::init();
    let keyset = tink_tests::new_test_aes_gcm_hkdf_keyset();
    let raw_key = keyset.key[1].clone();
    let keyset_handle = tink_core::keyset::insecure::new_handle(keyset).unwrap();
    let a = tink_streaming_aead::new(&keyset_handle).expect("tink_streaming_aead::new failed");

    // Encrypt with a primary RAW key and decrypt with the keyset
    validate_factory_cipher(a.box_clone(), a.box_clone()).expect("invalid cipher");

    // Encrypt with a non-primary RAW key and decrypt with the keyset
    assert_eq!(
        raw_key.output_prefix_type,
        tink_proto::OutputPrefixType::Raw as i32,
        "expect a raw key"
    );
    let keyset2 = tink_tests::new_keyset(raw_key.key_id, vec![raw_key]);
    let keyset_handle2 = tink_core::keyset::insecure::new_handle(keyset2).unwrap();
    let a2 = tink_streaming_aead::new(&keyset_handle2).expect("tink_streaming_aead::new failed");
    validate_factory_cipher(a2.box_clone(), a.box_clone()).expect("invalid cipher");

    // Encrypt with a random key not in the keyset, decrypt with the keyset should fail
    let keyset2 = tink_tests::new_test_aes_gcm_hkdf_keyset();
    let keyset_handle2 = tink_core::keyset::insecure::new_handle(keyset2).unwrap();
    let a2 = tink_streaming_aead::new(&keyset_handle2).expect("tink_streaming_aead::new failed");
    let result = validate_factory_cipher(a2.box_clone(), a.box_clone());
    tink_tests::expect_err(result, "no matching key");
}

fn validate_factory_cipher(
    encrypt_cipher: Box<dyn tink_core::StreamingAead>,
    decrypt_cipher: Box<dyn tink_core::StreamingAead>,
) -> Result<(), TinkError> {
    let tt = vec![1, 16, 4095, 4096, 4097, 16384];

    for t in tt {
        encrypt_decrypt(
            encrypt_cipher.box_clone(),
            decrypt_cipher.box_clone(),
            t,
            32,
        )
        .map_err(|e| wrap_err(&format!("failed plaintext-size={t}"), e))?;
    }
    Ok(())
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_mac::init();
    tink_streaming_aead::init();
    let wrong_kh = tink_core::keyset::Handle::new(&tink_mac::hmac_sha256_tag128_key_template())
        .expect("failed to build keyset.Handle");
    tink_tests::expect_err(
        tink_streaming_aead::new(&wrong_kh),
        "not a StreamingAead primitive",
    );

    // Now arrange a keyset where the primary key is correct but secondary key is not.
    let mut km = tink_core::keyset::Manager::new_from_handle(wrong_kh);
    km.rotate(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
        .unwrap();
    let wronger_kh = km.handle().unwrap();
    tink_tests::expect_err(
        tink_streaming_aead::new(&wronger_kh),
        "not a StreamingAead primitive",
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_streaming_aead::init();
    let good_kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
            .expect("failed to build keyset.Handle");

    assert!(
        tink_streaming_aead::new(&good_kh).is_ok(),
        "new() failed with good keyset.Handle"
    );
}

#[test]
fn test_key_rotation() {
    tink_streaming_aead::init();

    // Build four keysets like so:
    //   keyset1 = [A*]
    //   keyset2 = [A*, B]
    //   keyset3 = [A, B*]
    //   keyset4 = [(A), B*]
    // with *=primary, ()=disabled
    let kt_a = tink_streaming_aead::aes128_ctr_hmac_sha256_segment_4kb_key_template();
    let kt_b = tink_streaming_aead::aes256_ctr_hmac_sha256_segment_4kb_key_template();
    let mut ksm = tink_core::keyset::Manager::new();
    let id_a = ksm.rotate(&kt_a).unwrap();
    let h1 = ksm.handle().unwrap();
    let id_b = ksm.add(&kt_b, /* primary= */ false).unwrap();
    let h2 = ksm.handle().unwrap();
    ksm.set_primary(id_b).unwrap();
    let h3 = ksm.handle().unwrap();
    ksm.disable(id_a).unwrap();
    let h4 = ksm.handle().unwrap();
    let a1 = tink_streaming_aead::new(&h1).unwrap();
    let a2 = tink_streaming_aead::new(&h2).unwrap();
    let a3 = tink_streaming_aead::new(&h3).unwrap();
    let a4 = tink_streaming_aead::new(&h4).unwrap();

    // 1 encrypts with key A. So 1, 2 and 3 can decrypt it, but not 4.
    assert!(validate_factory_cipher(a1.box_clone(), a1.box_clone()).is_ok());
    assert!(validate_factory_cipher(a1.box_clone(), a2.box_clone()).is_ok());
    assert!(validate_factory_cipher(a1.box_clone(), a3.box_clone()).is_ok());
    assert!(validate_factory_cipher(a1.box_clone(), a4.box_clone()).is_err());

    // 2 encrypts with key A. So 1, 2 and 3 can decrypt it, but not 4.
    assert!(validate_factory_cipher(a2.box_clone(), a1.box_clone()).is_ok());
    assert!(validate_factory_cipher(a2.box_clone(), a2.box_clone()).is_ok());
    assert!(validate_factory_cipher(a2.box_clone(), a3.box_clone()).is_ok());
    assert!(validate_factory_cipher(a2.box_clone(), a4.box_clone()).is_err());

    // 3 encrypts with key B. So 2, 3 and 4 can decrypt it, but not 1.
    assert!(validate_factory_cipher(a3.box_clone(), a1.box_clone()).is_err());
    assert!(validate_factory_cipher(a3.box_clone(), a2.box_clone()).is_ok());
    assert!(validate_factory_cipher(a3.box_clone(), a3.box_clone()).is_ok());
    assert!(validate_factory_cipher(a3.box_clone(), a4.box_clone()).is_ok());

    // 4 encrypts with key B. So 2, 3 and 4 can decrypt it, but not 1.
    assert!(validate_factory_cipher(a3.box_clone(), a1.box_clone()).is_err());
    assert!(validate_factory_cipher(a3.box_clone(), a2.box_clone()).is_ok());
    assert!(validate_factory_cipher(a3.box_clone(), a3.box_clone()).is_ok());
    assert!(validate_factory_cipher(a3.box_clone(), a4.box_clone()).is_ok());
}

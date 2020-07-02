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

use prost::Message;
use std::{error::Error, sync::Arc};
use tink::subtle::random::get_random_bytes;

#[test]
fn test_aes_siv_primitive() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    let serialized_key = km.new_key(&[]).unwrap();
    let p = km.primitive(&serialized_key).unwrap();
    assert!(validate_aes_siv_primitive(p).is_ok());
}

#[test]
fn test_aes_siv_primitive_with_invalid_keys() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    let invalid_keys = gen_invalid_aes_siv_keys();
    for key in invalid_keys {
        let mut serialized_key = Vec::new();
        key.encode(&mut serialized_key).unwrap();
        assert!(km.primitive(&serialized_key).is_err());
    }
}

#[test]
fn test_aes_siv_new_key() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    let sk = km.new_key(&[]).unwrap();
    let key = tink::proto::AesSivKey::decode(sk.as_ref()).unwrap();
    assert!(validate_aes_siv_key(&key).is_ok());
}

#[test]
fn test_aes_siv_new_key_data() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    let kd = km.new_key_data(&[]).unwrap();
    assert_eq!(kd.type_url, tink_testutil::AES_SIV_TYPE_URL);
    assert_eq!(
        kd.key_material_type,
        tink::proto::key_data::KeyMaterialType::Symmetric as i32
    );

    let key = tink::proto::AesSivKey::decode(kd.value.as_ref()).unwrap();
    assert!(validate_aes_siv_key(&key).is_ok());
}

#[test]
fn test_aes_siv_new_key_invalid() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    let key_format = tink::proto::AesSivKeyFormat {
        key_size: (tink_daead::subtle::AES_SIV_KEY_SIZE - 1) as u32,
    };
    let mut serialized_key_format = Vec::new();
    key_format.encode(&mut serialized_key_format).unwrap();
    assert!(km.new_key(&serialized_key_format).is_err());
}

#[test]
fn test_aes_siv_does_support() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");

    assert!(
        km.does_support(tink_testutil::AES_SIV_TYPE_URL),
        "AESSIVKeyManager must support {}",
        tink_testutil::AES_SIV_TYPE_URL
    );
    assert!(
        !km.does_support("some bad type"),
        "AESSIVKeyManager must only support {}",
        tink_testutil::AES_SIV_TYPE_URL
    );
}

#[test]
fn test_aes_siv_type_url() {
    tink_daead::init();
    let km = tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL)
        .expect("cannot obtain AESSIV key manager");
    assert_eq!(km.type_url(), tink_testutil::AES_SIV_TYPE_URL);
}

fn validate_aes_siv_primitive(p: tink::Primitive) -> Result<(), Box<dyn Error>> {
    let cipher = match p {
        tink::Primitive::DeterministicAead(c) => c,
        _ => panic!("not a DeterministicAEAD"),
    };

    // try to encrypt and decrypt
    let pt = get_random_bytes(32);
    let aad = get_random_bytes(32);
    let ct = cipher
        .encrypt_deterministically(&pt, &aad)
        .expect("encryption failed");
    let decrypted = cipher.decrypt_deterministically(&ct, &aad)?;
    assert_eq!(decrypted, pt, "decryption failed");
    Ok(())
}

fn validate_aes_siv_key(key: &tink::proto::AesSivKey) -> Result<(), Box<dyn Error>> {
    if key.version != tink_testutil::AES_SIV_KEY_VERSION {
        return Err(format!(
            "incorrect key version: key_version != {}",
            tink_testutil::AES_SIV_KEY_VERSION,
        )
        .into());
    }
    if key.key_value.len() != tink_daead::subtle::AES_SIV_KEY_SIZE {
        return Err(format!(
            "incorrect key size: key_size != {}",
            tink_daead::subtle::AES_SIV_KEY_SIZE,
        )
        .into());
    }

    // Try to encrypt and decrypt.
    let p = tink_daead::subtle::AesSiv::new(&key.key_value)?;
    validate_aes_siv_primitive(tink::Primitive::DeterministicAead(Arc::new(p)))
}

fn gen_invalid_aes_siv_keys() -> Vec<tink::proto::AesSivKey> {
    vec![
        // Bad key size.
        tink::proto::AesSivKey {
            version: tink_testutil::AES_SIV_KEY_VERSION,
            key_value: get_random_bytes(16),
        },
        tink::proto::AesSivKey {
            version: tink_testutil::AES_SIV_KEY_VERSION,
            key_value: get_random_bytes(32),
        },
        tink::proto::AesSivKey {
            version: tink_testutil::AES_SIV_KEY_VERSION,
            key_value: get_random_bytes(63),
        },
        tink::proto::AesSivKey {
            version: tink_testutil::AES_SIV_KEY_VERSION,
            key_value: get_random_bytes(65),
        },
        // Bad version.
        tink::proto::AesSivKey {
            version: tink_testutil::AES_SIV_KEY_VERSION + 1,
            key_value: get_random_bytes(tink_daead::subtle::AES_SIV_KEY_SIZE),
        },
    ]
}

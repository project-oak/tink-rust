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
use std::sync::Arc;
use tink::{subtle::random::get_random_bytes, TinkError};
use tink_aead::subtle;

#[test]
fn test_x_cha_cha20_poly1305_get_primitive() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    let serialized_key = km.new_key(&[]).unwrap();
    let p = km.primitive(&serialized_key).unwrap();
    let key = tink::proto::XChaCha20Poly1305Key::decode(serialized_key.as_ref()).unwrap();
    validate_x_cha_cha20_poly1305_primitive(p, &key).unwrap();
}

#[test]
fn test_x_cha_cha20_poly1305_get_primitive_with_invalid_keys() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    let invalid_keys = gen_invalid_x_cha_cha20_poly1305_keys();
    for key in invalid_keys {
        let serialized_key = tink_testutil::proto_encode(&key);
        assert!(km.primitive(&serialized_key).is_err());
    }
}

#[test]
fn test_x_cha_cha20_poly1305_new_key() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    let m = km.new_key(&[]).unwrap();
    let key = tink::proto::XChaCha20Poly1305Key::decode(m.as_ref()).unwrap();
    validate_x_cha_cha20_poly1305_key(&key).unwrap();
}

#[test]
fn test_x_cha_cha20_poly1305_new_key_data() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    let kd = km.new_key_data(&[]).unwrap();
    assert_eq!(kd.type_url, tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL);
    assert_eq!(
        kd.key_material_type,
        tink::proto::key_data::KeyMaterialType::Symmetric as i32
    );
    let key = tink::proto::XChaCha20Poly1305Key::decode(kd.value.as_ref()).unwrap();
    validate_x_cha_cha20_poly1305_key(&key).unwrap();
}

#[test]
fn test_x_cha_cha20_poly1305_does_support() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    assert!(
        km.does_support(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL),
        "XChaCha20Poly1305KeyManager must support {}",
        tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL
    );
    assert!(
        !km.does_support("some bad type"),
        "XChaCha20Poly1305KeyManager must only support {}",
        tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL
    );
}

#[test]
fn test_x_cha_cha20_poly1305_type_url() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL)
        .expect("cannot obtain XChaCha20Poly1305 key manager");
    assert_eq!(km.type_url(), tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL);
}

fn gen_invalid_x_cha_cha20_poly1305_keys() -> Vec<tink::proto::XChaCha20Poly1305Key> {
    vec![
        // Bad key size.
        tink::proto::XChaCha20Poly1305Key {
            version: tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION,
            key_value: get_random_bytes(17),
        },
        tink::proto::XChaCha20Poly1305Key {
            version: tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION,
            key_value: get_random_bytes(25),
        },
        tink::proto::XChaCha20Poly1305Key {
            version: tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION,
            key_value: get_random_bytes(33),
        },
        // Bad version.
        tink::proto::XChaCha20Poly1305Key {
            version: tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION + 1,
            key_value: get_random_bytes(subtle::CHA_CHA20_KEY_SIZE),
        },
    ]
}

fn validate_x_cha_cha20_poly1305_primitive(
    p: tink::Primitive,
    _key: &tink::proto::XChaCha20Poly1305Key,
) -> Result<(), TinkError> {
    let cipher = match p {
        tink::Primitive::Aead(p) => p,
        _ => return Err("key and primitive don't match".into()),
    };

    // Try to encrypt and decrypt.
    let pt = get_random_bytes(32);
    let aad = get_random_bytes(32);
    let ct = cipher.encrypt(&pt, &aad)?;
    let decrypted = cipher.decrypt(&ct, &aad)?;

    if decrypted != pt {
        return Err("decryption failed".into());
    }
    Ok(())
}

fn validate_x_cha_cha20_poly1305_key(
    key: &tink::proto::XChaCha20Poly1305Key,
) -> Result<(), TinkError> {
    if key.version != tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION {
        return Err(format!(
            "incorrect key version: keyVersion != {}",
            tink_testutil::X_CHA_CHA20_POLY1305_KEY_VERSION
        )
        .into());
    }
    if key.key_value.len() as usize != subtle::CHA_CHA20_KEY_SIZE {
        return Err(format!(
            "incorrect key size: keySize != {}",
            subtle::CHA_CHA20_KEY_SIZE
        )
        .into());
    }

    // Try to encrypt and decrypt.
    let p = subtle::XChaCha20Poly1305::new(&key.key_value)?;
    validate_x_cha_cha20_poly1305_primitive(tink::Primitive::Aead(Arc::new(p)), key)
}

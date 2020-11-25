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
use std::collections::HashSet;
use tink::{subtle::random::get_random_bytes, TinkError};
use tink_testutil::proto_encode;

const KEY_SIZES: &[u32] = &[16, 32];

#[test]
fn test_aes_gcm_get_primitive_basic() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    assert_eq!(key_manager.type_url(), tink_testutil::AES_GCM_TYPE_URL);
    assert_eq!(
        key_manager.key_material_type(),
        tink::proto::key_data::KeyMaterialType::Symmetric
    );
    for key_size in KEY_SIZES {
        let key = tink_testutil::new_aes_gcm_key(tink_testutil::AES_GCM_KEY_VERSION, *key_size);
        let serialized_key = proto_encode(&key);
        let p = key_manager.primitive(&serialized_key).unwrap();
        validate_aes_gcm_primitive(p, &key).unwrap();
    }
}

#[test]
fn test_aes_gcm_get_primitive_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    // invalid AES_GCMKey
    let test_keys = gen_invalid_aes_gcm_keys();
    for (i, serialized_key) in test_keys.iter().enumerate() {
        assert!(
            key_manager.primitive(serialized_key).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty array
    assert!(
        key_manager.primitive(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_aes_gcm_new_key_multiple_times() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    let format = tink_testutil::new_aes_gcm_key_format(32);
    let serialized_format = proto_encode(&format);
    let mut keys = HashSet::new();
    let n_test = 26;
    for _ in 0..n_test {
        let key = key_manager.new_key(&serialized_format).unwrap();
        let serialized_key = proto_encode(&key);
        keys.insert(serialized_key);

        let key_data = key_manager.new_key_data(&serialized_format).unwrap();
        let serialized_key = key_data.value;
        keys.insert(serialized_key);
    }
    assert_eq!(keys.len(), n_test * 2, "key is repeated");
}

#[test]
fn test_aes_gcm_new_key_basic() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    for key_size in KEY_SIZES {
        let format = tink_testutil::new_aes_gcm_key_format(*key_size);
        let serialized_format = proto_encode(&format);
        let m = key_manager.new_key(&serialized_format).unwrap();
        let key = tink::proto::AesGcmKey::decode(m.as_ref()).unwrap();
        validate_aes_gcm_key(&key, &format).unwrap();
    }
}

#[test]
fn test_aes_gcm_new_key_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    // bad format
    let bad_formats = gen_invalid_aes_gcm_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        key_manager
            .new_key(serialized_format)
            .expect_err(&format!("expect an error in test case {}", i));
    }
    // empty array
    key_manager
        .new_key(&[])
        .expect_err("expect an error when input is empty");
}

#[test]
fn test_aes_gcm_new_key_data_basic() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    for key_size in KEY_SIZES {
        let format = tink_testutil::new_aes_gcm_key_format(*key_size);
        let serialized_format = proto_encode(&format);
        let key_data = key_manager.new_key_data(&serialized_format).unwrap();
        assert_eq!(
            key_data.type_url,
            tink_testutil::AES_GCM_TYPE_URL,
            "incorrect type url"
        );
        assert_eq!(
            key_data.key_material_type,
            tink::proto::key_data::KeyMaterialType::Symmetric as i32,
            "incorrect key material type"
        );
        let _key = tink::proto::AesGcmKey::decode(key_data.value.as_ref()).unwrap();
    }
}

#[test]
fn test_aes_gcm_new_key_data_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    let bad_formats = gen_invalid_aes_gcm_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        key_manager
            .new_key_data(serialized_format)
            .expect_err(&format!("expect an error in test case {}", i));
    }
    // empty array
    key_manager
        .new_key_data(&[])
        .expect_err("expect an error when input is empty");
}

#[test]
fn test_aes_gcm_does_support() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    assert!(
        key_manager.does_support(tink_testutil::AES_GCM_TYPE_URL),
        "AesGcmKeyManager must support {}",
        tink_testutil::AES_GCM_TYPE_URL
    );
    assert!(
        !key_manager.does_support("some bad type"),
        "AesGcmKeyManager must support only {}",
        tink_testutil::AES_GCM_TYPE_URL
    );
}

#[test]
fn test_aes_gcm_type_url() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL)
        .expect("cannot obtain AES-GCM key manager");
    assert_eq!(
        key_manager.type_url(),
        tink_testutil::AES_GCM_TYPE_URL,
        "incorrect key type"
    );
}

fn gen_invalid_aes_gcm_keys() -> Vec<Vec<u8>> {
    vec![
        // not a AES_GCMKey
        proto_encode(&tink_testutil::new_aes_gcm_key_format(32)),
        // bad key size
        proto_encode(&tink_testutil::new_aes_gcm_key(
            tink_testutil::AES_GCM_KEY_VERSION,
            17,
        )),
        proto_encode(&tink_testutil::new_aes_gcm_key(
            tink_testutil::AES_GCM_KEY_VERSION,
            25,
        )),
        proto_encode(&tink_testutil::new_aes_gcm_key(
            tink_testutil::AES_GCM_KEY_VERSION,
            33,
        )),
        // bad version
        proto_encode(&tink_testutil::new_aes_gcm_key(
            tink_testutil::AES_GCM_KEY_VERSION + 1,
            16,
        )),
    ]
}

fn gen_invalid_aes_gcm_key_formats() -> Vec<Vec<u8>> {
    vec![
        // not AES_GCMKeyFormat
        proto_encode(&tink_testutil::new_aes_gcm_key(
            tink_testutil::AES_GCM_KEY_VERSION,
            16,
        )),
        // invalid key size
        proto_encode(&tink_testutil::new_aes_gcm_key_format(15)),
        proto_encode(&tink_testutil::new_aes_gcm_key_format(23)),
        proto_encode(&tink_testutil::new_aes_gcm_key_format(31)),
    ]
}

fn validate_aes_gcm_key(
    key: &tink::proto::AesGcmKey,
    format: &tink::proto::AesGcmKeyFormat,
) -> Result<(), TinkError> {
    if key.key_value.len() != format.key_size as usize {
        return Err("incorrect key size".into());
    }
    if key.version != tink_testutil::AES_GCM_KEY_VERSION {
        return Err("incorrect key version".into());
    }
    // try to encrypt and decrypt
    let p = tink_aead::subtle::AesGcm::new(&key.key_value)?;
    validate_aes_gcm_primitive(tink::Primitive::Aead(Box::new(p)), key)
}

fn validate_aes_gcm_primitive(
    p: tink::Primitive,
    _key: &tink::proto::AesGcmKey,
) -> Result<(), TinkError> {
    let cipher = match p {
        tink::Primitive::Aead(p) => p,
        _ => return Err("key and primitive don't match".into()),
    };
    // try to encrypt and decrypt
    let pt = get_random_bytes(32);
    let aad = get_random_bytes(32);
    let ct = cipher.encrypt(&pt, &aad)?;
    let decrypted = cipher.decrypt(&ct, &aad)?;
    if decrypted != pt {
        return Err("decryption failed".into());
    }
    Ok(())
}

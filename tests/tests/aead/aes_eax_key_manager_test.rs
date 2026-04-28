// Copyright 2026 The Tink-Rust Authors
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
use tink_core::{subtle::random::get_random_bytes, TinkError};
use tink_proto::prost::Message;
use tink_tests::{proto_encode, AES_EAX_KEY_VERSION, AES_EAX_TYPE_URL};

const KEY_SIZES: &[u32] = &[16, 32];
// Note: The Rust eax crate only supports 16-byte IVs (cipher block size)
const IV_SIZES: &[u32] = &[16];

fn new_aes_eax_key(version: u32, key_size: u32, iv_size: u32) -> tink_proto::AesEaxKey {
    let key_value = get_random_bytes(key_size as usize);
    tink_proto::AesEaxKey {
        version,
        params: Some(tink_proto::AesEaxParams { iv_size }),
        key_value,
    }
}

fn new_aes_eax_key_format(key_size: u32, iv_size: u32) -> tink_proto::AesEaxKeyFormat {
    tink_proto::AesEaxKeyFormat {
        params: Some(tink_proto::AesEaxParams { iv_size }),
        key_size,
    }
}

#[test]
fn test_aes_eax_get_primitive_basic() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    assert_eq!(key_manager.type_url(), AES_EAX_TYPE_URL);
    assert_eq!(
        key_manager.key_material_type(),
        tink_proto::key_data::KeyMaterialType::Symmetric
    );
    for key_size in KEY_SIZES {
        for iv_size in IV_SIZES {
            let key = new_aes_eax_key(AES_EAX_KEY_VERSION, *key_size, *iv_size);
            let serialized_key = proto_encode(&key);
            let p = key_manager.primitive(&serialized_key).unwrap();
            validate_aes_eax_primitive(p, &key).unwrap();
        }
    }
}

#[test]
fn test_aes_eax_get_primitive_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    // invalid AES-EAX keys
    let test_keys = gen_invalid_aes_eax_keys();
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
fn test_aes_eax_new_key_multiple_times() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    let format = new_aes_eax_key_format(32, 16);
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
fn test_aes_eax_new_key_basic() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    for key_size in KEY_SIZES {
        for iv_size in IV_SIZES {
            let format = new_aes_eax_key_format(*key_size, *iv_size);
            let serialized_format = proto_encode(&format);
            let m = key_manager.new_key(&serialized_format).unwrap();
            let key = tink_proto::AesEaxKey::decode(m.as_ref()).unwrap();
            validate_aes_eax_key(&key, &format).unwrap();
        }
    }
}

#[test]
fn test_aes_eax_new_key_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    // bad format
    let bad_formats = gen_invalid_aes_eax_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        key_manager
            .new_key(serialized_format)
            .expect_err(&format!("expect an error in test case {i}"));
    }
    // empty array
    key_manager
        .new_key(&[])
        .expect_err("expect an error when input is empty");
}

#[test]
fn test_aes_eax_new_key_data_basic() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    for key_size in KEY_SIZES {
        for iv_size in IV_SIZES {
            let format = new_aes_eax_key_format(*key_size, *iv_size);
            let serialized_format = proto_encode(&format);
            let key_data = key_manager.new_key_data(&serialized_format).unwrap();
            assert_eq!(key_data.type_url, AES_EAX_TYPE_URL, "incorrect type url");
            assert_eq!(
                key_data.key_material_type,
                tink_proto::key_data::KeyMaterialType::Symmetric as i32,
                "incorrect key material type"
            );
            let _key = tink_proto::AesEaxKey::decode(key_data.value.as_ref()).unwrap();
        }
    }
}

#[test]
fn test_aes_eax_new_key_data_with_invalid_input() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    let bad_formats = gen_invalid_aes_eax_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        key_manager
            .new_key_data(serialized_format)
            .expect_err(&format!("expect an error in test case {i}"));
    }
    // empty array
    key_manager
        .new_key_data(&[])
        .expect_err("expect an error when input is empty");
}

#[test]
fn test_aes_eax_does_support() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    assert!(
        key_manager.does_support(AES_EAX_TYPE_URL),
        "AesEaxKeyManager must support {}",
        AES_EAX_TYPE_URL
    );
    assert!(
        !key_manager.does_support("some bad type"),
        "AesEaxKeyManager must support only {}",
        AES_EAX_TYPE_URL
    );
}

#[test]
fn test_aes_eax_type_url() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(AES_EAX_TYPE_URL)
        .expect("cannot obtain AES-EAX key manager");
    assert_eq!(
        key_manager.type_url(),
        AES_EAX_TYPE_URL,
        "incorrect key type"
    );
}

fn gen_invalid_aes_eax_keys() -> Vec<Vec<u8>> {
    vec![
        // not an AesEaxKey
        proto_encode(&new_aes_eax_key_format(32, 16)),
        // bad key size
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 17, 16)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 25, 16)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 33, 16)),
        // bad IV size (only 16 is supported)
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 8)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 12)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 15)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 17)),
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 24)),
        // bad version
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION + 1, 16, 16)),
        // missing params
        proto_encode(&tink_proto::AesEaxKey {
            version: AES_EAX_KEY_VERSION,
            params: None,
            key_value: get_random_bytes(16),
        }),
    ]
}

fn gen_invalid_aes_eax_key_formats() -> Vec<Vec<u8>> {
    vec![
        // not AesEaxKeyFormat
        proto_encode(&new_aes_eax_key(AES_EAX_KEY_VERSION, 16, 16)),
        // invalid key size
        proto_encode(&new_aes_eax_key_format(15, 16)),
        proto_encode(&new_aes_eax_key_format(23, 16)),
        proto_encode(&new_aes_eax_key_format(31, 16)),
        proto_encode(&new_aes_eax_key_format(33, 16)),
        // invalid IV size (only 16 is supported)
        proto_encode(&new_aes_eax_key_format(16, 8)),
        proto_encode(&new_aes_eax_key_format(16, 12)),
        proto_encode(&new_aes_eax_key_format(16, 15)),
        proto_encode(&new_aes_eax_key_format(16, 17)),
        proto_encode(&new_aes_eax_key_format(16, 24)),
        // missing params
        proto_encode(&tink_proto::AesEaxKeyFormat {
            params: None,
            key_size: 16,
        }),
    ]
}

fn validate_aes_eax_key(
    key: &tink_proto::AesEaxKey,
    format: &tink_proto::AesEaxKeyFormat,
) -> Result<(), TinkError> {
    if key.key_value.len() != format.key_size as usize {
        return Err("incorrect key size".into());
    }
    if key.version != AES_EAX_KEY_VERSION {
        return Err("incorrect key version".into());
    }
    let key_params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("missing params"))?;
    let format_params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("missing params"))?;
    if key_params.iv_size != format_params.iv_size {
        return Err("incorrect IV size".into());
    }
    // try to encrypt and decrypt
    let p = tink_aead::subtle::AesEax::new(&key.key_value, key_params.iv_size as usize)?;
    validate_aes_eax_primitive(tink_core::Primitive::Aead(Box::new(p)), key)
}

fn validate_aes_eax_primitive(
    p: tink_core::Primitive,
    _key: &tink_proto::AesEaxKey,
) -> Result<(), TinkError> {
    let cipher = match p {
        tink_core::Primitive::Aead(p) => p,
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

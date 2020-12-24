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
use tink::TinkError;
use tink_proto::HashType;
use tink_streaming_aead::subtle;
use tink_tests::proto_encode;

use super::common::encrypt_decrypt;

const AES_GCM_HKDF_KEY_SIZES: [u32; 2] = [16, 32];

#[test]
fn test_aes_gcm_hkdf_get_primitive_basic() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    for key_size in &AES_GCM_HKDF_KEY_SIZES {
        let key = tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_HKDF_KEY_VERSION,
            *key_size,
            *key_size,
            HashType::Sha256 as i32,
            4096,
        );
        let serialized_key = proto_encode(&key);
        let p = match key_manager.primitive(&serialized_key) {
            Ok(tink::Primitive::StreamingAead(p)) => p,
            _ => unreachable!(),
        };
        encrypt_decrypt(p.box_clone(), p.box_clone(), 32, 32).unwrap();
    }
}

#[test]
fn test_aes_gcm_hkdf_get_primitive_with_invalid_input() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");

    let test_keys = gen_invalid_aes_gcm_hkdf_keys();
    for (i, test_key) in test_keys.iter().enumerate() {
        let serialized_key = proto_encode(test_key);
        assert!(
            key_manager.primitive(&serialized_key).is_err(),
            "expect an error in test case {}",
            i
        );
    }

    assert!(
        key_manager.primitive(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_aes_gcm_hkdf_new_key_multiple_times() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    let format = tink_tests::new_aes_gcm_hkdf_key_format(32, 32, HashType::Sha256 as i32, 4096);
    let serialized_format = proto_encode(&format);
    let mut keys = HashSet::new();
    let n = 26;
    for _i in 0..n {
        let key = key_manager.new_key(&serialized_format).unwrap();
        let serialized_key = proto_encode(&key);
        keys.insert(serialized_key);

        let key_data = key_manager.new_key_data(&serialized_format).unwrap();
        let serialized_key = key_data.value;
        keys.insert(serialized_key);
    }
    assert_eq!(keys.len(), n * 2, "key is repeated");
}

#[test]
fn test_aes_gcm_hkdf_new_key_basic() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    for key_size in &AES_GCM_HKDF_KEY_SIZES {
        let format = tink_tests::new_aes_gcm_hkdf_key_format(
            *key_size,
            *key_size,
            HashType::Sha256 as i32,
            4096,
        );
        let serialized_format = proto_encode(&format);
        let m = key_manager.new_key(&serialized_format).unwrap();
        let key = tink_proto::AesGcmHkdfStreamingKey::decode(m.as_ref()).unwrap();
        validate_aes_gcm_hkdf_key(&key, &format).unwrap();
    }
}

#[test]
fn test_aes_gcm_hkdf_new_key_with_invalid_input() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    // bad format
    let bad_formats = gen_invalid_aes_gcm_hkdf_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        assert!(
            key_manager.new_key(serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty array
    assert!(
        key_manager.new_key(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_aes_gcm_hkdf_new_key_data_basic() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    for key_size in &AES_GCM_HKDF_KEY_SIZES {
        let format = tink_tests::new_aes_gcm_hkdf_key_format(
            *key_size,
            *key_size,
            HashType::Sha256 as i32,
            4096,
        );
        let serialized_format = proto_encode(&format);
        let key_data = key_manager.new_key_data(&serialized_format).unwrap();
        assert_eq!(
            key_data.type_url,
            tink_tests::AES_GCM_HKDF_TYPE_URL,
            "incorrect type url"
        );
        assert_eq!(
            key_data.key_material_type,
            tink_proto::key_data::KeyMaterialType::Symmetric as i32,
            "incorrect key material type"
        );
        let key = tink_proto::AesGcmHkdfStreamingKey::decode(key_data.value.as_ref())
            .expect("incorrect key value");
        validate_aes_gcm_hkdf_key(&key, &format).unwrap();
    }
}

#[test]
fn test_aes_gcm_hkdf_new_key_data_with_invalid_input() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    let bad_formats = gen_invalid_aes_gcm_hkdf_key_formats();
    for (i, serialized_format) in bad_formats.iter().enumerate() {
        assert!(
            key_manager.new_key_data(serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty input
    assert!(
        key_manager.new_key_data(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_aes_gcm_hkdf_does_support() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    assert!(
        key_manager.does_support(tink_tests::AES_GCM_HKDF_TYPE_URL),
        "AesGcmHkdfKeyManager must support {}",
        tink_tests::AES_GCM_HKDF_TYPE_URL
    );
    assert!(
        !key_manager.does_support("some bad type"),
        "AESGCMHKDFKeyManager must support only {}",
        tink_tests::AES_GCM_HKDF_TYPE_URL
    );
}

#[test]
fn test_aes_gcm_hkdf_type_url() {
    tink_streaming_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_tests::AES_GCM_HKDF_TYPE_URL)
        .expect("cannot obtain AES-GCM-HKDF key manager");
    assert_eq!(
        key_manager.type_url(),
        tink_tests::AES_GCM_HKDF_TYPE_URL,
        "incorrect key type"
    );
    assert_eq!(
        key_manager.key_material_type(),
        tink_proto::key_data::KeyMaterialType::Symmetric
    );
}

fn gen_invalid_aes_gcm_hkdf_keys() -> Vec<Vec<u8>> {
    vec![
        // not a AES_GCM_HKDFKey
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            32,
            32,
            HashType::Sha256 as i32,
            4096,
        )),
        // bad key size
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            17,
            16,
            HashType::Sha256 as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            16,
            17,
            HashType::Sha256 as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            33,
            33,
            HashType::Sha256 as i32,
            4096,
        )),
        // bad version
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION + 1,
            16,
            16,
            HashType::Sha256 as i32,
            4096,
        )),
        // ciphertext segment size too short
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            16,
            16,
            HashType::Sha256 as i32,
            4,
        )),
        // invalid hash
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            16,
            16,
            HashType::UnknownHash as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            16,
            16,
            9999,
            4096,
        )),
    ]
}

fn gen_invalid_aes_gcm_hkdf_key_formats() -> Vec<Vec<u8>> {
    vec![
        // not AESGCMKeyFormat
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key(
            tink_tests::AES_GCM_KEY_VERSION,
            16,
            16,
            HashType::Sha256 as i32,
            16,
        )),
        // invalid key size
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            17,
            16,
            HashType::Sha256 as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            16,
            17,
            HashType::Sha256 as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            33,
            33,
            HashType::Sha256 as i32,
            4096,
        )),
        // invalid hash type
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            32,
            32,
            HashType::UnknownHash as i32,
            4096,
        )),
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(32, 32, 9999, 4096)),
        // segment size too short
        proto_encode(&tink_tests::new_aes_gcm_hkdf_key_format(
            32,
            32,
            HashType::Sha256 as i32,
            4,
        )),
    ]
}

fn validate_aes_gcm_hkdf_key(
    key: &tink_proto::AesGcmHkdfStreamingKey,
    format: &tink_proto::AesGcmHkdfStreamingKeyFormat,
) -> Result<(), TinkError> {
    if key.key_value.len() != format.key_size as usize {
        return Err("incorrect key size".into());
    }
    if key.version != tink_tests::AES_GCM_KEY_VERSION {
        return Err("incorrect key version".into());
    }
    let key_params = key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params"))?;
    let format_params = format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params"))?;
    if key_params.ciphertext_segment_size != format_params.ciphertext_segment_size {
        return Err("incorrect ciphertext segment size".into());
    }
    if key_params.derived_key_size != format_params.derived_key_size {
        return Err("incorrect derived key size".into());
    }
    if key_params.hkdf_hash_type != format_params.hkdf_hash_type {
        return Err("incorrect HKDF hash type".into());
    }
    // try to encrypt and decrypt
    let hkdf_hash_type = HashType::from_i32(key_params.hkdf_hash_type)
        .ok_or_else(|| TinkError::new("invalid HKDF hash"))?;
    let p = subtle::AesGcmHkdf::new(
        &key.key_value,
        hkdf_hash_type,
        key_params.derived_key_size as usize,
        key_params.ciphertext_segment_size as usize,
        0,
    )
    .expect("invalid key");
    validate_primitive(p, key)
}

fn validate_primitive(
    cipher: subtle::AesGcmHkdf,
    key: &tink_proto::AesGcmHkdfStreamingKey,
) -> Result<(), TinkError> {
    if cipher.main_key != key.key_value {
        return Err("main key and primitive don't match".into());
    }
    encrypt_decrypt(Box::new(cipher.clone()), Box::new(cipher), 32, 32)
}

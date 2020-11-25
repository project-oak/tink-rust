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
use tink::proto::{AesCtrHmacAeadKey, AesCtrHmacAeadKeyFormat, HashType};

#[test]
fn test_new_key_multiple_times() {
    tink_aead::init();
    let key_template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let _aead_key_format =
        tink::proto::AesCtrHmacAeadKeyFormat::decode(key_template.value.as_ref())
            .expect("cannot unmarshal AES128_CTR_HMAC_SHA256 key template");

    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let mut keys = HashSet::new();
    let num_tests = 24;
    for _ in 0..num_tests / 2 {
        let sk = key_manager.new_key(&key_template.value).unwrap();
        let key = tink::proto::AesCtrHmacAeadKey::decode(sk.as_ref()).unwrap();

        keys.insert(key.aes_ctr_key.as_ref().unwrap().key_value.clone());
        keys.insert(key.hmac_key.as_ref().unwrap().key_value.clone());
        assert_eq!(
            key.aes_ctr_key.unwrap().key_value.len(),
            16,
            "unexpected AES key size"
        );
        assert_eq!(
            key.hmac_key.unwrap().key_value.len(),
            32,
            "unexpected HMAC key size"
        );
    }
    assert_eq!(keys.len(), num_tests, "unexpected number of keys in set");
}

#[test]
fn test_new_key_with_corrupted_format() {
    tink_aead::init();
    let key_template = tink::proto::KeyTemplate {
        type_url: tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL.to_string(),
        value: vec![0, 128],
        output_prefix_type: tink::proto::OutputPrefixType::UnknownPrefix as i32,
    };

    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    key_manager
        .new_key(&key_template.value)
        .expect_err("new_key got: success, want: error due to corrupted format");
    key_manager
        .new_key_data(&key_template.value)
        .expect_err("new_key_data got: success, want: error due to corrupted format");
}

#[test]
fn test_key_manager_params() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    assert_eq!(
        key_manager.type_url(),
        tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL
    );
    assert_eq!(
        key_manager.key_material_type(),
        tink::proto::key_data::KeyMaterialType::Symmetric
    );
    assert!(!key_manager.supports_private_keys());
}

#[test]
fn test_new_key_with_invalid_format() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let invalid_formats = vec![
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 0 }), // invalid
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 0, // invalid
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 0, // invalid
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 999999, // invalid
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
                key_size: 0, // invalid
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: 999, // invalid
                    tag_size: 16,
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: None, // invalid
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: None, // invalid
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: None, // invalid
            hmac_key_format: Some(tink::proto::HmacKeyFormat {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
                key_size: 32,
            }),
        },
        AesCtrHmacAeadKeyFormat {
            aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                key_size: 16,
            }),
            hmac_key_format: None, // invalid
        },
        /* All based on this valid key format:
                AesCtrHmacAeadKeyFormat {
                    aes_ctr_key_format: Some(tink::proto::AesCtrKeyFormat {
                        params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
                        key_size: 16,
                    }),
                    hmac_key_format: Some(tink::proto::HmacKeyFormat {
                        version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                        params: Some(tink::proto::HmacParams {
                            hash: HashType::Sha256 as i32,
                            tag_size: 16,
                        }),
                        key_size: 32,
                    }),
                },
        */
    ];
    for format in &invalid_formats {
        let serialized_format = tink_testutil::proto_encode(format);
        assert!(key_manager.new_key(&serialized_format).is_err());
    }
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let invalid_keys = vec![
        AesCtrHmacAeadKey {
            version: 999, // invalid
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 1], // invalid
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 0 }), // invalid
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 2], // invalid
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: 9999, // invalid
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 1, // invalid
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: None, // invalid
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: None, // invalid
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: None, // invalid
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: None, // invalid
        },
        /* All based on this valid key:
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink::proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink::proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink::proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink::proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        */
    ];
    for key in &invalid_keys {
        let serialized_key = tink_testutil::proto_encode(key);
        assert!(key_manager.primitive(&serialized_key).is_err());
    }
}

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

use std::collections::HashSet;
use tink_proto::{prost::Message, AesCtrHmacAeadKey, AesCtrHmacAeadKeyFormat, HashType};

#[test]
fn test_new_key_multiple_times() {
    tink_aead::init();
    let key_template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let _aead_key_format = tink_proto::AesCtrHmacAeadKeyFormat::decode(key_template.value.as_ref())
        .expect("cannot unmarshal AES128_CTR_HMAC_SHA256 key template");

    let key_manager = tink_core::registry::get_key_manager(tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let mut keys = HashSet::new();
    let num_tests = 24;
    for _ in 0..num_tests / 2 {
        let sk = key_manager.new_key(&key_template.value).unwrap();
        let key = tink_proto::AesCtrHmacAeadKey::decode(sk.as_ref()).unwrap();

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
    let key_template = tink_proto::KeyTemplate {
        type_url: tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL.to_string(),
        value: vec![0, 128],
        output_prefix_type: tink_proto::OutputPrefixType::UnknownPrefix as i32,
    };

    let key_manager = tink_core::registry::get_key_manager(tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL)
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
    let key_manager = tink_core::registry::get_key_manager(tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    assert_eq!(
        key_manager.type_url(),
        tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL
    );
    assert_eq!(
        key_manager.key_material_type(),
        tink_proto::key_data::KeyMaterialType::Symmetric
    );
    assert!(!key_manager.supports_private_keys());
}

#[test]
fn test_new_key_with_invalid_format() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let invalid_formats = vec![
        (
            "IV size out of range",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 0 }), // invalid
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "invalid AES key size",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 0, // invalid
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "tag_size 0 is too small",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 0, // invalid
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "tag_size 999999 is too big",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 999999, // invalid
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "HMAC key_size is too small",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                    key_size: 0, // invalid
                }),
            },
        ),
        (
            "hash_type 999 not supported",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: 999, // invalid
                        tag_size: 16,
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "no AES key params",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: None, // invalid
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "no HMAC key params",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: None, // invalid
                    key_size: 32,
                }),
            },
        ),
        (
            "no AES key format",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: None, // invalid
                hmac_key_format: Some(tink_proto::HmacKeyFormat {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                    key_size: 32,
                }),
            },
        ),
        (
            "no HMAC key format",
            AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                    key_size: 16,
                }),
                hmac_key_format: None, // invalid
            },
        ),
        /* All based on this valid key format:
                AesCtrHmacAeadKeyFormat {
                    aes_ctr_key_format: Some(tink_proto::AesCtrKeyFormat {
                        params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                        key_size: 16,
                    }),
                    hmac_key_format: Some(tink_proto::HmacKeyFormat {
                        version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                        params: Some(tink_proto::HmacParams {
                            hash: HashType::Sha256 as i32,
                            tag_size: 16,
                        }),
                        key_size: 32,
                    }),
                },
        */
    ];
    for (err_msg, format) in &invalid_formats {
        let serialized_format = tink_tests::proto_encode(format);
        let result = key_manager.new_key(&serialized_format);
        tink_tests::expect_err(result, err_msg);
    }
    let result = key_manager.new_key(&[]);
    tink_tests::expect_err(result, "empty");
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_aead::init();
    let key_manager = tink_core::registry::get_key_manager(tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let invalid_keys = vec![
        (
            "version in range",
            AesCtrHmacAeadKey {
                version: 999, // invalid
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "invalid AES key size",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 1], // invalid
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "IV size out of range",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 0 }), // invalid
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "key too short",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 2], // invalid
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "unknown hash",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: 9999, // invalid
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "tag size too small",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 1, // invalid
                    }),
                }),
            },
        ),
        (
            "no AES key params",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: None, // invalid
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "no HMAC params",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: None, // invalid
                }),
            },
        ),
        (
            "no AES key",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: None, // invalid
                hmac_key: Some(tink_proto::HmacKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 32],
                    params: Some(tink_proto::HmacParams {
                        hash: HashType::Sha256 as i32,
                        tag_size: 16,
                    }),
                }),
            },
        ),
        (
            "no HMAC key",
            AesCtrHmacAeadKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                aes_ctr_key: Some(tink_proto::AesCtrKey {
                    version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                    key_value: vec![0; 16],
                    params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
                }),
                hmac_key: None, // invalid
            },
        ),
        /* All based on this valid key:
        AesCtrHmacAeadKey {
            version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
            aes_ctr_key: Some(tink_proto::AesCtrKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 16],
                params: Some(tink_proto::AesCtrParams { iv_size: 16 }),
            }),
            hmac_key: Some(tink_proto::HmacKey {
                version: tink_aead::AES_CTR_HMAC_AEAD_KEY_VERSION,
                key_value: vec![0; 32],
                params: Some(tink_proto::HmacParams {
                    hash: HashType::Sha256 as i32,
                    tag_size: 16,
                }),
            }),
        },
        */
    ];
    for (err_msg, key) in &invalid_keys {
        let serialized_key = tink_tests::proto_encode(key);
        let result = key_manager.primitive(&serialized_key);
        tink_tests::expect_err(result, err_msg);
    }
    let result = key_manager.primitive(&[]);
    tink_tests::expect_err(result, "empty");
}

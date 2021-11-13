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
use tink_core::{subtle::random::get_random_bytes, Signer, TinkError, Verifier};
use tink_proto::{
    prost::Message, EcdsaKeyFormat, EcdsaParams, EcdsaPrivateKey, EcdsaPublicKey,
    EcdsaSignatureEncoding, EllipticCurveType, HashType,
};

use super::common::*;

#[test]
fn test_ecdsa_signer_get_primitive_basic() {
    tink_signature::init();
    let test_params = gen_valid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let serialized_key = tink_tests::proto_encode(&tink_tests::new_random_ecdsa_private_key(
            test_param.hash_type,
            test_param.curve,
        ));
        assert!(
            km.primitive(&serialized_key).is_ok(),
            "unexpected error in test case {}",
            i
        );
    }
}

#[test]
fn test_ecdsa_sign_get_primitive_with_invalid_input() {
    tink_signature::init();
    // invalid params
    let test_params = gen_invalid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let serialized_key = tink_tests::proto_encode(&tink_tests::new_random_ecdsa_private_key(
            test_param.hash_type,
            test_param.curve,
        ));
        assert!(
            km.primitive(&serialized_key).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // invalid version
    let mut key =
        tink_tests::new_random_ecdsa_private_key(HashType::Sha256, EllipticCurveType::NistP256);
    key.version = tink_tests::ECDSA_SIGNER_KEY_VERSION + 1;
    let serialized_key = tink_tests::proto_encode(&key);
    assert!(
        km.primitive(&serialized_key).is_err(),
        "expect an error when version is invalid"
    );
    // empty input
    assert!(
        km.primitive(&[]).is_err(),
        "expect an error when input is empty slice"
    );
}

#[test]
fn test_ecdsa_sign_new_key_basic() {
    tink_signature::init();
    let test_params = gen_valid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let params = tink_tests::new_ecdsa_params(
            test_param.hash_type,
            test_param.curve,
            tink_proto::EcdsaSignatureEncoding::Der,
        );
        let serialized_format =
            tink_tests::proto_encode(&tink_tests::new_ecdsa_key_format(&params));
        let tmp = km.new_key(&serialized_format).unwrap();
        let key = tink_proto::EcdsaPrivateKey::decode(tmp.as_ref()).unwrap();
        assert!(
            validate_ecdsa_private_key(&key, &params).is_ok(),
            "invalid private key in test case {}",
            i
        );
    }
}

#[test]
fn test_ecdsa_sign_new_key_with_invalid_input() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    // invalid hash and curve type
    let test_params = vec![
        EcdsaParams {
            hash_type: HashType::UnknownHash as i32,
            curve: EllipticCurveType::NistP256 as i32,
            encoding: tink_proto::EcdsaSignatureEncoding::Der as i32,
        },
        EcdsaParams {
            hash_type: HashType::Sha256 as i32,
            curve: EllipticCurveType::UnknownCurve as i32,
            encoding: tink_proto::EcdsaSignatureEncoding::Der as i32,
        },
        EcdsaParams {
            hash_type: HashType::Sha256 as i32,
            curve: EllipticCurveType::NistP256 as i32,
            encoding: tink_proto::EcdsaSignatureEncoding::UnknownEncoding as i32,
        },
        EcdsaParams {
            hash_type: 9999,
            curve: EllipticCurveType::NistP256 as i32,
            encoding: tink_proto::EcdsaSignatureEncoding::Der as i32,
        },
        EcdsaParams {
            hash_type: HashType::Sha256 as i32,
            curve: 9999,
            encoding: tink_proto::EcdsaSignatureEncoding::Der as i32,
        },
        EcdsaParams {
            hash_type: HashType::Sha256 as i32,
            curve: EllipticCurveType::NistP256 as i32,
            encoding: 999,
        },
    ];
    for (i, params) in test_params.iter().enumerate() {
        let serialized_format = tink_tests::proto_encode(&tink_tests::new_ecdsa_key_format(params));
        assert!(
            km.new_key(&serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }

    // invalid encoding
    let test_params = gen_valid_ecdsa_params();
    for (i, test_param) in test_params.iter().enumerate() {
        let params = tink_tests::new_ecdsa_params(
            test_param.hash_type,
            test_param.curve,
            tink_proto::EcdsaSignatureEncoding::UnknownEncoding,
        );
        let serialized_format =
            tink_tests::proto_encode(&tink_tests::new_ecdsa_key_format(&params));
        assert!(
            km.new_key(&serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty input
    assert!(
        km.new_key(&[]).is_err(),
        "expect an error when input is empty slice"
    );
}

#[test]
fn test_ecdsa_sign_new_key_multiple_times() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    let test_params = gen_valid_ecdsa_params();
    let n_test = 27;
    for test_param in test_params {
        let mut keys = HashSet::new();
        let params = tink_tests::new_ecdsa_params(
            test_param.hash_type,
            test_param.curve,
            tink_proto::EcdsaSignatureEncoding::Der,
        );
        let format = tink_tests::new_ecdsa_key_format(&params);
        let serialized_format = tink_tests::proto_encode(&format);
        for _j in 0..n_test {
            let serialized_key = km.new_key(&serialized_format).unwrap();
            keys.insert(serialized_key);

            let key_data = km.new_key_data(&serialized_format).unwrap();
            let serialized_key = key_data.value;
            keys.insert(serialized_key);
        }
        assert_eq!(
            keys.len(),
            n_test * 2,
            "key is repeated with params: {:?}",
            params
        );
    }
}

#[test]
fn test_ecdsa_sign_new_key_data_basic() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    let test_params = gen_valid_ecdsa_params();
    for (i, test_param) in test_params.iter().enumerate() {
        let params = tink_tests::new_ecdsa_params(
            test_param.hash_type,
            test_param.curve,
            tink_proto::EcdsaSignatureEncoding::Der,
        );
        let serialized_format =
            tink_tests::proto_encode(&tink_tests::new_ecdsa_key_format(&params));

        let key_data = km
            .new_key_data(&serialized_format)
            .unwrap_or_else(|e| panic!("unexpected error in test case  {}: {:?}", i, e));
        assert_eq!(
            key_data.type_url,
            tink_tests::ECDSA_SIGNER_TYPE_URL,
            "incorrect type url in test case {}",
            i
        );
        assert_eq!(
            key_data.key_material_type,
            tink_proto::key_data::KeyMaterialType::AsymmetricPrivate as i32,
            "incorrect key material type in test case  {}",
            i
        );
        let key = tink_proto::EcdsaPrivateKey::decode(key_data.value.as_ref())
            .unwrap_or_else(|e| panic!("unexpected error in test case {}: {:?}", i, e));
        assert!(
            validate_ecdsa_private_key(&key, &params).is_ok(),
            "invalid private key in test case {}",
            i,
        );
    }
}

#[test]
fn test_ecdsa_sign_new_key_data_with_invalid_input() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    let test_params = gen_invalid_ecdsa_params();
    for (i, test_param) in test_params.iter().enumerate() {
        let params = tink_tests::new_ecdsa_params(
            test_param.hash_type,
            test_param.curve,
            tink_proto::EcdsaSignatureEncoding::Der,
        );
        let format = tink_tests::new_ecdsa_key_format(&params);
        let serialized_format = tink_tests::proto_encode(&format);

        assert!(
            km.new_key_data(&serialized_format).is_err(),
            "expect an error in test case  {}",
            i
        );
    }
    // empty input
    assert!(
        km.new_key_data(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_public_key_data_basic() {
    tink_signature::init();
    let test_params = gen_valid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    assert!(
        km.supports_private_keys(),
        "key manager does not support private keys"
    );
    for (i, test_param) in test_params.iter().enumerate() {
        let key = tink_tests::new_random_ecdsa_private_key(test_param.hash_type, test_param.curve);
        let serialized_key = tink_tests::proto_encode(&key);

        let pub_key_data = km
            .public_key_data(&serialized_key)
            .unwrap_or_else(|e| panic!("unexpected error in test case {}: {:?}", i, e));
        assert_eq!(
            pub_key_data.type_url,
            tink_tests::ECDSA_VERIFIER_TYPE_URL,
            "incorrect type url"
        );
        assert_eq!(
            pub_key_data.key_material_type,
            tink_proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
            "incorrect key material type"
        );
        let _pub_key = tink_proto::EcdsaPublicKey::decode(pub_key_data.value.as_ref())
            .expect("invalid public key");
    }
}

#[test]
fn test_public_key_data_with_invalid_input() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL)
        .expect("cannot obtain EcdsaSigner key manager");
    assert!(
        km.supports_private_keys(),
        "key manager does not support private keys"
    );
    // modified key
    let key =
        tink_tests::new_random_ecdsa_private_key(HashType::Sha256, EllipticCurveType::NistP256);
    let mut serialized_key = tink_tests::proto_encode(&key);
    serialized_key[0] = 0;
    assert!(
        km.public_key_data(&serialized_key).is_err(),
        "expect an error when input is a modified serialized key"
    );
    // empty slice
    assert!(
        km.public_key_data(&[]).is_err(),
        "expect an error when input is an empty slice"
    );
    // invalid with a single byte
    assert!(
        km.public_key_data(&[42]).is_err(),
        "expect an error when input is a single byte"
    );
}

fn validate_ecdsa_private_key(
    key: &tink_proto::EcdsaPrivateKey,
    params: &tink_proto::EcdsaParams,
) -> Result<(), TinkError> {
    if key.version != tink_tests::ECDSA_SIGNER_KEY_VERSION {
        return Err(format!(
            "incorrect private key's version: expect {}, got {}",
            tink_tests::ECDSA_SIGNER_KEY_VERSION,
            key.version
        )
        .into());
    }
    let public_key = key
        .public_key
        .as_ref()
        .ok_or_else(|| TinkError::new("no public key!"))?;
    if public_key.version != tink_tests::ECDSA_SIGNER_KEY_VERSION {
        return Err(format!(
            "incorrect public key's version: expect {}, got {}",
            tink_tests::ECDSA_SIGNER_KEY_VERSION,
            key.version
        )
        .into());
    }
    let key_params = public_key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no params!"))?;
    if params.hash_type != key_params.hash_type
        || params.curve != key_params.curve
        || params.encoding != key_params.encoding
    {
        return Err(format!(
            "incorrect params: expect {:?}, got {:?}",
            params, public_key.params
        )
        .into());
    }
    if public_key.x.is_empty() || public_key.y.is_empty() {
        return Err("public points are not initialized".into());
    }
    // check private key's size
    let key_size = key.key_value.len();
    match EllipticCurveType::from_i32(params.curve) {
        Some(EllipticCurveType::NistP256) => {
            if !(256 / 8 - 8..=256 / 8 + 1).contains(&key_size) {
                return Err("private key doesn't have adequate size".into());
            }
        }
        Some(EllipticCurveType::NistP384) => {
            if !(384 / 8 - 8..=384 / 8 + 1).contains(&key_size) {
                return Err("private key doesn't have adequate size".into());
            }
        }
        Some(EllipticCurveType::NistP521) => {
            if !(521 / 8 - 8..=521 / 8 + 1).contains(&key_size) {
                return Err("private key doesn't have adequate size".into());
            }
        }
        _ => return Err("unknown curve type".into()),
    }
    // try to sign and verify with the key
    let (hash, curve, encoding) = tink_tests::get_ecdsa_params(
        public_key
            .params
            .as_ref()
            .ok_or_else(|| TinkError::new("no params!"))?,
    );
    let signer = tink_signature::subtle::EcdsaSigner::new(hash, curve, encoding, &key.key_value)
        .expect("unexpected error when creating EcdsaSign");
    let verifier = tink_signature::subtle::EcdsaVerifier::new(
        hash,
        curve,
        encoding,
        &public_key.x,
        &public_key.y,
    )
    .expect("unexpected error when creating EcdsaVerify");
    let data = get_random_bytes(1281);
    let signature = signer.sign(&data).expect("unexpected error when signing");

    assert!(
        verifier.verify(&signature, &data).is_ok(),
        "unexpected error when verifying signature"
    );
    Ok(())
}

#[test]
fn test_key_manager_params() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL).unwrap();

    assert_eq!(km.type_url(), tink_tests::ECDSA_SIGNER_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::AsymmetricPrivate
    );
    assert!(km.supports_private_keys());
}

#[test]
fn test_new_key_with_invalid_format() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL).unwrap();

    let invalid_formats = vec![
        (
            "invalid hash type",
            EcdsaKeyFormat {
                params: Some(EcdsaParams {
                    hash_type: 9999, // invalid
                    curve: EllipticCurveType::NistP256 as i32,
                    encoding: EcdsaSignatureEncoding::Der as i32,
                }),
            },
        ),
        (
            "unsupported curve",
            EcdsaKeyFormat {
                params: Some(EcdsaParams {
                    hash_type: HashType::Sha256 as i32,
                    curve: 9999, // invalid
                    encoding: EcdsaSignatureEncoding::Der as i32,
                }),
            },
        ),
        (
            "invalid hash type",
            EcdsaKeyFormat {
                params: Some(EcdsaParams {
                    hash_type: HashType::Sha256 as i32,
                    curve: EllipticCurveType::NistP521 as i32,
                    encoding: EcdsaSignatureEncoding::Der as i32,
                }),
            },
        ),
        (
            "unsupported curve",
            EcdsaKeyFormat {
                params: Some(EcdsaParams {
                    hash_type: HashType::Sha512 as i32,
                    curve: EllipticCurveType::NistP521 as i32,
                    encoding: EcdsaSignatureEncoding::Der as i32,
                }),
            },
        ),
        (
            "unsupported encoding",
            EcdsaKeyFormat {
                params: Some(EcdsaParams {
                    hash_type: HashType::Sha256 as i32,
                    curve: EllipticCurveType::NistP256 as i32,
                    encoding: 9999, // invalid
                }),
            },
        ),
        (
            "invalid key format",
            EcdsaKeyFormat {
                params: None, // invalid
            },
        ),
        /* All based on this valid key format:
        EcdsaKeyFormat {
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
        },
         */
    ];
    for (err_msg, format) in &invalid_formats {
        let serialized_format = tink_tests::proto_encode(format);
        let result = km.new_key(&serialized_format);
        tink_tests::expect_err(result, err_msg);
    }
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_SIGNER_TYPE_URL).unwrap();
    let pub_x_data =
        hex::decode("7ea7cc506e46cfb2bbdb1503b0fb5f4edbf6e9830459b64a4064455045a7a58c").unwrap();
    let pub_y_data =
        hex::decode("fe38bbb204c8afab3691af996eeb78aa60b8c24ea6dbe13fb6df788786fb2230").unwrap();
    let secret_key_data =
        hex::decode("2fa00a02762046c8797d5cc62cd1ba41ecf11f0996e3c5169ca8c891af8055c3").unwrap();

    let invalid_keys = vec![
        (
            "only keys with version in range",
            EcdsaPrivateKey {
                version: 9999, // invalid
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "only keys with version in range",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: 9999, // invalid
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "invalid hash type",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: 9999, // invalid
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unsupported curve",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: 9999, // invalid
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unsupported encoding",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: 9999, // invalid
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "invalid key",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: vec![], // invalid
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "invalid key",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: vec![], // invalid
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "invalid private key",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: Some(EcdsaParams {
                        hash_type: HashType::Sha256 as i32,
                        curve: EllipticCurveType::NistP256 as i32,
                        encoding: EcdsaSignatureEncoding::Der as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: vec![], // invalid
            },
        ),
        (
            "no public key parameters",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: Some(EcdsaPublicKey {
                    version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                    params: None, // invalid
                    x: pub_x_data,
                    y: pub_y_data,
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "no public key",
            EcdsaPrivateKey {
                version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
                public_key: None,
                key_value: secret_key_data,
            },
        ),
        /* All based on this valid key:
        EcdsaPrivateKey {
            version: tink_signature::ECDSA_SIGNER_KEY_VERSION,
            public_key: Some(EcdsaPublicKey {
                version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
                params: Some(EcdsaParams {
                    hash_type: HashType::Sha256 as i32,
                    curve: EllipticCurveType::NistP256 as i32,
                    encoding: EcdsaSignatureEncoding::Der as i32,
                }),
                x: pub_x_data.clone(),
                y: pub_y_data.clone(),
            }),
            key_value: secret_key_data.clone(),
        },
         */
    ];
    for (err_msg, key) in &invalid_keys {
        let serialized_key = tink_tests::proto_encode(key);
        let result = km.primitive(&serialized_key);
        tink_tests::expect_err(result, err_msg);
    }
}

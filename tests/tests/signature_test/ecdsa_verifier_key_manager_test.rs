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

use tink_proto::{
    EcdsaParams, EcdsaPublicKey, EcdsaSignatureEncoding, EllipticCurveType, HashType,
};

use super::common::*;

#[test]
fn test_ecdsa_verify_get_primitive_basic() {
    tink_signature::init();
    let test_params = gen_valid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_VERIFIER_TYPE_URL)
        .expect("cannot obtain EcdsaVerifier key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let serialized_key = tink_tests::proto_encode(&tink_tests::new_random_ecdsa_public_key(
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
fn test_ecdsa_verify_get_primitive_with_invalid_input() {
    tink_signature::init();
    let test_params = gen_invalid_ecdsa_params();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_VERIFIER_TYPE_URL)
        .expect("cannot obtain EcdsaVerifier key manager");
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
    let mut key = tink_tests::new_random_ecdsa_public_key(
        tink_proto::HashType::Sha256,
        tink_proto::EllipticCurveType::NistP256,
    );
    key.version = tink_tests::ECDSA_VERIFIER_KEY_VERSION + 1;
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
fn test_new_key_fails() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_VERIFIER_TYPE_URL).unwrap();

    assert!(km.new_key(&[]).is_err());
    assert!(km.new_key_data(&[]).is_err());
}

#[test]
fn test_key_manager_params() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_VERIFIER_TYPE_URL).unwrap();

    assert_eq!(km.type_url(), tink_tests::ECDSA_VERIFIER_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    );
    assert!(!km.supports_private_keys());
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_signature::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECDSA_VERIFIER_TYPE_URL).unwrap();
    let pub_x_data =
        hex::decode("7ea7cc506e46cfb2bbdb1503b0fb5f4edbf6e9830459b64a4064455045a7a58c").unwrap();
    let pub_y_data =
        hex::decode("fe38bbb204c8afab3691af996eeb78aa60b8c24ea6dbe13fb6df788786fb2230").unwrap();

    let invalid_keys = vec![
        EcdsaPublicKey {
            version: 9999, // invalid
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: pub_x_data.clone(),
            y: pub_y_data.clone(),
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: 9999, // invalid
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: pub_x_data.clone(),
            y: pub_y_data.clone(),
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: 9999, // invalid
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: pub_x_data.clone(),
            y: pub_y_data.clone(),
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: 9999, // invalid
            }),
            x: pub_x_data.clone(),
            y: pub_y_data.clone(),
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: vec![], // invalid
            y: pub_y_data.clone(),
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: pub_x_data.clone(),
            y: vec![], // invalid
        },
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: None, // invalid
            x: pub_x_data,
            y: pub_y_data,
        },
        /* All based on this valid key:
        EcdsaPublicKey {
            version: tink_signature::ECDSA_VERIFIER_KEY_VERSION,
            params: Some(EcdsaParams {
                hash_type: HashType::Sha256 as i32,
                curve: EllipticCurveType::NistP256 as i32,
                encoding: EcdsaSignatureEncoding::Der as i32,
            }),
            x: pub_x_data.clone(),
            y: pub_y_data.clone(),
        },
         */
    ];
    for key in &invalid_keys {
        let serialized_key = tink_tests::proto_encode(key);
        assert!(
            km.primitive(&serialized_key).is_err(),
            "unexpected success with {:?}",
            key
        );
    }
}

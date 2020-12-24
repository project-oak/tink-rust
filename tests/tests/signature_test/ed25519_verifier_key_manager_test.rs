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

use tink_proto::Ed25519PublicKey;

#[test]
fn test_ed25519_verify_get_primitive_basic() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_tests::ED25519_VERIFIER_TYPE_URL)
        .expect("cannot obtain Ed25519Verifier key manager");
    let serialized_key = tink_tests::proto_encode(&tink_tests::new_ed25519_public_key());
    assert!(
        km.primitive(&serialized_key).is_ok(),
        "unexpected error in test case"
    );
}

#[test]
fn test_ed25519_verify_get_primitive_with_invalid_input() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_tests::ED25519_VERIFIER_TYPE_URL)
        .expect("cannot obtain Ed25519Verifier key manager");

    // invalid version
    let mut key = tink_tests::new_ed25519_public_key();
    key.version = tink_tests::ED25519_VERIFIER_KEY_VERSION + 1;
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
    let km = tink::registry::get_key_manager(tink_tests::ED25519_VERIFIER_TYPE_URL).unwrap();

    assert!(km.new_key(&[]).is_err());
    assert!(km.new_key_data(&[]).is_err());
}

#[test]
fn test_key_manager_params() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_tests::ED25519_VERIFIER_TYPE_URL).unwrap();

    assert_eq!(km.type_url(), tink_tests::ED25519_VERIFIER_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    );
    assert!(!km.supports_private_keys());
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_tests::ED25519_VERIFIER_TYPE_URL).unwrap();

    let invalid_keys = vec![
        Ed25519PublicKey {
            version: 9999, // invalid
            key_value: vec![0; 32],
        },
        Ed25519PublicKey {
            version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
            key_value: vec![0; 2], // invalid
        },
        Ed25519PublicKey {
            version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
            key_value: vec![], // invalid
        },
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

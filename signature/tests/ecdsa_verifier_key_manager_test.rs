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

mod common;
use common::*;

#[test]
fn test_ecdsa_verify_get_primitive_basic() {
    tink_signature::init();
    let test_params = gen_valid_ecdsa_params();
    let km = tink::registry::get_key_manager(tink_testutil::ECDSA_VERIFIER_TYPE_URL)
        .expect("cannot obtain EcdsaVerifier key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let serialized_key = tink_testutil::proto_encode(
            &tink_testutil::new_random_ecdsa_public_key(test_param.hash_type, test_param.curve),
        );
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
    let km = tink::registry::get_key_manager(tink_testutil::ECDSA_VERIFIER_TYPE_URL)
        .expect("cannot obtain EcdsaVerifier key manager");
    for (i, test_param) in test_params.iter().enumerate() {
        let serialized_key = tink_testutil::proto_encode(
            &tink_testutil::new_random_ecdsa_private_key(test_param.hash_type, test_param.curve),
        );
        assert!(
            km.primitive(&serialized_key).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // invalid version
    let mut key = tink_testutil::new_random_ecdsa_public_key(
        tink::proto::HashType::Sha256,
        tink::proto::EllipticCurveType::NistP256,
    );
    key.version = tink_testutil::ECDSA_VERIFIER_KEY_VERSION + 1;
    let serialized_key = tink_testutil::proto_encode(&key);
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

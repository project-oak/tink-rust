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
use tink::{
    proto::{Ed25519PrivateKey, Ed25519PublicKey},
    subtle::random::get_random_bytes,
    utils::wrap_err,
    Signer, TinkError, Verifier,
};

#[test]
fn test_ed25519_signer_get_primitive_basic() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL)
        .expect("cannot obtain Ed25519Signer key manager");
    let pvt_key = tink_testutil::new_ed25519_private_key();
    let serialized_key = tink_testutil::proto_encode(&pvt_key);
    let tmp = km
        .primitive(&serialized_key)
        .expect("unexpected error in test case");
    let s = match tmp {
        tink::Primitive::Signer(s) => s,
        _ => panic!("unexpected primitive type"),
    };

    let km_pub = tink::registry::get_key_manager(tink_testutil::ED25519_VERIFIER_TYPE_URL)
        .expect("cannot obtain Ed25519Verifier key manager");
    let pub_key = pvt_key.public_key.unwrap();
    let serialized_key = tink_testutil::proto_encode(&pub_key);
    let tmp = km_pub
        .primitive(&serialized_key)
        .expect("unexpected error in test case");
    let v = match tmp {
        tink::Primitive::Verifier(v) => v,
        _ => panic!("unexpected primitive type"),
    };

    let data = get_random_bytes(1281);
    let signature = s.sign(&data).expect("unexpected error when signing");

    assert!(
        v.verify(&signature, &data).is_ok(),
        "unexpected error when verifying signature"
    );
}

#[test]
fn test_ed25519_sign_get_primitive_with_invalid_input() {
    tink_signature::init();
    // invalid params
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL)
        .expect("cannot obtain Ed25519Signer key manager");

    // invalid version
    let mut key = tink_testutil::new_ed25519_private_key();
    key.version = tink_testutil::ED25519_SIGNER_KEY_VERSION + 1;
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

#[test]
fn test_ed25519_sign_new_key_basic() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL)
        .expect("cannot obtain Ed25519Signer key manager");
    let serialized_format = tink_testutil::proto_encode(&tink_testutil::new_ed25519_private_key());
    let tmp = km.new_key(&serialized_format).unwrap();
    let key = tink::proto::Ed25519PrivateKey::decode(tmp.as_ref()).unwrap();
    assert!(
        validate_ed25519_private_key(&key).is_ok(),
        "invalid private key in test case"
    );
}

#[test]
fn test_ed25519_public_key_data_basic() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL)
        .expect("cannot obtain Ed25519Signer key manager");
    assert!(
        km.supports_private_keys(),
        "key manager does not support private keys"
    );

    let key = tink_testutil::new_ed25519_private_key();
    let serialized_key = tink_testutil::proto_encode(&key);

    let pub_key_data = km.public_key_data(&serialized_key).unwrap();
    assert_eq!(
        pub_key_data.type_url,
        tink_testutil::ED25519_VERIFIER_TYPE_URL,
        "incorrect type url"
    );
    assert_eq!(
        pub_key_data.key_material_type,
        tink::proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
        "incorrect key material type"
    );
    assert!(
        tink::proto::Ed25519PublicKey::decode(pub_key_data.value.as_ref()).is_ok(),
        "invalid public key"
    );
}

#[test]
fn test_ed25519_public_key_data_with_invalid_input() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL)
        .expect("cannot obtain Ed25519Signer key manager");
    assert!(
        km.supports_private_keys(),
        "key manager does not support private keys"
    );
    // modified key
    let key = tink_testutil::new_ed25519_private_key();
    let mut serialized_key = tink_testutil::proto_encode(&key);
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
}

fn validate_ed25519_private_key(key: &tink::proto::Ed25519PrivateKey) -> Result<(), TinkError> {
    if key.version != tink_testutil::ED25519_SIGNER_KEY_VERSION {
        return Err(format!(
            "incorrect private key's version: expect {}, got {}",
            tink_testutil::ED25519_SIGNER_KEY_VERSION,
            key.version
        )
        .into());
    }
    let public_key = key.public_key.as_ref().unwrap();
    if public_key.version != tink_testutil::ED25519_SIGNER_KEY_VERSION {
        return Err(format!(
            "incorrect public key's version: expect {}, got {}",
            tink_testutil::ED25519_SIGNER_KEY_VERSION,
            key.version
        )
        .into());
    }

    let signer = tink_signature::subtle::Ed25519Signer::new(&key.key_value)
        .map_err(|e| wrap_err("unexpected error when creating Ed25519Sign", e))?;

    let verifier = tink_signature::subtle::Ed25519Verifier::new(&public_key.key_value)
        .map_err(|e| wrap_err("unexpected error when creating ED25519Verify: {}", e))?;
    for _i in 0..100 {
        let data = get_random_bytes(1281);
        let signature = signer
            .sign(&data)
            .map_err(|e| wrap_err("unexpected error when signing", e))?;
        verifier
            .verify(&signature, &data)
            .map_err(|e| wrap_err("unexpected error when verifying signature", e))?;
    }
    Ok(())
}

#[test]
fn test_key_manager_params() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL).unwrap();

    assert_eq!(km.type_url(), tink_testutil::ED25519_SIGNER_TYPE_URL);
    assert_eq!(
        km.key_material_type(),
        tink::proto::key_data::KeyMaterialType::AsymmetricPrivate
    );
    assert!(km.supports_private_keys());
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_signature::init();
    let km = tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL).unwrap();

    let invalid_keys = vec![
        Ed25519PrivateKey {
            version: 9999, // invalid
            key_value: vec![0; 32],
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![0; 32],
            }),
        },
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![0; 2], // invalid
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![0; 32],
            }),
        },
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![], // invalid
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![0; 32],
            }),
        },
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![0; 32],
            public_key: Some(Ed25519PublicKey {
                version: 9999, // invalid
                key_value: vec![0; 32],
            }),
        },
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![0; 32],
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![0; 2], // invalid
            }),
        },
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![0; 32],
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![], // invalid
            }),
        },
        /* All based on this valid key:
        Ed25519PrivateKey {
            version: tink_signature::ED25519_SIGNER_KEY_VERSION,
            key_value: vec![0; 32],
            public_key: Some(Ed25519PublicKey {
                version: tink_signature::ED25519_VERIFIER_KEY_VERSION,
                key_value: vec![0; 32],
            }),
        },
         */
    ];
    for key in &invalid_keys {
        let serialized_key = tink_testutil::proto_encode(key);
        assert!(
            km.primitive(&serialized_key).is_err(),
            "unexpected success with {:?}",
            key
        );
    }
}

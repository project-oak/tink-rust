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

use tink_core::{keyset, subtle::random::get_random_bytes};

#[test]
fn test_validate_key_version() {
    assert!(keyset::validate_key_version(2, 1).is_err());
    assert!(keyset::validate_key_version(1, 1).is_ok());
    assert!(keyset::validate_key_version(1, 2).is_ok());
}

#[test]
fn test_validate() {
    // empty keyset
    let empty_keys = vec![];
    assert!(
        keyset::validate(&tink_tests::new_keyset(1, empty_keys)).is_err(),
        "expect an error when keyset is empty"
    );
    // no primary key
    let keys = vec![tink_tests::new_dummy_key(
        1,
        tink_proto::KeyStatusType::Enabled,
        tink_proto::OutputPrefixType::Tink,
    )];
    assert!(
        keyset::validate(&tink_tests::new_keyset(2, keys)).is_err(),
        "expect an error when there is no primary key"
    );
    // primary key is disabled
    let keys = vec![
        tink_tests::new_dummy_key(
            1,
            tink_proto::KeyStatusType::Enabled,
            tink_proto::OutputPrefixType::Tink,
        ),
        tink_tests::new_dummy_key(
            2,
            tink_proto::KeyStatusType::Disabled,
            tink_proto::OutputPrefixType::Legacy,
        ),
    ];
    assert!(
        keyset::validate(&tink_tests::new_keyset(2, keys)).is_err(),
        "expect an error when primary key is disabled"
    );
    // multiple primary keys
    let keys = vec![
        tink_tests::new_dummy_key(
            1,
            tink_proto::KeyStatusType::Enabled,
            tink_proto::OutputPrefixType::Tink,
        ),
        tink_tests::new_dummy_key(
            1,
            tink_proto::KeyStatusType::Enabled,
            tink_proto::OutputPrefixType::Legacy,
        ),
    ];
    assert!(
        keyset::validate(&tink_tests::new_keyset(1, keys)).is_err(),
        "expect an error when there are multiple primary keys"
    );
    // invalid keys
    let invalid_keys = generate_invalid_keys();
    for (i, key) in invalid_keys.into_iter().enumerate() {
        assert!(
            keyset::validate(&tink_tests::new_keyset(1, vec![key])).is_err(),
            "expect an error when validate invalid key {}",
            i
        );
    }
    // no primary keys
    let keys = vec![
        tink_tests::new_dummy_key(
            1,
            tink_proto::KeyStatusType::Disabled,
            tink_proto::OutputPrefixType::Tink,
        ),
        tink_tests::new_dummy_key(
            1,
            tink_proto::KeyStatusType::Disabled,
            tink_proto::OutputPrefixType::Legacy,
        ),
    ];
    assert!(
        keyset::validate(&tink_tests::new_keyset(1, keys)).is_err(),
        "expect an error when there are no primary keys"
    );
    // public key only
    let keys = vec![tink_tests::new_key(
        &tink_tests::new_key_data(
            tink_tests::ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL,
            &get_random_bytes(10),
            tink_proto::key_data::KeyMaterialType::AsymmetricPublic,
        ),
        tink_proto::KeyStatusType::Enabled,
        1,
        tink_proto::OutputPrefixType::Tink,
    )];
    assert!(
        keyset::validate(&tink_tests::new_keyset(1, keys)).is_ok(),
        "valid test failed when using public key only"
    );
    // private key
    let keys = vec![
        tink_tests::new_key(
            &tink_tests::new_key_data(
                tink_tests::ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL,
                &get_random_bytes(10),
                tink_proto::key_data::KeyMaterialType::AsymmetricPublic,
            ),
            tink_proto::KeyStatusType::Enabled,
            1,
            tink_proto::OutputPrefixType::Tink,
        ),
        tink_tests::new_key(
            &tink_tests::new_key_data(
                tink_tests::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL,
                &get_random_bytes(10),
                tink_proto::key_data::KeyMaterialType::AsymmetricPrivate,
            ),
            tink_proto::KeyStatusType::Enabled,
            1,
            tink_proto::OutputPrefixType::Tink,
        ),
    ];
    assert!(
        keyset::validate(&tink_tests::new_keyset(1, keys)).is_err(),
        "expect an error when there are keydata other than public"
    );
}

fn generate_invalid_keys() -> Vec<tink_proto::keyset::Key> {
    vec![
        // unknown status
        tink_tests::new_key(
            &tink_proto::KeyData::default(),
            tink_proto::KeyStatusType::UnknownStatus,
            1,
            tink_proto::OutputPrefixType::Tink,
        ),
        // unknown prefix
        tink_tests::new_key(
            &tink_proto::KeyData::default(),
            tink_proto::KeyStatusType::Enabled,
            1,
            tink_proto::OutputPrefixType::UnknownPrefix,
        ),
        // zero key id
        tink_tests::new_key(
            &tink_proto::KeyData::default(),
            tink_proto::KeyStatusType::Enabled,
            0,
            tink_proto::OutputPrefixType::Tink,
        ),
        // no key_data
        tink_proto::keyset::Key {
            key_data: None,
            status: tink_proto::KeyStatusType::Enabled as i32,
            key_id: 1,
            output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
        },
    ]
}

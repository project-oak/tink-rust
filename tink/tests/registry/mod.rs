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
use std::sync::Arc;

#[test]
fn test_register_key_manager() {
    tink_mac::init();
    // get HMACKeyManager
    tink::registry::get_key_manager(tink_testutil::HMAC_TYPE_URL).unwrap();
    /* TODO: enable when tink-aead crate is available.
        // get AESGCMKeyManager
        tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL).unwrap();
    */
    // some random typeurl
    assert!(
        tink::registry::get_key_manager("some url").is_err(),
        "expect an error when a type url doesn't exist in the registry"
    );
}

/* TODO: enable when tink-aead crate is available.
#[test]
#[ignore]
fn test_register_key_manager_with_collision() {
    tink_aead::init();
    // dummy_key_manager's type_url is equal to that of AES-GCM by default.
    let dummy_key_manager = Arc::new(tink_testutil::DummyAeadKeyManager::default());
    // This should fail because overwriting is disallowed.
    assert!(
        tink::registry::register_key_manager(dummy_key_manager).is_err(),
        "AES_GCM_TYPE_URL shouldn't be registered again",
    );
}
*/

#[test]
fn test_register_key_manager_duplicate() {
    let dummy_key_manager = Arc::new(tink_testutil::DummyAeadKeyManager {
        type_url: "blah".to_string(),
    });
    tink::registry::register_key_manager(dummy_key_manager.clone()).unwrap();

    // This should fail because overwriting is disallowed.
    assert!(
        tink::registry::register_key_manager(dummy_key_manager).is_err(),
        "Shouldn't allow double registration",
    );
}

#[test]
fn test_new_key_data() {
    tink_mac::init();
    // new KeyData from a Hmac KeyTemplate
    let key_data =
        tink::registry::new_key_data(&tink_mac::hmac_sha256_tag128_key_template()).unwrap();
    assert_eq!(
        tink_testutil::HMAC_TYPE_URL,
        key_data.type_url,
        "invalid key data"
    );
    let _key = tink::proto::HmacKey::decode(key_data.value.as_ref())
        .expect("unexpected error when unmarshal HmacKey");

    // unregistered type url
    let template = tink::proto::KeyTemplate {
        type_url: "some url".to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
        value: vec![0],
    };
    assert!(
        tink::registry::new_key_data(&template).is_err(),
        "expect an error when key template contains unregistered type_url"
    );
}

/* TODO: enable when tink-aead crate is available.
#[test]
fn test_new_key() {
    tink_aead::init();
    // aead template
    let aes_gcm_template = tink_aead::aes128_gcm_key_template();
    let key = tink::registry::new_key(aes_gcm_template).unwrap();

    let aes_gcm_key: tink::proto::AesGcmKey = key;

    let aes_gcm_format =
        tink::proto::AesGcmKeyFormat::decode(aes_gcm_template.value.as_ref()).unwrap();
    assert_eq!(
        aes_gcm_key.key_value.len(),
        aes_gcm_format.key_size as usize
    );

    // unregistered type url
    let template = tink::proto::KeyTemplate {
        type_url: "some url".to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
        value: vec![0],
    };
    assert!(
        tink::registry::new_key(&template).is_err(),
        "expect an error when key template is not registered"
    );
}
*/

#[test]
fn test_primitive_from_key_data() {
    tink_mac::init();
    // hmac keydata
    let mut key_data = tink_testutil::new_hmac_key_data(tink::proto::HashType::Sha256, 16);
    let p = tink::registry::primitive_from_key_data(&key_data).unwrap();
    if let tink::Primitive::Mac(_) = p {
    } else {
        panic!("Primitive not a Mac");
    }

    // unregistered url
    key_data.type_url = "some url".to_string();
    assert!(
        tink::registry::primitive_from_key_data(&key_data).is_err(),
        "expect an error when type_url has not been registered"
    );
    // unmatched url
    key_data.type_url = tink_testutil::AES_GCM_TYPE_URL.to_string();
    assert!(
        tink::registry::primitive_from_key_data(&key_data).is_err(),
        "expect an error when type_url doesn't match key"
    );
}

#[test]
fn test_primitive() {
    tink_mac::init();
    // hmac key
    let key = tink_testutil::new_hmac_key(tink::proto::HashType::Sha256, 16);
    let mut serialized_key = vec![];
    key.encode(&mut serialized_key).unwrap();
    let p = tink::registry::primitive(tink_testutil::HMAC_TYPE_URL, &serialized_key).unwrap();
    if let tink::Primitive::Mac(_) = p {
    } else {
        panic!("Primitive not a Mac");
    }

    // unregistered url
    assert!(
        tink::registry::primitive("some url", &serialized_key).is_err(),
        "expect an error when type_url has not been registered"
    );
    // unmatched url
    assert!(
        tink::registry::primitive(tink_testutil::AES_GCM_TYPE_URL, &serialized_key).is_err(),
        "expect an error when type_url doesn't match key"
    );
    // empty key
    assert!(
        tink::registry::primitive(tink_testutil::AES_GCM_TYPE_URL, &[]).is_err(),
        "expect an error when key is empty"
    );
    assert!(
        tink::registry::primitive(tink_testutil::AES_GCM_TYPE_URL, &[0]).is_err(),
        "expect an error when key is short"
    );
}

#[test]
fn test_register_kms_client() {
    let kms = tink_testutil::DummyKmsClient {};
    tink::registry::register_kms_client(kms);

    tink::registry::get_kms_client("dummy").expect("error fetching dummy kms client");
}

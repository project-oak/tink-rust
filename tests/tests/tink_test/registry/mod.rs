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
    tink_aead::init();
    // get HMACKeyManager
    let km = tink_core::registry::get_key_manager(tink_tests::HMAC_TYPE_URL).unwrap();
    // get AESGCMKeyManager
    tink_core::registry::get_key_manager(tink_tests::AES_GCM_TYPE_URL).unwrap();
    // some random typeurl
    assert!(
        tink_core::registry::get_key_manager("some url").is_err(),
        "expect an error when a type url doesn't exist in the registry"
    );

    // HMACKeyManager is symmetric
    assert!(!km.supports_private_keys());
    assert!(km.public_key_data(&[]).is_err());
}

#[test]
fn test_register_key_manager_with_collision() {
    tink_aead::init();
    // dummy_key_manager's type_url is equal to that of AES-GCM by default.
    let dummy_key_manager = Arc::new(tink_tests::DummyAeadKeyManager::default());
    // This should fail because overwriting is disallowed.
    assert!(
        tink_core::registry::register_key_manager(dummy_key_manager).is_err(),
        "AES_GCM_TYPE_URL shouldn't be registered again",
    );
}

#[test]
fn test_register_key_manager_duplicate() {
    let dummy_key_manager = Arc::new(tink_tests::DummyAeadKeyManager { type_url: "blah" });
    tink_core::registry::register_key_manager(dummy_key_manager.clone()).unwrap();

    // This should fail because overwriting is disallowed.
    assert!(
        tink_core::registry::register_key_manager(dummy_key_manager).is_err(),
        "Shouldn't allow double registration",
    );
}

#[test]
fn test_new_key_data() {
    tink_mac::init();
    // new KeyData from a Hmac KeyTemplate
    let key_data =
        tink_core::registry::new_key_data(&tink_mac::hmac_sha256_tag128_key_template()).unwrap();
    assert_eq!(
        tink_tests::HMAC_TYPE_URL,
        key_data.type_url,
        "invalid key data"
    );
    let _key = tink_proto::HmacKey::decode(key_data.value.as_ref())
        .expect("unexpected error when unmarshal HmacKey");

    // unregistered type url
    let template = tink_proto::KeyTemplate {
        type_url: "some url".to_string(),
        output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
        value: vec![0],
    };
    assert!(
        tink_core::registry::new_key_data(&template).is_err(),
        "expect an error when key template contains unregistered type_url"
    );
}

#[test]
fn test_new_key() {
    tink_aead::init();
    // aead template
    let aes_gcm_template = tink_aead::aes128_gcm_key_template();
    let key = tink_core::registry::new_key(&aes_gcm_template).unwrap();

    let aes_gcm_key = tink_proto::AesGcmKey::decode(key.as_ref()).unwrap();

    let aes_gcm_format =
        tink_proto::AesGcmKeyFormat::decode(aes_gcm_template.value.as_ref()).unwrap();
    assert_eq!(
        aes_gcm_key.key_value.len(),
        aes_gcm_format.key_size as usize
    );

    // unregistered type url
    let template = tink_proto::KeyTemplate {
        type_url: "some url".to_string(),
        output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
        value: vec![0],
    };
    assert!(
        tink_core::registry::new_key(&template).is_err(),
        "expect an error when key template is not registered"
    );
}

#[test]
fn test_primitive_from_key_data() {
    tink_mac::init();
    // hmac keydata
    let mut key_data = tink_tests::new_hmac_key_data(tink_proto::HashType::Sha256, 16);
    let p = tink_core::registry::primitive_from_key_data(&key_data).unwrap();
    if let tink_core::Primitive::Mac(_) = p {
    } else {
        panic!("Primitive not a Mac");
    }

    // unregistered url
    key_data.type_url = "some url".to_string();
    assert!(
        tink_core::registry::primitive_from_key_data(&key_data).is_err(),
        "expect an error when type_url has not been registered"
    );
    // unmatched url
    key_data.type_url = tink_tests::AES_GCM_TYPE_URL.to_string();
    assert!(
        tink_core::registry::primitive_from_key_data(&key_data).is_err(),
        "expect an error when type_url doesn't match key"
    );
}

#[test]
fn test_primitive() {
    tink_mac::init();
    // hmac key
    let key = tink_tests::new_hmac_key(tink_proto::HashType::Sha256, 16);
    let mut serialized_key = vec![];
    key.encode(&mut serialized_key).unwrap();
    let p = tink_core::registry::primitive(tink_tests::HMAC_TYPE_URL, &serialized_key).unwrap();
    if let tink_core::Primitive::Mac(_) = p {
    } else {
        panic!("Primitive not a Mac");
    }

    // unregistered url
    assert!(
        tink_core::registry::primitive("some url", &serialized_key).is_err(),
        "expect an error when type_url has not been registered"
    );
    // unmatched url
    assert!(
        tink_core::registry::primitive(tink_tests::AES_GCM_TYPE_URL, &serialized_key).is_err(),
        "expect an error when type_url doesn't match key"
    );
    // empty key
    assert!(
        tink_core::registry::primitive(tink_tests::AES_GCM_TYPE_URL, &[]).is_err(),
        "expect an error when key is empty"
    );
    assert!(
        tink_core::registry::primitive(tink_tests::AES_GCM_TYPE_URL, &[0]).is_err(),
        "expect an error when key is short"
    );
}

#[test]
fn test_register_kms_client() {
    let kms = tink_tests::DummyKmsClient {};
    tink_core::registry::register_kms_client(kms);

    tink_core::registry::get_kms_client("dummy").expect("error fetching dummy kms client");
}

fn dummy_key_generator() -> tink_proto::KeyTemplate {
    tink_proto::KeyTemplate {
        type_url: "TEST".to_string(),
        value: vec![],
        output_prefix_type: 0,
    }
}

#[test]
fn test_get_template_generator() {
    let dummy_name = "TEST".to_string();
    tink_core::registry::register_template_generator(&dummy_name, dummy_key_generator);
    let generator = tink_core::registry::get_template_generator(&dummy_name).unwrap();
    assert_eq!(generator().type_url, "TEST");
    let names = tink_core::registry::template_names();
    assert!(names.contains(&dummy_name));
}

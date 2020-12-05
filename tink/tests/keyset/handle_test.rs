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

use std::sync::Arc;
use tink::{
    keyset::{insecure, Handle},
    proto::{key_data::KeyMaterialType, KeyData},
    TinkError,
};

#[test]
fn test_new_handle() {
    tink_mac::init();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    let kh = Handle::new(&kt).unwrap();
    let ks = insecure::keyset_material(&kh);
    assert_eq!(1, ks.key.len(), "incorrect number of keys in the keyset");
    let key = ks.key[0].clone();
    assert_eq!(ks.primary_key_id, key.key_id, "incorrect primary key id");
    assert_eq!(
        key.key_data.unwrap().type_url,
        kt.type_url,
        "incorrect type url"
    );
    assert!(
        tink_mac::new(&kh).is_ok(),
        "cannot get primitive from generated keyset handle"
    );
}

#[test]
fn test_new_handle_with_invalid_input() {
    tink_mac::init();
    // template unregistered type_url
    let mut template = tink_mac::hmac_sha256_tag128_key_template();
    template.type_url = "some unknown type_url".to_string();
    assert!(
        Handle::new(&template).is_err(),
        "expect an error when type_url is not registered"
    );
}

#[test]
fn test_read() {
    let main_key = Box::new(tink_aead::subtle::AesGcm::new(&[b'A'; 32]).unwrap());

    // Create a keyset
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[42, 42, 0x42, 0x42, 0o42, 0o42], // 42 in all possible formats
        KeyMaterialType::Symmetric,
    );
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    // Also check that debug output of handle doesn't include key material.
    let debug_output = format!("{:?}", h);
    assert!(!debug_output.contains("42"));

    let mem_keyset = &mut tink::keyset::MemReaderWriter::default();
    assert!(h.write(mem_keyset, main_key.clone()).is_ok());
    let h2 = Handle::read(mem_keyset, main_key).unwrap();
    assert_eq!(
        insecure::keyset_material(&h),
        insecure::keyset_material(&h2),
        "Decrypt failed: got {:?}, want {:?}",
        h2,
        h
    );
}

#[test]
fn test_read_with_no_secrets() {
    // Create a keyset containing public key material
    let key_data =
        tink_testutil::new_key_data("some type url", &[0], KeyMaterialType::AsymmetricPublic);
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    let mem_keyset = &mut tink::keyset::MemReaderWriter::default();
    assert!(h.write_with_no_secrets(mem_keyset).is_ok());
    let h2 = Handle::read_with_no_secrets(mem_keyset).unwrap();

    assert_eq!(
        insecure::keyset_material(&h),
        insecure::keyset_material(&h2),
        "Decrypt failed: got {:?}, want {:?}",
        h2,
        h
    );
}

#[test]
fn test_with_no_secrets_functions_fail_when_handling_secret_key_material() {
    // Create a keyset containing secret key material (symmetric)
    let key_data = tink_testutil::new_key_data("some type url", &[0], KeyMaterialType::Symmetric);
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    assert!(
        h.write_with_no_secrets(&mut tink::keyset::MemReaderWriter::default())
            .is_err(),
        "handle.write_with_no_secrets() should fail when exporting secret key material"
    );

    assert!(
        Handle::read_with_no_secrets(&mut tink::keyset::MemReaderWriter {
            keyset: Some(insecure::keyset_material(&h)),
            ..Default::default()
        })
        .is_err(),
        "keyset.read_with_no_secrets should fail when importing secret key material"
    );
}

#[test]
fn test_with_no_secrets_functions_fail_when_unknown_key_material() {
    // Create a keyset containing secret key material (symmetric)
    let key_data =
        tink_testutil::new_key_data("some type url", &[0], KeyMaterialType::UnknownKeymaterial);
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    assert!(
        h.write_with_no_secrets(&mut tink::keyset::MemReaderWriter::default())
            .is_err(),
        "handle.write_with_no_secrets() should fail when exporting secret key material"
    );

    assert!(
        Handle::read_with_no_secrets(&mut tink::keyset::MemReaderWriter {
            keyset: Some(insecure::keyset_material(&h)),
            ..Default::default()
        })
        .is_err(),
        "keyset.read_with_no_secrets should fail when importing secret key material"
    );
}

#[test]
fn test_with_no_secrets_functions_fail_with_asymmetric_private_key_material() {
    // Create a keyset containing secret key material (asymmetric)
    let key_data =
        tink_testutil::new_key_data("some type url", &[0], KeyMaterialType::AsymmetricPrivate);
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    assert!(
        h.write_with_no_secrets(&mut tink::keyset::MemReaderWriter::default())
            .is_err(),
        "handle.write_with_no_secrets() should fail when exporting secret key material"
    );

    assert!(
        Handle::read_with_no_secrets(&mut tink::keyset::MemReaderWriter {
            keyset: Some(insecure::keyset_material(&h)),
            ..Default::default()
        })
        .is_err(),
        "keyset.read_with_no_secrets should fail when importing secret key material"
    );
}

#[test]
fn test_keyset_info() {
    tink_mac::init();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    let kh = tink::keyset::Handle::new(&kt).unwrap();
    let info = kh.keyset_info();
    assert_eq!(info.primary_key_id, info.key_info[0].key_id);
}

#[test]
fn test_invalid_keyset() {
    tink_mac::init();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    let kh = Handle::new(&kt).unwrap();

    let mut invalid_ks = insecure::keyset_material(&kh);
    invalid_ks.key[0].key_data = None;
    assert!(insecure::new_handle(invalid_ks).is_err());

    let mut invalid_ks = insecure::keyset_material(&kh);
    invalid_ks.key.clear();
    assert!(insecure::new_handle(invalid_ks).is_err());
}

#[test]
fn test_invalid_keyset_from_manager() {
    // Use a key manager that generates invalid `KeyData`.
    pub struct InvalidKeyManager {}

    impl tink::registry::KeyManager for InvalidKeyManager {
        fn primitive(&self, _serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
            Err("not implemented".into())
        }

        fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
            Err("not implemented".into())
        }

        fn type_url(&self) -> &'static str {
            "InvalidKeyGenerator"
        }

        fn key_material_type(&self) -> KeyMaterialType {
            KeyMaterialType::Symmetric
        }

        fn new_key_data(&self, _serialized_key_format: &[u8]) -> Result<KeyData, TinkError> {
            Ok(KeyData {
                key_material_type: 9999,
                type_url: self.type_url().to_string(),
                value: vec![],
            })
        }
    }
    tink::registry::register_key_manager(Arc::new(InvalidKeyManager {})).unwrap();
    let kt = tink::proto::KeyTemplate {
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
        type_url: "InvalidKeyGenerator".to_string(),
        value: vec![],
    };

    assert!(tink::keyset::Handle::new(&kt).is_err());
}

#[test]
fn test_destroyed_key_keyset() {
    tink_mac::init();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    let kh = Handle::new(&kt).unwrap();

    let mut ks = insecure::keyset_material(&kh);
    ks.key[0].key_data = None;
    ks.key[0].status = tink::proto::KeyStatusType::Destroyed as i32;
    let kh = insecure::new_handle(ks).unwrap();
    let info = kh.keyset_info();
    assert_eq!(info.primary_key_id, info.key_info[0].key_id);
    // The type_url for a destroyed key is not available.
    assert_eq!(info.key_info[0].type_url, "");
}

#[test]
fn test_handle_public() {
    tink_signature::init();
    let kh = Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();

    let kh_public = kh.public().unwrap();

    let ks = insecure::keyset_material(&kh_public);
    assert_eq!(
        ks.key[0].key_data.as_ref().unwrap().key_material_type,
        KeyMaterialType::AsymmetricPublic as i32
    );

    // handle.public() only works for asymmetric private keys.
    let result = kh_public.public();
    tink_testutil::expect_err(result, "contains a non-private key");
}

#[test]
fn test_handle_public_destroyed_key() {
    tink_signature::init();

    let mut ksm = tink::keyset::Manager::new();
    ksm.rotate(&tink_signature::ecdsa_p256_key_template())
        .unwrap();
    let key_id = ksm
        .add(
            &tink_signature::ecdsa_p256_key_template(),
            /* primary= */ false,
        )
        .unwrap();
    ksm.destroy(key_id).unwrap();
    let kh = ksm.handle().unwrap();

    let result = kh.public();
    tink_testutil::expect_err(result, "invalid keyset");
}

#[test]
fn test_handle_public_wrong_keymanager() {
    tink_mac::init();
    tink_signature::init();
    let kh = Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();

    // Manually corrupt the keyset to refer to the wrong key manager.
    let mut ks = insecure::keyset_material(&kh);
    ks.key[0].key_data.as_mut().unwrap().type_url = tink_testutil::HMAC_TYPE_URL.to_string();
    let invalid_kh = insecure::new_handle(ks).unwrap();

    let result = invalid_kh.public();
    tink_testutil::expect_err(result, "handles private keys");
}

#[test]
fn test_mem_read_with_no_secrets_empty() {
    let result = Handle::read_with_no_secrets(&mut tink::keyset::MemReaderWriter::default());
    tink_testutil::expect_err(result, "no keyset available");
}

#[test]
fn test_mem_read_empty() {
    let main_key = Box::new(tink_aead::subtle::AesGcm::new(&[b'A'; 32]).unwrap());
    let result = Handle::read(&mut tink::keyset::MemReaderWriter::default(), main_key);
    tink_testutil::expect_err(result, "no keyset available");
}

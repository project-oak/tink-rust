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
use tink::keyset::{insecure, Handle};

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
    let master_key = Arc::new(tink_aead::subtle::AesGcm::new(&[b'A'; 32]).unwrap());

    // Create a keyset
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[0],
        tink::proto::key_data::KeyMaterialType::Symmetric,
    );
    let key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        1,
        tink::proto::OutputPrefixType::Tink,
    );
    let ks = tink_testutil::new_keyset(1, vec![key]);
    let h = insecure::new_handle(ks).unwrap();

    let mem_keyset = &mut tink::keyset::MemReaderWriter::default();
    assert!(h.write(mem_keyset, master_key.clone()).is_ok());
    let h2 = Handle::read(mem_keyset, master_key).unwrap();
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
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[0],
        tink::proto::key_data::KeyMaterialType::AsymmetricPublic,
    );
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
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[0],
        tink::proto::key_data::KeyMaterialType::Symmetric,
    );
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
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[0],
        tink::proto::key_data::KeyMaterialType::UnknownKeymaterial,
    );
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
    let key_data = tink_testutil::new_key_data(
        "some type url",
        &[0],
        tink::proto::key_data::KeyMaterialType::AsymmetricPrivate,
    );
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

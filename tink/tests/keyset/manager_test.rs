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

use tink::keyset::insecure;

#[test]
fn test_keyset_manager_basic() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm = tink::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm.rotate(&kt)
        .expect("cannot rotate when key template is available");
    let h = ksm.handle().expect("cannot get keyset handle");
    let ks = insecure::keyset_material(&h);
    assert_eq!(
        1,
        ks.key.len(),
        "expect the number of keys in the keyset is 1"
    );
    assert_eq!(ks.key[0].key_id, ks.primary_key_id);
    assert_eq!(
        ks.key[0].key_data.as_ref().unwrap().type_url,
        tink_testutil::HMAC_TYPE_URL
    );
    assert_eq!(ks.key[0].status, tink_proto::KeyStatusType::Enabled as i32);
    assert_eq!(
        ks.key[0].output_prefix_type,
        tink_proto::OutputPrefixType::Tink as i32
    );
}

#[test]
fn test_keyset_manager_operations() {
    tink_aead::init();
    let mut key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key.
    let mut keyset_manager = tink::keyset::Manager::new();
    keyset_manager
        .add(&key_template, /* as_primary= */ true)
        .unwrap();
    assert_eq!(1, keyset_manager.key_count());

    // Verify the keyset.
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    let key_id_0 = keyset.key[0].key_id;
    assert_eq!(key_id_0, keyset.primary_key_id);
    assert_eq!(
        keyset.key[0].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[0].output_prefix_type,
        tink_proto::OutputPrefixType::Tink as i32
    );
    assert_eq!(
        keyset.key[0].key_data.as_ref().unwrap().type_url,
        tink_testutil::AES_GCM_TYPE_URL
    );
    assert_eq!(
        tink_proto::key_data::KeyMaterialType::Symmetric as i32,
        keyset.key[0].key_data.as_ref().unwrap().key_material_type
    );

    // Add another key.
    key_template.output_prefix_type = tink_proto::OutputPrefixType::Raw as i32;
    let key_id_1 = keyset_manager
        .add(&key_template, /* as_primary= */ false)
        .unwrap();
    assert_eq!(2, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(2, keyset.key.len());
    assert_eq!(key_id_0, keyset.primary_key_id);
    assert_ne!(keyset.key[0].key_data, keyset.key[1].key_data);
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[1].output_prefix_type,
        tink_proto::OutputPrefixType::Raw as i32
    );
    assert_eq!(
        keyset.key[1].key_data.as_ref().unwrap().type_url,
        tink_testutil::AES_GCM_TYPE_URL
    );
    assert_eq!(
        tink_proto::key_data::KeyMaterialType::Symmetric as i32,
        keyset.key[1].key_data.as_ref().unwrap().key_material_type
    );

    // And another one, via rotation.
    key_template.output_prefix_type = tink_proto::OutputPrefixType::Legacy as i32;
    let key_id_2 = keyset_manager.rotate(&key_template).unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(3, keyset.key.len());
    assert_eq!(key_id_2, keyset.primary_key_id);
    assert_ne!(keyset.key[0].key_data, keyset.key[2].key_data);
    assert_ne!(keyset.key[1].key_data, keyset.key[2].key_data);
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert_eq!(
        keyset.key[2].output_prefix_type,
        tink_proto::OutputPrefixType::Legacy as i32
    );
    assert_eq!(
        keyset.key[2].key_data.as_ref().unwrap().type_url,
        tink_testutil::AES_GCM_TYPE_URL
    );
    assert_eq!(
        tink_proto::key_data::KeyMaterialType::Symmetric as i32,
        keyset.key[2].key_data.as_ref().unwrap().key_material_type
    );

    // Change the primary.
    keyset_manager.set_primary(key_id_1).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(3, keyset_manager.key_count());
    assert_eq!(3, keyset.key.len());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Clone a keyset via the manager, and check equality.
    let keyset_manager_2 = tink::keyset::Manager::new_from_handle(keyset_manager.handle().unwrap());
    let keyset_2 = insecure::keyset_material(&keyset_manager_2.handle().unwrap());
    assert_eq!(keyset, keyset_2);

    // Disable a key, and try to set it as primary.
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    keyset_manager.disable(key_id_2).unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );

    let result = keyset_manager.set_primary(key_id_2);
    tink_testutil::expect_err(result, "must be Enabled");
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Enable ENABLED key, disable a DISABLED one.
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    keyset_manager.enable(key_id_1).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[1].status,
        tink_proto::KeyStatusType::Enabled as i32
    );

    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );
    keyset_manager.disable(key_id_2).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Disabled as i32
    );

    // Enable the disabled key, then destroy it, and try to re-enable.
    keyset_manager.enable(key_id_2).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Enabled as i32
    );
    assert!(!keyset.key[2].key_data.is_none());

    keyset_manager.destroy(key_id_2).unwrap();
    assert_eq!(3, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Destroyed as i32
    );
    assert!(keyset.key[2].key_data.is_none());

    let result = keyset_manager.enable(key_id_2);
    tink_testutil::expect_err(result, "Cannot enable key");
    let result = keyset_manager.disable(key_id_2);
    tink_testutil::expect_err(result, "Cannot disable key");
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(
        keyset.key[2].status,
        tink_proto::KeyStatusType::Destroyed as i32
    );
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Delete the destroyed key, then try to destroy and delete it again.
    keyset_manager.delete(key_id_2).unwrap();
    assert_eq!(2, keyset_manager.key_count());
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(2, keyset.key.len());

    let result = keyset_manager.destroy(key_id_2);
    tink_testutil::expect_err(result, "not found");

    let result = keyset_manager.delete(key_id_2);
    tink_testutil::expect_err(result, "not found");

    // Try disabling/destroying/deleting the primary key.
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    let result = keyset_manager.disable(key_id_1);
    tink_testutil::expect_err(result, "Cannot disable primary");

    let result = keyset_manager.destroy(key_id_1);
    tink_testutil::expect_err(result, "Cannot destroy primary");

    let result = keyset_manager.delete(key_id_1);
    tink_testutil::expect_err(result, "Cannot delete primary");

    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(key_id_1, keyset.primary_key_id);

    // Delete the first key, then try to set it as primary.
    keyset_manager.delete(key_id_0).unwrap();
    let keyset = insecure::keyset_material(&keyset_manager.handle().unwrap());
    assert_eq!(1, keyset.key.len());
    assert_eq!(key_id_1, keyset.key[0].key_id);

    let result = keyset_manager.set_primary(key_id_0);
    tink_testutil::expect_err(result, "not found");
    assert_eq!(1, keyset_manager.key_count());

    // Operations with invalid key ID fail
    let invalid_key_id = 99999; // assume this doesn't accidentally clash
    assert!(keyset_manager.set_primary(invalid_key_id).is_err());
    assert!(keyset_manager.enable(invalid_key_id).is_err());
    assert!(keyset_manager.disable(invalid_key_id).is_err());
    assert!(keyset_manager.destroy(invalid_key_id).is_err());
    assert!(keyset_manager.delete(invalid_key_id).is_err());
}

#[test]
fn test_keyset_manager_corrupt_primary_key() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key which has an invalid status value.
    let mut km = tink::keyset::Manager::new();
    km.rotate(&key_template).unwrap();
    let mut keyset = insecure::keyset_material(&km.handle().unwrap());
    keyset.key[0].status = 999;
    let key_id = keyset.key[0].key_id;

    let kh = insecure::new_handle(keyset).unwrap();
    let mut km = tink::keyset::Manager::new_from_handle(kh);

    // All operations shoud fail.
    let result = km.enable(key_id);
    tink_testutil::expect_err(result, "Cannot enable");
    let result = km.disable(key_id);
    tink_testutil::expect_err(result, "Cannot disable");
    let result = km.destroy(key_id);
    tink_testutil::expect_err(result, "Cannot destroy");
    let result = km.set_primary(key_id);
    tink_testutil::expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_corrupt_secondary_key() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a valid primary key and a second key with an invalid status
    // value.
    let mut km = tink::keyset::Manager::new();
    let _primary_key_id = km.rotate(&key_template).unwrap();
    let secondary_key_id = km.add(&key_template, false).unwrap();
    let mut keyset = insecure::keyset_material(&km.handle().unwrap());
    keyset.key[1].status = 999;

    let kh = insecure::new_handle(keyset).unwrap();
    let mut km = tink::keyset::Manager::new_from_handle(kh);

    // All operations shoud fail.
    let result = km.enable(secondary_key_id);
    tink_testutil::expect_err(result, "Cannot enable");
    let result = km.disable(secondary_key_id);
    tink_testutil::expect_err(result, "Cannot disable");
    let result = km.destroy(secondary_key_id);
    tink_testutil::expect_err(result, "Cannot destroy");
    let result = km.set_primary(secondary_key_id);
    tink_testutil::expect_err(result, "must be Enabled");
}

#[test]
fn test_keyset_manager_invalid_key_id() {
    tink_aead::init();
    let key_template = tink_aead::aes128_gcm_key_template();

    // Create a keyset that contains a single key.
    let mut km = tink::keyset::Manager::new();
    km.rotate(&key_template).unwrap();

    // All operations shoud fail with an invalid key_id.
    let key_id = 9999;
    let result = km.enable(key_id);
    tink_testutil::expect_err(result, "not found");
    let result = km.disable(key_id);
    tink_testutil::expect_err(result, "not found");
    let result = km.destroy(key_id);
    tink_testutil::expect_err(result, "not found");
    let result = km.set_primary(key_id);
    tink_testutil::expect_err(result, "not found");
}

#[test]
fn test_keyset_manager_unknown_prefix_type() {
    tink_aead::init();
    let mut key_template = tink_aead::aes128_gcm_key_template();
    for prefix_type in &[9999, tink_proto::OutputPrefixType::UnknownPrefix as i32] {
        key_template.output_prefix_type = *prefix_type;

        let mut km = tink::keyset::Manager::new();
        km.rotate(&key_template).unwrap();
        let kh = km.handle().unwrap();
        let ks = insecure::keyset_material(&kh);
        assert_eq!(
            ks.key[0].output_prefix_type,
            tink_proto::OutputPrefixType::Tink as i32
        );
    }
}

#[test]
fn test_existing_keyset() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm1 = tink::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm1.rotate(&kt)
        .expect("cannot rotate when key template is available");

    let h1 = ksm1.handle().expect("cannot get keyset handle");
    let ks1 = insecure::keyset_material(&h1);

    let mut ksm2 = tink::keyset::Manager::new_from_handle(h1);
    ksm2.rotate(&kt).expect("failed to rotate");
    let h2 = ksm2.handle().expect("cannot get keyset handle");
    let ks2 = insecure::keyset_material(&h2);

    assert_eq!(ks2.key.len(), 2, "expect the number of keys to be 2");
    assert_eq!(
        format!("{:?}", ks1.key[0]),
        format!("{:?}", ks2.key[0]),
        "expect the first key in two keysets to be the same"
    );
    assert_eq!(
        ks2.key[1].key_id, ks2.primary_key_id,
        "expect the second key to be primary"
    );
}

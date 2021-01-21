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

use tink_core::{primitiveset::Entry, Primitive};
use tink_proto::{keyset::Key, KeyStatusType, OutputPrefixType};
use tink_tests::{new_dummy_key, DummyMac};

fn create_keyset() -> Vec<Key> {
    let key_id0 = 1234543;
    let key_id1 = 7213743;
    let key_id2 = key_id1;
    let key_id3 = 947327;
    let key_id4 = 529472;
    let key_id5 = key_id0;
    vec![
        new_dummy_key(key_id0, KeyStatusType::Enabled, OutputPrefixType::Tink),
        new_dummy_key(key_id1, KeyStatusType::Enabled, OutputPrefixType::Legacy),
        new_dummy_key(key_id2, KeyStatusType::Enabled, OutputPrefixType::Tink),
        new_dummy_key(key_id3, KeyStatusType::Enabled, OutputPrefixType::Raw),
        new_dummy_key(key_id4, KeyStatusType::Enabled, OutputPrefixType::Raw),
        new_dummy_key(key_id5, KeyStatusType::Enabled, OutputPrefixType::Tink),
    ]
}

#[test]
fn test_primitive_set_basic() {
    let mut ps = tink_core::primitiveset::PrimitiveSet::new();
    assert!(ps.primary.is_none());
    assert!(ps.entries.is_empty());
    // generate test keys
    let keys = create_keyset();
    // add all test primitives
    let mut macs = Vec::with_capacity(keys.len());
    let mut entries = Vec::with_capacity(keys.len());
    for i in 0..keys.len() {
        let mac = Box::new(DummyMac {
            name: format!("Mac#{}", i),
        });
        macs.push(mac);
        entries.push(ps.add(Primitive::Mac(macs[i].clone()), &keys[i]).unwrap());
    }

    // set primary entry
    let primary_id = 2;
    ps.primary = Some(entries[primary_id].clone());

    // check raw primitives
    let raw_ids = vec![keys[3].key_id, keys[4].key_id];
    let raw_macs = vec![macs[3].clone(), macs[4].clone()];
    let raw_statuses = vec![
        KeyStatusType::from_i32(keys[3].status).unwrap(),
        KeyStatusType::from_i32(keys[4].status).unwrap(),
    ];
    let raw_prefix_types = vec![
        OutputPrefixType::from_i32(keys[3].output_prefix_type).unwrap(),
        OutputPrefixType::from_i32(keys[4].output_prefix_type).unwrap(),
    ];
    let raw_entries = ps.raw_entries();
    assert!(
        validate_entry_list(
            &raw_entries,
            &raw_ids,
            &raw_macs,
            &raw_statuses,
            &raw_prefix_types
        ),
        "raw primitives do not match input"
    );

    // check tink primitives, same id
    let tink_ids = vec![keys[0].key_id, keys[5].key_id];
    let tink_macs = vec![macs[0].clone(), macs[5].clone()];
    let tink_statuses = vec![
        KeyStatusType::from_i32(keys[0].status).unwrap(),
        KeyStatusType::from_i32(keys[5].status).unwrap(),
    ];
    let tink_prefix_types = vec![
        OutputPrefixType::from_i32(keys[0].output_prefix_type).unwrap(),
        OutputPrefixType::from_i32(keys[5].output_prefix_type).unwrap(),
    ];
    let prefix = tink_core::cryptofmt::output_prefix(&keys[0]).unwrap();
    let tink_entries = ps.entries_for_prefix(&prefix);
    assert!(
        validate_entry_list(
            &tink_entries,
            &tink_ids,
            &tink_macs,
            &tink_statuses,
            &tink_prefix_types
        ),
        "tink primitives do not match the input key"
    );

    // check another tink primitive
    let tink_ids = vec![keys[2].key_id];
    let tink_macs = vec![macs[2].clone()];
    let tink_statuses = vec![KeyStatusType::from_i32(keys[2].status).unwrap()];
    let tink_prefix_types = vec![OutputPrefixType::from_i32(keys[2].output_prefix_type).unwrap()];
    let prefix = tink_core::cryptofmt::output_prefix(&keys[2]).unwrap();
    let tink_entries = ps.entries_for_prefix(&prefix);
    assert!(
        validate_entry_list(
            &tink_entries,
            &tink_ids,
            &tink_macs,
            &tink_statuses,
            &tink_prefix_types
        ),
        "tink primitives do not match the input key"
    );

    // check legacy primitives
    let legacy_ids = vec![keys[1].key_id];
    let legacy_macs = vec![macs[1].clone()];
    let legacy_statuses = vec![KeyStatusType::from_i32(keys[1].status).unwrap()];
    let legacy_prefix_types = vec![OutputPrefixType::from_i32(keys[1].output_prefix_type).unwrap()];
    let legacy_prefix = tink_core::cryptofmt::output_prefix(&keys[1]).unwrap();
    let legacy_entries = ps.entries_for_prefix(&legacy_prefix);
    assert!(
        validate_entry_list(
            &legacy_entries,
            &legacy_ids,
            &legacy_macs,
            &legacy_statuses,
            &legacy_prefix_types
        ),
        "legacy primitives do not match the input key"
    );
}

#[test]
fn test_add_with_invalid_input() {
    let mut ps = tink_core::primitiveset::PrimitiveSet::new();
    let dummy_mac = Box::new(DummyMac {
        name: "".to_string(),
    });
    // unknown prefix type
    let invalid_key = new_dummy_key(0, KeyStatusType::Enabled, OutputPrefixType::UnknownPrefix);
    assert!(
        ps.add(Primitive::Mac(dummy_mac.clone()), &invalid_key)
            .is_err(),
        "expect an error when key is invalid"
    );

    // disabled key
    let disabled_key = new_dummy_key(0, KeyStatusType::Disabled, OutputPrefixType::UnknownPrefix);
    assert!(
        ps.add(Primitive::Mac(dummy_mac), &disabled_key).is_err(),
        "expect an error when key is disabled"
    );
}

fn validate_entry_list(
    entries: &[Entry],
    key_ids: &[tink_core::KeyId],
    macs: &[Box<DummyMac>],
    statuses: &[KeyStatusType],
    prefix_types: &[OutputPrefixType],
) -> bool {
    if entries.len() != macs.len() {
        return false;
    }
    for (i, entry) in entries.iter().enumerate() {
        if !validate_entry(entry, key_ids[i], &macs[i], &statuses[i], &prefix_types[i]) {
            return false;
        }
    }
    true
}

// Compare an entry with the [`DummyMAC`] that was used to create the entry.
fn validate_entry(
    entry: &Entry,
    key_id: tink_core::KeyId,
    test_mac: &DummyMac,
    status: &KeyStatusType,
    output_prefix_type: &OutputPrefixType,
) -> bool {
    if entry.key_id != key_id || entry.status != *status || entry.prefix_type != *output_prefix_type
    {
        return false;
    }
    if let Primitive::Mac(dummy_mac) = &entry.primitive {
        let mut data = vec![1, 2, 3, 4, 5];
        let digest = dummy_mac.compute_mac(&data).unwrap();
        data.extend_from_slice(test_mac.name.as_bytes());
        if digest != data {
            return false;
        }
    } else {
        panic!("failed to retrieve MAC primitive");
    }
    true
}

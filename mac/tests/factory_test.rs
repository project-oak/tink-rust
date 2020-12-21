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

use tink::{utils::wrap_err, TinkError};

#[test]
fn test_factory_multiple_keys() {
    tink_mac::init();
    let tag_size = 16;
    let keyset = tink_testutil::new_test_hmac_keyset(tag_size, tink_proto::OutputPrefixType::Tink);
    let primary_key = keyset.key[0].clone();
    assert_eq!(
        primary_key.output_prefix_type,
        tink_proto::OutputPrefixType::Tink as i32
    );
    let raw_key = keyset.key[1].clone();
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();

    let p = tink_mac::new(&keyset_handle).unwrap();
    let expected_prefix = tink::cryptofmt::output_prefix(&primary_key).unwrap();

    verify_mac_primitive(&p, &p, &expected_prefix, tag_size as usize).expect("invalid primitive");

    // mac with a primary RAW key, verify with the keyset
    assert_eq!(
        raw_key.output_prefix_type,
        tink_proto::OutputPrefixType::Raw as i32
    );
    let keyset2 = tink_testutil::new_keyset(raw_key.key_id, vec![raw_key]);
    let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();

    let p2 = tink_mac::new(&keyset_handle2).unwrap();
    verify_mac_primitive(&p2, &p, &tink::cryptofmt::RAW_PREFIX, tag_size as usize)
        .expect("invalid primitive");

    // mac with a random key not in the keyset, verify with the keyset should fail
    let keyset2 = tink_testutil::new_test_hmac_keyset(tag_size, tink_proto::OutputPrefixType::Tink);
    let primary_key = keyset2.key[0].clone();
    let expected_prefix = tink::cryptofmt::output_prefix(&primary_key).unwrap();
    let keyset_handle2 = tink::keyset::insecure::new_handle(keyset2).unwrap();

    let p2 = tink_mac::new(&keyset_handle2).unwrap();
    let result = verify_mac_primitive(&p2, &p.box_clone(), &expected_prefix, tag_size as usize);
    assert!(result.is_err(), "Invalid MAC, shouldn't return valid");
    let detail = format!("{:?}", result.unwrap_err());
    assert!(
        detail.contains("mac verification failed"),
        "Invalid MAC, shouldn't return valid"
    );
}

#[test]
fn test_factory_raw_key() {
    tink_mac::init();
    let tag_size = 16;
    let keyset = tink_testutil::new_test_hmac_keyset(tag_size, tink_proto::OutputPrefixType::Raw);
    let primary_key = keyset.key[0].clone();
    assert_eq!(
        primary_key.output_prefix_type,
        tink_proto::OutputPrefixType::Raw as i32
    );
    let keyset_handle = tink::keyset::insecure::new_handle(keyset).unwrap();
    let p = tink_mac::new(&keyset_handle).unwrap();
    verify_mac_primitive(&p, &p, &tink::cryptofmt::RAW_PREFIX, tag_size as usize)
        .expect("invalid primitive");
}

#[allow(clippy::borrowed_box)]
fn verify_mac_primitive(
    compute_primitive: &Box<dyn tink::Mac>,
    verify_primitive: &Box<dyn tink::Mac>,
    expected_prefix: &[u8],
    tag_size: usize,
) -> Result<(), TinkError> {
    let data = b"hello";
    let tag = compute_primitive.compute_mac(data)?;
    let prefix_size = expected_prefix.len();
    if &tag[..prefix_size] != expected_prefix {
        return Err("incorrect prefix".into());
    }
    if prefix_size + tag_size != tag.len() {
        return Err("incorrect tag length".into());
    }
    verify_primitive
        .verify_mac(&tag, &data[..])
        .map_err(|e| wrap_err("mac verification failed", e))?;

    // Modify plaintext or tag and make sure verify_mac failed.
    let mut data_and_tag = Vec::new();
    data_and_tag.extend_from_slice(&data[..]);
    data_and_tag.extend_from_slice(&tag);
    if verify_primitive
        .verify_mac(&data_and_tag[data.len()..], &data_and_tag[..data.len()])
        .is_err()
    {
        return Err("mac verification failed".into());
    }
    for i in 0..data_and_tag.len() {
        let tmp = data_and_tag[i];
        for j in 0..8u8 {
            data_and_tag[i] ^= 1 << j;
            if verify_primitive
                .verify_mac(&data_and_tag[data.len()..], &data_and_tag[..data.len()])
                .is_ok()
            {
                return Err("invalid tag or plaintext, mac should be invalid".into());
            }
            data_and_tag[i] = tmp;
        }
    }
    Ok(())
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_mac::init();
    tink_prf::init();
    let wrong_kh = tink::keyset::Handle::new(&tink_prf::hkdf_sha256_prf_key_template()).unwrap();

    assert!(
        tink_mac::new(&wrong_kh).is_err(),
        "calling new() with wrong keyset::Handle should fail"
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_mac::init();
    let good_kh = tink::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template()).unwrap();

    tink_mac::new(&good_kh).expect("calling new() with good keyset::Handle failed");
}

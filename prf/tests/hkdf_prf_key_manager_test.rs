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
use std::collections::HashSet;
use tink::{proto::HashType, utils::wrap_err, Prf, TinkError};
use tink_testutil::proto_encode;

#[test]
fn test_get_primitive_hkdf_basic() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");
    let test_keys = gen_valid_hkdf_keys();
    for test_key in test_keys {
        let serialized_key = proto_encode(&test_key);
        let p = km.primitive(&serialized_key).unwrap();
        assert!(validate_hkdf_primitive(p, &test_key).is_ok());
    }
}

#[test]
fn test_get_primitive_hkdf_with_invalid_input() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");
    // invalid key
    let test_keys = gen_invalid_hkdf_keys();
    for (i, serialized_key) in test_keys.iter().enumerate() {
        assert!(
            km.primitive(&serialized_key).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty input
    assert!(
        km.primitive(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_new_key_hkdf_multiple_times() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    let serialized_format = proto_encode(&tink_testutil::new_hkdf_prf_key_format(
        tink::proto::HashType::Sha256,
        &[],
    ));
    let mut keys = HashSet::new();
    let n_test = 26;
    for _i in 0..n_test {
        let serialized_key = km.new_key(&serialized_format).unwrap();
        keys.insert(hex::encode(serialized_key));

        let key_data = km.new_key_data(&serialized_format).unwrap();
        keys.insert(hex::encode(key_data.value));
    }
    assert_eq!(keys.len(), 2 * n_test, "key is repeated");
}

#[test]
fn test_new_key_hkdf_basic() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");
    let test_formats = gen_valid_hkdf_key_formats();
    for (i, test_format) in test_formats.iter().enumerate() {
        let serialized_format = proto_encode(test_format);
        let serialized_key = km
            .new_key(&serialized_format)
            .unwrap_or_else(|e| panic!("unexpected error in test case {}: {:?}", i, e));
        let key = tink::proto::HkdfPrfKey::decode(serialized_key.as_ref()).unwrap();
        assert!(validate_hkdf_key(test_format, &key).is_ok());
    }
}

#[test]
fn test_new_key_hkdf_with_invalid_input() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    // invalid key formats
    let test_formats = gen_invalid_hkdf_key_formats();
    for (i, serialized_format) in test_formats.iter().enumerate() {
        assert!(
            km.new_key(serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty input
    assert!(
        km.new_key(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_new_key_data_hkdf_basic() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    let test_formats = gen_valid_hkdf_key_formats();
    for (i, test_format) in test_formats.iter().enumerate() {
        let serialized_format = proto_encode(test_format);
        let key_data = km
            .new_key_data(&serialized_format)
            .unwrap_or_else(|e| panic!("unexpected error in test case {}: {:?}", i, e));
        assert_eq!(
            key_data.type_url,
            tink_testutil::HKDF_PRF_TYPE_URL,
            "incorrect type url in test case {}",
            i
        );
        assert_eq!(
            key_data.key_material_type,
            tink::proto::key_data::KeyMaterialType::Symmetric as i32,
            "incorrect key material type in test case {}",
            i
        );
        let key =
            tink::proto::HkdfPrfKey::decode(key_data.value.as_ref()).expect("invalid key value");
        validate_hkdf_key(test_format, &key).expect("invalid key");
    }
}

#[test]
fn test_new_key_data_hkdf_with_invalid_input() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    // invalid key formats
    let test_formats = gen_invalid_hkdf_key_formats();
    for (i, serialized_format) in test_formats.iter().enumerate() {
        assert!(
            km.new_key_data(serialized_format).is_err(),
            "expect an error in test case {}",
            i
        );
    }
    // empty input
    assert!(
        km.new_key_data(&[]).is_err(),
        "expect an error when input is empty"
    );
}

#[test]
fn test_hkdf_does_support() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    assert!(
        km.does_support(tink_testutil::HKDF_PRF_TYPE_URL),
        "HkdfPrfKeyManager must support {}",
        tink_testutil::HKDF_PRF_TYPE_URL
    );
    assert!(
        !km.does_support("some bad type"),
        "HkdfPrfKeyManager must support only {}",
        tink_testutil::HKDF_PRF_TYPE_URL
    );
}

#[test]
fn test_hkdf_type_url() {
    tink_prf::init();
    let km = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .expect("HKDF PRF key manager not found");

    assert_eq!(
        km.type_url(),
        tink_testutil::HKDF_PRF_TYPE_URL,
        "incorrect key_type()"
    );
}

fn gen_invalid_hkdf_keys() -> Vec<Vec<u8>> {
    let mut bad_version_key = tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha256, &[]);
    bad_version_key.version += 1;
    let mut short_key = tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha256, &[]);
    short_key.key_value = vec![1, 1];
    let sha1_key = tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha1, &[]);
    let unknown_hash_key = tink_testutil::new_hkdf_prf_key(tink::proto::HashType::UnknownHash, &[]);
    let non_key = tink_testutil::new_hkdf_prf_params(tink::proto::HashType::Sha256, &[]);

    vec![
        proto_encode(&non_key),
        proto_encode(&bad_version_key),
        proto_encode(&short_key),
        proto_encode(&sha1_key),
        proto_encode(&unknown_hash_key),
    ]
}

fn gen_invalid_hkdf_key_formats() -> Vec<Vec<u8>> {
    let mut short_key_format =
        tink_testutil::new_hkdf_prf_key_format(tink::proto::HashType::Sha256, &[]);
    short_key_format.key_size = 1;

    vec![
        // not a `HkdfPrfKeyFormat`
        proto_encode(&tink_testutil::new_hmac_params(
            tink::proto::HashType::Sha256,
            32,
        )),
        // key too short
        proto_encode(&short_key_format),
        // SHA-1
        proto_encode(&tink_testutil::new_hkdf_prf_key_format(
            tink::proto::HashType::Sha1,
            &[],
        )),
        // unknown hash type
        proto_encode(&tink_testutil::new_hkdf_prf_key_format(
            tink::proto::HashType::UnknownHash,
            &[],
        )),
    ]
}

fn gen_valid_hkdf_key_formats() -> Vec<tink::proto::HkdfPrfKeyFormat> {
    vec![
        tink_testutil::new_hkdf_prf_key_format(tink::proto::HashType::Sha256, &[]),
        tink_testutil::new_hkdf_prf_key_format(tink::proto::HashType::Sha512, &[]),
        tink_testutil::new_hkdf_prf_key_format(tink::proto::HashType::Sha256, &[0x01, 0x03, 0x42]),
        tink_testutil::new_hkdf_prf_key_format(tink::proto::HashType::Sha512, &[0x01, 0x03, 0x42]),
    ]
}

fn gen_valid_hkdf_keys() -> Vec<tink::proto::HkdfPrfKey> {
    vec![
        tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha256, &[]),
        tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha512, &[]),
        tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha256, &[0x01, 0x03, 0x42]),
        tink_testutil::new_hkdf_prf_key(tink::proto::HashType::Sha512, &[0x01, 0x03, 0x42]),
    ]
}

// Checks whether the given HKDFPRFKey matches the given key HKDFPRFKeyFormat
fn validate_hkdf_key(
    format: &tink::proto::HkdfPrfKeyFormat,
    key: &tink::proto::HkdfPrfKey,
) -> Result<(), TinkError> {
    if format.key_size as usize != key.key_value.len()
        || key.params.as_ref().unwrap().hash != format.params.as_ref().unwrap().hash
    {
        return Err("key format and generated key do not match".into());
    }
    let p = tink_prf::subtle::HkdfPrf::new(
        HashType::from_i32(key.params.as_ref().unwrap().hash).unwrap(),
        &key.key_value,
        &key.params.as_ref().unwrap().salt,
    )
    .map_err(|e| wrap_err("cannot create primitive from key", e))?;
    validate_hkdf_primitive(tink::Primitive::Prf(Box::new(p)), key)
}

/// Check whether the given primitive matches the given [`HkdfPrfKey`](tink::proto::HkdfPrfKey).
fn validate_hkdf_primitive(
    p: tink::Primitive,
    key: &tink::proto::HkdfPrfKey,
) -> Result<(), TinkError> {
    let hkdf_primitive = match p {
        tink::Primitive::Prf(prf) => prf,
        _ => return Err("not a Prf primitive".into()),
    };
    let hash = HashType::from_i32(key.params.as_ref().unwrap().hash).unwrap();
    let prf_primitive =
        tink_prf::subtle::HkdfPrf::new(hash, &key.key_value, &key.params.as_ref().unwrap().salt)
            .map_err(|e| {
                wrap_err(
                    &format!(
                        "Could not create HKDF PRF with key material {}",
                        hex::encode(&key.key_value)
                    ),
                    e,
                )
            })?;
    let data = tink::subtle::random::get_random_bytes(20);
    let res = hkdf_primitive
        .compute_prf(&data, 16)
        .map_err(|e| wrap_err("prf computation failed", e))?;
    if res.len() != 16 {
        return Err("prf computation did not produce 16 byte output".into());
    }
    let res2 = prf_primitive
        .compute_prf(&data, 16)
        .map_err(|e| wrap_err("prf computation failed", e))?;
    if res2.len() != 16 {
        return Err("prf computation did not produce 16 byte output".into());
    }
    assert_eq!(
        hex::encode(res),
        hex::encode(res2),
        "prf computation did not produce the same output for the same key and input"
    );
    Ok(())
}

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

use tink_core::{subtle::random::get_random_bytes, Mac};
use tink_proto::HashType;

struct TestCase {
    hash_alg: HashType,
    tag_size: usize,
    key: &'static [u8],
    data: &'static [u8],
    expected_mac: &'static str,
}

const KEY: &[u8] = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
const DATA: &[u8] = b"Hello";

const HMAC_TESTS : &[TestCase] = &[
    TestCase {
        hash_alg:     HashType::Sha256,
        tag_size:     32,
        data:         DATA,
        key:          KEY,
        expected_mac: "e0ff02553d9a619661026c7aa1ddf59b7b44eac06a9908ff9e19961d481935d4",
    },
    TestCase {
        hash_alg:     HashType::Sha512,
        tag_size:     64,
        data:         DATA,
        key:          KEY,
        expected_mac: "481e10d823ba64c15b94537a3de3f253c16642451ac45124dd4dde120bf1e5c15e55487d55ba72b43039f235226e7954cd5854b30abc4b5b53171a4177047c9b",
    },
    // empty data
    TestCase {
        hash_alg:     HashType::Sha256,
        tag_size:     32,
        data:         &[],
        key:          KEY,
        expected_mac: "07eff8b326b7798c9ccfcbdbe579489ac785a7995a04618b1a2813c26744777d",
    },
];

#[test]
fn test_hmac_basic() {
    tink_mac::init();
    for (i, test) in HMAC_TESTS.iter().enumerate() {
        let cipher = tink_mac::subtle::Hmac::new(test.hash_alg, test.key, test.tag_size)
            .expect("cannot create new mac");
        let mac = cipher
            .compute_mac(test.data)
            .expect("mac computation failed");
        assert_eq!(
            hex::encode(&mac),
            test.expected_mac[..(test.tag_size * 2)],
            "incorrect mac in test case {i}",
        );
        cipher
            .verify_mac(&mac, test.data)
            .unwrap_or_else(|_| panic!("mac verification failed in test case {}", i,));
    }
}

#[test]
fn test_new_hmac_with_invalid_input() {
    tink_mac::init();
    // invalid hash algorithm
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::UnknownHash, &get_random_bytes(16), 32),
        "invalid hash algorithm",
    );

    // key too short
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::Sha256, &get_random_bytes(1), 32),
        "key too short",
    );
    // tag too short
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::Sha256, &get_random_bytes(16), 9),
        "tag size too small",
    );
    // tag too big
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::Sha1, &get_random_bytes(16), 21),
        "tag size too big",
    );
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::Sha256, &get_random_bytes(16), 33),
        "tag size too big",
    );
    tink_tests::expect_err(
        tink_mac::subtle::Hmac::new(HashType::Sha512, &get_random_bytes(16), 65),
        "tag size too big",
    );
}

#[test]
fn test_hmac_compute_verify_with_empty_input() {
    let cipher = tink_mac::subtle::Hmac::new(HashType::Sha256, &get_random_bytes(16), 32).unwrap();
    let tag = cipher.compute_mac(&[]).unwrap();
    assert!(cipher.verify_mac(&tag, &[]).is_ok());
}

#[test]
fn test_verify_mac_with_invalid_input() {
    let cipher = tink_mac::subtle::Hmac::new(HashType::Sha256, &get_random_bytes(16), 32).unwrap();
    assert!(
        cipher.verify_mac(&[], &[0x01]).is_err(),
        "expect an error when mac is nil"
    );
    assert!(
        cipher.verify_mac(&[0x01], &[]).is_err(),
        "expect an error when data is nil"
    );
    assert!(cipher.verify_mac(&[], &[]).is_err());
}

#[test]
fn test_hmac_modification() {
    tink_mac::init();
    for test in HMAC_TESTS {
        let cipher = tink_mac::subtle::Hmac::new(test.hash_alg, test.key, test.tag_size)
            .expect("cannot create new mac");
        let mut mac = cipher
            .compute_mac(test.data)
            .expect("mac computation failed");

        for i in 0..mac.len() {
            let tmp = mac[i];
            for j in 0..8u8 {
                mac[i] ^= 1 << j;
                assert!(
                    cipher.verify_mac(&mac, test.data).is_err(),
                    "test case {}: modified MAC should be invalid",
                    i
                );
                mac[i] = tmp;
            }
        }
    }
}

#[test]
fn test_hmac_truncation() {
    tink_mac::init();
    for test in HMAC_TESTS {
        let cipher = tink_mac::subtle::Hmac::new(test.hash_alg, test.key, test.tag_size)
            .expect("cannot create new mac");
        let mac = cipher
            .compute_mac(test.data)
            .expect("mac computation failed");

        for i in 1..mac.len() {
            assert!(
                cipher.verify_mac(&mac[..i], test.data).is_err(),
                "test case {}: truncated MAC should be invalid",
                i
            );
        }
    }
}

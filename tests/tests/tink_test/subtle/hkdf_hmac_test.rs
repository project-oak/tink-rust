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

use tink::subtle::{compute_hkdf, random::get_random_bytes};
use tink_proto::HashType;

// Tests sourced from
// java/src/test/java/com/google/crypto/tink/subtle/HkdfTest.java

#[test]
fn test_hkdf_basic() {
    struct Case {
        hash_alg: HashType,
        key: &'static str,
        salt: &'static str,
        info: &'static str,
        tag_size: usize,
        expected_kdf: &'static str,
    };
    let hkdf_tests = vec![
        Case {
            hash_alg:     HashType::Sha256,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            tag_size:     42,
            expected_kdf: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        Case {
            hash_alg: HashType::Sha256,
            key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            tag_size: 82,
            expected_kdf: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Case {
            hash_alg: HashType::Sha256,
            key:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:    "",
            info:    "",
            tag_size: 42,
            expected_kdf: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
        Case {
            hash_alg:     HashType::Sha1,
            key:         "0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            tag_size:     42,
            expected_kdf: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
        },
        Case {
            hash_alg: HashType::Sha1,
            key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            tag_size: 82,
            expected_kdf: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
        },
        Case {
            hash_alg: HashType::Sha1,
            key:     "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:    "",
            info:    "",
            tag_size: 42,
            expected_kdf: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        },
        Case {
            hash_alg: HashType::Sha1,
            key:     "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            salt:    "",
            info:    "",
            tag_size: 42,
            expected_kdf: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        },
        // Extra tests for Rust port:
        Case {
            hash_alg:     HashType::Sha384,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            tag_size:     42,
            expected_kdf: "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5",
        },
        Case {
            hash_alg:     HashType::Sha512,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            tag_size:     42,
            expected_kdf: "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb",
        },
    ];

    for (ti, test) in hkdf_tests.iter().enumerate() {
        let k = hex::decode(test.key).unwrap();
        let s = hex::decode(test.salt).unwrap();
        let i = hex::decode(test.info).unwrap();

        let result = compute_hkdf(test.hash_alg, &k, &s, &i, test.tag_size)
            .map_err(|e| format!("mac computation failed in test case {}: {}", ti, e))
            .unwrap();
        let r = hex::encode(result);

        println!("Test no: {}", ti);
        println!("Length of tag {}", test.tag_size);
        println!("Length of result {}", r.len());
        println!("Length of expected: {}\n\n", test.expected_kdf.len());
        assert_eq!(
            test.expected_kdf, r,
            "incorrect hkdf in test case {}: expect {}, got {}",
            ti, test.expected_kdf, r
        );
    }
}

#[test]
fn test_new_hmac_with_invalid_input() {
    // invalid hash algorithm
    if let Err(e) = compute_hkdf(HashType::UnknownHash, &get_random_bytes(16), &[], &[], 32) {
        assert!(
            format!("{}", e).contains("invalid hash algorithm"),
            "expect error with 'invalid hash algorithm', got '{}'",
            e
        );
    } else {
        panic!("expect an error when hash algorithm is invalid");
    }

    // tag too short
    if let Err(e) = compute_hkdf(HashType::Sha256, &get_random_bytes(16), &[], &[], 9) {
        assert!(
            format!("{}", e).contains("tag size too small"),
            "expect error with 'tag size too small', got '{}'",
            e
        );
    } else {
        panic!("expect an error when hash algorithm is invalid");
    }

    // tag too big
    if let Err(e) = compute_hkdf(HashType::Sha1, &get_random_bytes(16), &[], &[], 5101) {
        assert!(
            format!("{}", e).contains("tag size too big"),
            "expect error with 'tag size too big', got '{}'",
            e
        );
    } else {
        panic!("expect an error when hash algorithm is invalid");
    }
    if let Err(e) = compute_hkdf(HashType::Sha256, &get_random_bytes(16), &[], &[], 8162) {
        assert!(
            format!("{}", e).contains("tag size too big"),
            "expect error with 'tag size too big', got '{}'",
            e
        );
    } else {
        panic!("expect an error when hash algorithm is invalid");
    }
    if let Err(e) = compute_hkdf(HashType::Sha512, &get_random_bytes(16), &[], &[], 16323) {
        assert!(
            format!("{}", e).contains("tag size too big"),
            "expect error with 'tag size too big', got '{}'",
            e
        );
    } else {
        panic!("expect an error when hash algorithm is invalid");
    }
}

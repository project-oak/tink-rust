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

use maplit::hashmap;
use serde::Deserialize;
use tink_core::Prf;
use tink_prf::subtle::{validate_hkdf_prf_params, HkdfPrf};
use tink_proto::HashType;

struct Rfc5869Test {
    hash: HashType,
    key: &'static str,
    salt: &'static str,
    info: &'static str,
    output_length: usize,
    okm: &'static str,
}

#[test]
fn test_vectors_rfc5869() {
    // Test vectors from RFC 5869.
    let testvectors = [
        Rfc5869Test{
            hash:        HashType::Sha256,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            output_length: 42,
            okm:         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        },
        Rfc5869Test{
            hash:        HashType::Sha256,
            key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            output_length: 82,
            okm:         "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Rfc5869Test{
            hash:        HashType::Sha256,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "",
            info:        "",
            output_length: 42,
            okm:         "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
        },
        Rfc5869Test{
            hash:        HashType::Sha1,
            key:         "0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "000102030405060708090a0b0c",
            info:        "f0f1f2f3f4f5f6f7f8f9",
            output_length: 42,
            okm:         "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
        },
        Rfc5869Test{
            hash:        HashType::Sha1,
            key:         "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt:        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info:        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            output_length: 82,
            okm:         "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
        },
        Rfc5869Test{
            hash:        HashType::Sha1,
            key:         "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt:        "",
            info:        "",
            output_length: 42,
            okm:         "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
        },
        Rfc5869Test{
            hash:        HashType::Sha1,
            key:         "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
            salt:        "",
            info:        "",
            output_length: 42,
            okm:         "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
        },
    ];
    for v in testvectors.iter() {
        let key = hex::decode(v.key).expect("Could not decode key");
        let salt = hex::decode(v.salt).expect("Could not decode salt");
        let info = hex::decode(v.info).expect("Could not decode info");
        let p = HkdfPrf::new(v.hash, &key, &salt).expect("Could not create HKDF object");
        let output = p
            .compute_prf(&info, v.output_length)
            .expect("Error computing HKDF");
        assert_eq!(
            hex::encode(output),
            v.okm,
            "Computation and test vector differ."
        );
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct HkdfTestData {
    #[serde(flatten)]
    pub suite: tink_tests::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<HkdfTestGroup>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct HkdfTestGroup {
    #[serde(flatten)]
    pub group: tink_tests::WycheproofGroup,
    #[serde(rename = "keySize")]
    pub key_size: u32,
    pub tests: Vec<HkdfTestCase>,
}

#[derive(Debug, Deserialize)]
struct HkdfTestCase {
    #[serde(flatten)]
    pub case: tink_tests::WycheproofCase,
    #[serde(with = "tink_tests::hex_string")]
    pub ikm: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub salt: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub info: Vec<u8>,
    pub size: usize,
    #[serde(with = "tink_tests::hex_string")]
    pub okm: Vec<u8>,
}

#[test]
fn test_hkdf_prf_wycheproof_cases() {
    for hash in &[HashType::Sha1, HashType::Sha256, HashType::Sha512] {
        let hash_name = format!("{hash:?}");
        let filename = format!("testvectors/hkdf_{}_test.json", hash_name.to_lowercase());
        println!("wycheproof file '{filename}' hash {hash_name}");
        let bytes = tink_tests::wycheproof_data(&filename);
        let data: HkdfTestData = serde_json::from_slice(&bytes).unwrap();

        for g in &data.test_groups {
            println!("   key info: key_size={}", g.key_size);
            for tc in &g.tests {
                println!(
                    "     case {} [{}] {}",
                    tc.case.case_id, tc.case.result, tc.case.comment
                );
                assert_eq!(tc.ikm.len() * 8, g.key_size as usize);
                let hkdf_prf = HkdfPrf::new(*hash, &tc.ikm, &tc.salt);
                let valid = tc.case.result == tink_tests::WycheproofResult::Valid;
                if valid && hkdf_prf.is_err() {
                    panic!(
                        "Could not create HKDF {:?} PRF for test case {} ({})",
                        hash, tc.case.case_id, tc.case.comment
                    );
                }
                if !valid && hkdf_prf.is_err() {
                    continue;
                }
                let res = match hkdf_prf.unwrap().compute_prf(&tc.info, tc.size) {
                    Err(_) => {
                        assert!(
                            !valid,
                            "Could not compute HKDF {:?} PRF for test case {} ({})",
                            hash, tc.case.case_id, tc.case.comment
                        );
                        continue;
                    }
                    Ok(r) => r,
                };
                if valid {
                    assert_eq!(
                        res, tc.okm,
                        "Computed HKDF {:?} PRF and expected for test case {} ({}) do not match",
                        hash, tc.case.case_id, tc.case.comment
                    );
                } else {
                    assert_ne!(
                        res, tc.okm,
                        "Computed HKDF {:?} PRF and invalid expected for test case {} ({}) match",
                        hash, tc.case.case_id, tc.case.comment
                    );
                }
            }
        }
    }
}

#[test]
fn test_hkdf_prf_hash() {
    assert!(
        HkdfPrf::new(
            HashType::Sha256,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[]
        )
        .is_ok(),
        "Expected HkdfPrf::new to work with SHA256"
    );
    assert!(
        HkdfPrf::new(
            HashType::Sha512,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[]
        )
        .is_ok(),
        "Expected HkdfPrf::new to work with SHA512"
    );

    assert!(
        HkdfPrf::new(
            HashType::Sha1,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[]
        )
        .is_ok(),
        "Expected HkdfPrf::new to work with SHA1"
    );
    assert!(
        HkdfPrf::new(
            HashType::UnknownHash,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[]
        )
        .is_err(),
        "Expected HkdfPrf::new to fail with unknown hash"
    );
}

#[test]
fn test_hkdf_prf_salt() {
    assert!(
        HkdfPrf::new(
            HashType::Sha256,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[]
        )
        .is_ok(),
        "Expected HkdfPrf::new to work empty salt"
    );
    assert!(
        HkdfPrf::new(
            HashType::Sha256,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ],
            &[0xaf, 0xfe, 0xc0, 0xff, 0xee]
        )
        .is_ok(),
        "Expected HkdfPrf::new to work with salt"
    );
}

#[test]
fn test_hkdf_prf_output_length() {
    let testdata = hashmap! {
        HashType::Sha1 => 20,
        HashType::Sha256 => 32,
        HashType::Sha512 => 64,
    };
    for (hash, length) in testdata {
        let prf = HkdfPrf::new(
            hash,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10,
            ],
            &[],
        )
        .unwrap_or_else(|_| {
            panic!(
                "Expected HkdfPrf::new to work on 32 byte key with hash {:?}",
                hash
            )
        });
        // If overflow checks are enabled (which they are by default for tests),
        // this loop runs too slow, so only test every 10th length.
        for i in (0..=(length * 255)).step_by(10) {
            let output = prf.compute_prf(&[0x01, 0x02], i).unwrap_or_else(|e| {
                panic!(
                    "Expected to be able to compute HKDF {:?} PRF with {} output length: {:?}",
                    hash, i, e
                )
            });
            assert_eq!(
                output.len(),
                i,
                "Expected HKDF {:?} PRF to compute {} bytes, got {}",
                hash,
                i,
                output.len()
            );
        }
        for i in (length * 255 + 1)..(length * 255 + 100) {
            assert!(
                prf.compute_prf(&[0x01, 0x02], i).is_err(),
                "Expected to not be able to compute HKDF {:?} PRF with {} output length",
                hash,
                i
            );
        }
    }
}

#[test]
fn test_validate_hkdf_prf_params() {
    assert!(
        validate_hkdf_prf_params(HashType::Sha256, 32, &[]).is_ok(),
        "Unexpected error for valid HKDF PRF params"
    );
    assert!(
        validate_hkdf_prf_params(HashType::Sha256, 32, &[0xaf, 0xfe, 0xc0, 0xff, 0xee]).is_ok(),
        "Unexpected error for salted valid HKDF PRF params"
    );

    assert!(
        validate_hkdf_prf_params(HashType::Sha256, 4, &[]).is_err(),
        "Short key size not detected for HKDF PRF params"
    );
    assert!(
        validate_hkdf_prf_params(HashType::UnknownHash, 32, &[]).is_err(),
        "Unknown hash function not detected for HKDF PRF params"
    );
    assert!(
        validate_hkdf_prf_params(HashType::Sha1, 32, &[]).is_err(),
        "Weak hash function not detected for HKDF PRF params"
    );
}

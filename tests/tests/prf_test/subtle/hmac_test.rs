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

use super::aes_cmac_test::TestData;
use maplit::hashmap;
use std::collections::HashMap;
use tink::Prf;
use tink_prf::subtle::{validate_hmac_prf_params, HmacPrf};
use tink_proto::HashType;

struct Rfc4868Test {
    key: &'static str,
    data: &'static str,
    prf: HashMap<HashType, &'static str>,
}

#[test]
fn test_vectors_rfc4868() {
    // Test vectors from RFC 4868.
    let testvectors = [
        Rfc4868Test{
            key:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            data: "4869205468657265",
            prf: hashmap! {
                HashType::Sha256 => "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                HashType::Sha512 => "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            },
        },
        Rfc4868Test{
            key:  "4a656665",
            data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
            prf: hashmap! {
                HashType::Sha256 => "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
                HashType::Sha512 => "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            },
        },
        Rfc4868Test{
            key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            data: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            prf: hashmap! {
                HashType::Sha256 => "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
                HashType::Sha512 => "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            },
        },
        Rfc4868Test{
            key:  "0102030405060708090a0b0c0d0e0f10111213141516171819",
            data: "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
            prf: hashmap! {
                HashType::Sha256 => "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
                HashType::Sha512 => "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
            },
        },
        Rfc4868Test{
            key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
            prf: hashmap! {
                HashType::Sha256 => "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                HashType::Sha512 => "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            },
        },
        Rfc4868Test{
            key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            data: "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e",
            prf: hashmap! {
                HashType::Sha256 => "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                HashType::Sha512 => "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
            },
        },
    ];
    for v in testvectors.iter() {
        let key = hex::decode(v.key).expect("Could not decode key");
        let data = hex::decode(v.data).expect("Could not decode salt");
        for (hash, e) in &v.prf {
            let p = HmacPrf::new(*hash, &key).expect("Could not create HMAC PRF object");
            let output = p
                .compute_prf(&data, e.len() / 2)
                .expect("Error computing HMAC");
            assert_eq!(
                hex::encode(output),
                *e,
                "Computation and test vector differ."
            );
        }
    }
}

#[test]
fn test_hmac_prf_wycheproof_cases() {
    for hash in &[HashType::Sha1, HashType::Sha256, HashType::Sha512] {
        let hash_name = format!("{:?}", hash);
        let filename = format!("testvectors/hmac_{}_test.json", hash_name.to_lowercase());
        println!("wycheproof file '{}' hash {}", filename, hash_name);
        let bytes = tink_tests::wycheproof_data(&filename);
        let data: TestData = serde_json::from_slice(&bytes).unwrap();

        for g in &data.test_groups {
            for tc in &g.tests {
                println!(
                    "     case {} [{}] {}",
                    tc.case.case_id, tc.case.result, tc.case.comment
                );
                assert_eq!(tc.key.len() * 8, g.key_size as usize);

                let h = HmacPrf::new(*hash, &tc.key);
                let valid = tc.case.result == tink_tests::WycheproofResult::Valid;
                if valid && h.is_err() {
                    panic!(
                        "Could not create HmacPrf for test case {} ({})",
                        tc.case.case_id, tc.case.comment
                    );
                }
                if !valid && h.is_err() {
                    continue;
                }
                assert_eq!(
                    g.tag_size % 8,
                    0,
                    "Requested tag size for test case {} ({}) is not a multiple of 8, but {}",
                    tc.case.case_id,
                    tc.case.comment,
                    g.tag_size
                );
                let res = match h.unwrap().compute_prf(&tc.msg, (g.tag_size / 8) as usize) {
                    Err(e) => {
                        assert!(
                            !valid,
                            "Could not compute HMAC for test case {} ({}): {}",
                            tc.case.case_id, tc.case.comment, e
                        );
                        continue;
                    }
                    Ok(r) => r,
                };
                if valid {
                    assert_eq!(
                        res, tc.tag,
                        "Computed HMAC and expected for test case {} ({}) do not match",
                        tc.case.case_id, tc.case.comment
                    );
                } else {
                    assert_ne!(
                        res, tc.tag,
                        "Computed HMAC and invalid expected for test case {} ({}) match",
                        tc.case.case_id, tc.case.comment
                    )
                }
            }
        }
    }
}

#[test]
fn test_hmacprf_hash() {
    assert!(
        HmacPrf::new(
            HashType::Sha256,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ]
        )
        .is_ok(),
        "Expected HmacPrf::new to work with SHA256"
    );
    assert!(
        HmacPrf::new(
            HashType::Sha512,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ]
        )
        .is_ok(),
        "Expected HmacPrf::new to work with SHA512"
    );
    assert!(
        HmacPrf::new(
            HashType::Sha1,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ]
        )
        .is_ok(),
        "Expected HmacPrf::new to work with SHA1"
    );
    assert!(
        HmacPrf::new(
            HashType::UnknownHash,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10
            ]
        )
        .is_err(),
        "Expected HmacPrf::new to fail with unknown hash"
    );
}

#[test]
fn test_hmac_prf_output_length() {
    let testdata = hashmap! {
        HashType::Sha1 => 20,
        HashType::Sha256 => 32,
        HashType::Sha512 => 64,
    };
    for (hash, length) in testdata {
        let prf = HmacPrf::new(
            hash,
            &[
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
                0x0f, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                0x0d, 0x0e, 0x0f, 0x10,
            ],
        )
        .unwrap_or_else(|_| {
            panic!(
                "Expected HmacPrf::new to work on 32 byte key with hash {:?}",
                hash
            )
        });

        for i in 0..=length {
            let output = prf.compute_prf(&[0x01, 0x02], i).unwrap_or_else(|e| {
                panic!(
                    "Expected to be able to compute HMAC {:?} PRF with {} output length: {:?}",
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
        for i in (length + 1)..100 {
            assert!(
                prf.compute_prf(&[0x01, 0x02], i).is_err(),
                "Expected to not be able to compute HMAC {:?} PRF with {} output length",
                hash,
                i
            );
        }
    }
}

#[test]
fn test_validate_hmac_prf_params() {
    assert!(
        validate_hmac_prf_params(HashType::Sha256, 32).is_ok(),
        "Unexpected error for valid HMAC PRF params"
    );
    assert!(
        validate_hmac_prf_params(HashType::Sha256, 4).is_err(),
        "Short key size not detected for HMAC PRF params"
    );
    assert!(
        validate_hmac_prf_params(HashType::UnknownHash, 32).is_err(),
        "Unknown hash function not detected for HMAC PRF params"
    );
}

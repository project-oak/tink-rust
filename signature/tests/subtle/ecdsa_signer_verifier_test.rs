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

use generic_array::typenum::Unsigned;
use p256::elliptic_curve::Generate;
use serde::Deserialize;
use std::collections::HashSet;
use tink::{
    proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType},
    subtle::random::get_random_bytes,
    Signer, Verifier,
};
use tink_signature::subtle::{EcdsaPrivateKey, EcdsaPublicKey};

#[test]
fn test_sign_verify() {
    let mut csprng = rand::thread_rng();
    let data = get_random_bytes(20);
    let hash = HashType::Sha256;
    let curve = EllipticCurveType::NistP256;
    let encodings = vec![
        EcdsaSignatureEncoding::Der,
        EcdsaSignatureEncoding::IeeeP1363,
    ];
    for encoding in encodings {
        let (priv_key, pub_key) = match curve {
            EllipticCurveType::NistP256 => {
                let secret_key = p256::SecretKey::generate(&mut csprng);
                let public_key =
                    p256::PublicKey::from_secret_key(&secret_key, /* compressed= */ false).unwrap();
                (
                    EcdsaPrivateKey::NistP256(secret_key),
                    EcdsaPublicKey::NistP256(public_key),
                )
            }
            _ => panic!("unsupported curve {:?}", curve),
        };
        let priv_key_bytes = match &priv_key {
            EcdsaPrivateKey::NistP256(secret_key) => secret_key.as_bytes().to_vec(),
        };
        let (pub_x, pub_y) = match &pub_key {
            EcdsaPublicKey::NistP256(public_key) => {
                let point_len = <p256::NistP256 as elliptic_curve::Curve>::ElementSize::to_usize();
                let pub_key_data = public_key.as_bytes();
                assert_eq!(
                    pub_key_data[0],
                    tink_signature::ECDSA_UNCOMPRESSED_POINT_PREFIX
                );
                (
                    pub_key_data[1..point_len + 1].to_vec(),
                    pub_key_data[point_len + 1..].to_vec(),
                )
            }
        };

        // Use the private key and public key directly to create new instances
        let signer = tink_signature::subtle::EcdsaSigner::new_from_private_key(
            hash, curve, encoding, priv_key,
        )
        .expect("unexpected error when creating EcdsaSigner");
        let verifier = tink_signature::subtle::EcdsaVerifier::new_from_public_key(
            hash, curve, encoding, pub_key,
        )
        .expect("unexpected error when creating ECDSAVerifier");
        let signature = signer.sign(&data).expect("unexpected error when signing");
        assert!(
            verifier.verify(&signature, &data).is_ok(),
            "unexpected error when verifying"
        );

        // Use byte slices to create new instances
        let signer =
            tink_signature::subtle::EcdsaSigner::new(hash, curve, encoding, &priv_key_bytes)
                .expect("unexpected error when creating EcdsaSigner");
        let verifier =
            tink_signature::subtle::EcdsaVerifier::new(hash, curve, encoding, &pub_x, &pub_y)
                .expect("unexpected error when creating EcdsaVerifier");
        let signature = signer.sign(&data).expect("unexpected error when signing");
        assert!(
            verifier.verify(&signature, &data).is_ok(),
            "unexpected error when verifying"
        );
    }
}

#[derive(Debug, Deserialize)]
struct TestData {
    #[serde(flatten)]
    pub suite: tink_testutil::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
struct TestGroup {
    #[serde(flatten)]
    pub group: tink_testutil::WycheproofGroup,
    pub jwk: Option<Jwk>,
    #[serde(rename = "keyDer")]
    pub key_der: String,
    #[serde(rename = "keyPem")]
    pub key_pem: String,
    pub sha: String,
    pub key: TestKey,
    pub tests: Vec<TestCase>,
}

#[derive(Debug, Deserialize)]
struct TestKey {
    curve: String,
    #[serde(rename = "type")]
    key_type: String,
    wx: String,
    wy: String,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    crv: String,
    kid: String,
    kty: String,
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    #[serde(flatten)]
    pub case: tink_testutil::WycheproofCase,
    pub msg: String,
    pub sig: String,
}

#[test]
fn test_wycheproof_vectors() {
    struct TestVector {
        filename: &'static str,
        encoding: EcdsaSignatureEncoding,
        panic_tests: HashSet<i32>,
    }
    let vectors = vec![
        TestVector {
            filename: "ecdsa_test.json",
            encoding: EcdsaSignatureEncoding::Der,
            panic_tests: vec![4, 654, 690, 693, 707, 708].into_iter().collect(),
        },
        TestVector {
            filename: "ecdsa_secp256r1_sha256_p1363_test.json",
            encoding: EcdsaSignatureEncoding::IeeeP1363,
            panic_tests: vec![136, 172, 175, 189, 190].into_iter().collect(),
        },
        /* TODO: more ECDSA curves
                TestVector {
                    filename: "ecdsa_secp384r1_sha512_p1363_test.json",
                    encoding: EcdsaSignatureEncoding::IeeeP1363,
                },
                TestVector {
                    filename: "ecdsa_secp521r1_sha512_p1363_test.json",
                    encoding: EcdsaSignatureEncoding::IeeeP1363,
                },
        */
    ];
    for v in vectors {
        wycheproof_test(v.filename, v.encoding, v.panic_tests)
    }
}

fn wycheproof_test(filename: &str, encoding: EcdsaSignatureEncoding, panic_tests: HashSet<i32>) {
    // TODO: fix all panic tests
    println!(
        "wycheproof file 'testvectors/{}', encoding '{:?}'",
        filename, encoding
    );
    let bytes = tink_testutil::wycheproof_data(&format!("testvectors/{}", filename));
    let data: TestData = serde_json::from_slice(&bytes).unwrap();
    let mut skipped_hashes = HashSet::new();
    let mut skipped_curves = HashSet::new();
    for g in &data.test_groups {
        let hash = convert_hash_name(&g.sha);
        let curve = convert_curve_name(&g.key.curve);
        if hash == HashType::UnknownHash {
            if !skipped_hashes.contains(&g.sha) {
                println!("skipping tests for unsupported hash {}", g.sha);
                skipped_hashes.insert(g.sha.clone());
            }
            continue;
        }
        // TODO: more ECDSA curves
        // if curve == EllipticCurveType::UnknownCurve {
        if curve != EllipticCurveType::NistP256 {
            if !skipped_curves.contains(&g.key.curve) {
                println!("skipping tests for unsupported curve {}", g.key.curve);
                skipped_curves.insert(g.key.curve.clone());
            }
            continue;
        }
        let x_bytes = hex::decode(&g.key.wx).expect("cannot decode wx");
        let y_bytes = hex::decode(&g.key.wy).expect("cannot decode wy");
        println!(
            "   key info: {:?}, {:?}, {:?}, {}, {}",
            hash,
            curve,
            encoding,
            hex::encode(&x_bytes),
            hex::encode(&y_bytes),
        );
        let verifier = match tink_signature::subtle::EcdsaVerifier::new(
            hash, curve, encoding, &x_bytes, &y_bytes,
        ) {
            Ok(v) => v,
            Err(e) => {
                panic!("failed to build verifier for key: {:?}", e);
            }
        };
        for tc in &g.tests {
            if panic_tests.contains(&tc.case.case_id) {
                println!(
                    "     SKIP case {} [{}] {}",
                    tc.case.case_id, tc.case.result, tc.case.comment
                );
                continue;
            }
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            let message = hex::decode(&tc.msg).unwrap_or_else(|e| {
                panic!(
                    "cannot decode message in test case {}: {}",
                    tc.case.case_id, e
                )
            });
            let sig = hex::decode(&tc.sig).unwrap_or_else(|e| {
                panic!(
                    "cannot decode signature in test case {}: {}",
                    tc.case.case_id, e
                )
            });
            let result = verifier.verify(&sig, &message);
            if (tc.case.result == "valid" && result.is_err())
                || (tc.case.result == "invalid" && result.is_ok())
            {
                panic!(
                    "failed in test case {} with result '{:?}' ",
                    tc.case.case_id, result
                );
            }
        }
    }
}

/// Convert different forms of a hash name to the hash type that Tink recognizes.
pub fn convert_hash_name(name: &str) -> HashType {
    match name {
        "SHA-256" => HashType::Sha256,
        "SHA-384" => HashType::Sha384,
        "SHA-512" => HashType::Sha512,
        "SHA-1" => HashType::Sha1,
        _ => HashType::UnknownHash,
    }
}

/// Convert different forms of a curve name to the type that Tink recognizes.
pub fn convert_curve_name(name: &str) -> EllipticCurveType {
    match name {
        "secp256r1" | "P-256" => EllipticCurveType::NistP256,
        "secp384r1" | "P-384" => EllipticCurveType::NistP384,
        "secp521r1" | "P-521" => EllipticCurveType::NistP521,
        _ => EllipticCurveType::UnknownCurve,
    }
}

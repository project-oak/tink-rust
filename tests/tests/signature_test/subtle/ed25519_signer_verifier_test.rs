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

use ed25519_dalek::Keypair;
use serde::Deserialize;
use tink_core::{subtle::random::get_random_bytes, Signer, TinkError, Verifier};
use tink_signature::subtle::{Ed25519Signer, Ed25519Verifier};
use tink_tests::WycheproofResult;

#[test]
fn test_ed25519_deterministic() {
    let data = get_random_bytes(20);
    let mut csprng = rand::thread_rng();
    let keypair = Keypair::generate(&mut csprng);

    // Use the private key and public key directly to create new instances
    let (signer, verifier) = new_signer_verifier(keypair)
        .expect("unexpected error when creating ED25519 Signer and Verifier");
    let sign1 = signer.sign(&data).expect("unexpected error when signing");
    assert!(
        verifier.verify(&sign1, &data).is_ok(),
        "unexpected error when verifying"
    );

    let sign2 = signer.sign(&data).expect("unexpected error when signing");
    assert!(
        verifier.verify(&sign2, &data).is_ok(),
        "unexpected error when verifying"
    );
    assert_eq!(sign1, sign2, "deterministic signature check failure");
}

#[test]
fn test_ed25519_verify_modified_signature() {
    let data = get_random_bytes(20);
    let mut csprng = rand::thread_rng();
    let keypair = Keypair::generate(&mut csprng);

    // Use the private key and public key directly to create new instances
    let (signer, verifier) =
        new_signer_verifier(keypair).expect("failed to create new signer verifier");

    let mut sign = signer.sign(&data).expect("unexpected error when signing");

    for i in 0..sign.len() {
        for j in 0..8 {
            let prev = sign[i];
            sign[i] ^= 1 << j;
            assert!(
                verifier.verify(&sign, &data).is_err(),
                "unexpected success when verifying signature modified at [{}] bit {}",
                i,
                j
            );
            sign[i] = prev;
        }
    }
}

#[test]
fn test_ed25519_verify_truncated_signature() {
    let data = get_random_bytes(20);
    let mut csprng = rand::thread_rng();
    let keypair = Keypair::generate(&mut csprng);

    // Use the private key and public key directly to create new instances
    let (signer, verifier) =
        new_signer_verifier(keypair).expect("failed to create new signer verifier");

    let sign = signer.sign(&data).expect("unexpected error when signing");

    let result = verifier.verify(&sign[..sign.len() - 1], &data);
    tink_tests::expect_err(result, "length of the signature");
}

#[test]
fn test_ed25519_verify_modified_message() {
    let mut data = get_random_bytes(20);
    let mut csprng = rand::thread_rng();
    let keypair = Keypair::generate(&mut csprng);

    // Use the private key and public key directly to create new instances
    let (signer, verifier) =
        new_signer_verifier(keypair).expect("failed to create new signer verifier");

    let sign = signer.sign(&data).expect("unexpected error when signing");

    for i in 0..data.len() {
        for j in 0..8 {
            let prev = data[i];
            data[i] ^= 1 << j;
            assert!(
                verifier.verify(&sign, &data).is_err(),
                "unexpected success when verifying signature of data modified at [{}] bit {}",
                i,
                j
            );
            data[i] = prev;
        }
    }
}
#[test]
fn test_ed25519_sign_verify() {
    let mut csprng = rand::thread_rng();
    let keypair = Keypair::generate(&mut csprng);
    let seed = keypair.secret.as_bytes().to_vec();

    // Use the private key and public key directly to create new instances
    let (signer, verifier) = new_signer_verifier(keypair)
        .expect("unexpected error when creating ED25519 Signer and Verifier");
    for _i in 0..100 {
        let data = get_random_bytes(20);
        let signature = signer.sign(&data).expect("unexpected error when signing");
        assert!(
            verifier.verify(&signature, &data).is_ok(),
            "unexpected error when verifying"
        );

        // Use byte slices to create new instances
        let signer = tink_signature::subtle::Ed25519Signer::new(&seed[..])
            .expect("unexpected error when creating ED25519 Signer");

        let signature = signer.sign(&data).expect("unexpected error when signing");
        assert!(
            verifier.verify(&signature, &data).is_ok(),
            "unexpected error when verifying"
        );
    }
}

#[test]
fn test_ed25519_signer_invalid_seed() {
    let result = tink_signature::subtle::Ed25519Signer::new(&[]);
    tink_tests::expect_err(result, "invalid key");
    let result = tink_signature::subtle::Ed25519Signer::new(&[1, 2, 3]);
    tink_tests::expect_err(result, "invalid key");
}

#[derive(Debug, Deserialize)]
struct TestDataEd25519 {
    #[serde(flatten)]
    pub suite: tink_tests::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroupEd25519>,
}

#[derive(Debug, Deserialize)]
struct TestGroupEd25519 {
    #[serde(flatten)]
    pub group: tink_tests::WycheproofGroup,
    #[serde(rename = "keyDer")]
    pub key_der: String,
    #[serde(rename = "keyPem")]
    pub key_pem: String,
    pub key: TestKeyEd25519,
    pub tests: Vec<TestCaseEd25519>,
}

#[derive(Debug, Deserialize)]
struct TestKeyEd25519 {
    #[serde(with = "tink_tests::hex_string")]
    sk: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pk: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TestCaseEd25519 {
    #[serde(flatten)]
    pub case: tink_tests::WycheproofCase,
    #[serde(with = "tink_tests::hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "tink_tests::hex_string")]
    pub sig: Vec<u8>,
}

#[test]
fn test_ed25519_wycheproof_cases() {
    let filename = "testvectors/eddsa_test.json";
    println!("wycheproof file '{}'", filename);
    let bytes = tink_tests::wycheproof_data(filename);
    let data: TestDataEd25519 = serde_json::from_slice(&bytes).unwrap();
    for g in &data.test_groups {
        println!(
            "   key info: sk={}, pk={}",
            hex::encode(&g.key.sk),
            hex::encode(&g.key.pk)
        );

        let signer = match Ed25519Signer::new(&g.key.sk) {
            Ok(s) => s,
            Err(e) => {
                panic!("failed to build signer for test group {:?}: {:?}", g, e);
            }
        };
        let verifier = match Ed25519Verifier::new(&g.key.pk) {
            Ok(v) => v,
            Err(e) => {
                panic!("failed to build verifier for test group {:?}: {:?}", g, e);
            }
        };

        for tc in &g.tests {
            println!(
                "     case {} [{}] {}",
                tc.case.case_id, tc.case.result, tc.case.comment
            );
            let result = signer.sign(&tc.msg);
            match tc.case.result {
                tink_tests::WycheproofResult::Valid => {
                    match result {
                        Err(e) => panic!(
                            "Ed25519Signer::sign failed in test case {}: with error {:?}",
                            tc.case.case_id, e
                        ),
                        Ok(got) => {
                            // Ed25519 is deterministic.
                            // Getting an alternative signature may leak the private key.
                            // This is especially the case if an attacker can also learn the valid
                            // signature.
                            assert_eq!(
                                tc.sig,
                                got,
                                "Ed25519Signer::sign failed in test case {}: invalid signature generated {}",
                                tc.case.case_id,
                                hex::encode(&got)
                            )
                        }
                    }
                }
                tink_tests::WycheproofResult::Invalid => {
                    if result.is_ok() && tc.sig == result.unwrap() {
                        panic!(
                            "Ed25519Signer::sign failed in test case {}: invalid signature generated",
                            tc.case.case_id
                        )
                    }
                }
                _ => panic!("unrecognized result {}", tc.case.result),
            }

            let result = verifier.verify(&tc.sig, &tc.msg);
            match tc.case.result {
                WycheproofResult::Valid => assert!(
                    result.is_ok(),
                    "verify failed in test case {}: valid signature is rejected with error {:?}",
                    tc.case.case_id,
                    result
                ),
                WycheproofResult::Invalid => assert!(
                    result.is_err(),
                    "verify failed in test case {}: invalid signature is accepted",
                    tc.case.case_id
                ),
                _ => panic!("unrecognized result {}", tc.case.result),
            }
        }
    }
}

fn new_signer_verifier(
    keypair: ed25519_dalek::Keypair,
) -> Result<(Ed25519Signer, Ed25519Verifier), TinkError> {
    let pub_key = keypair.public;
    let signer = Ed25519Signer::new_from_keypair(keypair)?;
    let verifier = Ed25519Verifier::new_from_public_key(pub_key)?;
    Ok((signer, verifier))
}

#[test]
fn test_ed25519_point_on_curve() {
    // Point taken from ed25519_dalek::PublicKey docs.
    let public_key_bytes: [u8; 32] = [
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26,
    ];
    assert!(ed25519_dalek::PublicKey::from_bytes(&public_key_bytes).is_ok());
    assert!(Ed25519Verifier::new(&public_key_bytes).is_ok());

    // Change final byte, and confirm that a point not on the curve is rejected.
    let public_key_bytes: [u8; 32] = [
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243,
        218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 24,
    ];
    let result = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes);
    assert!(result.is_err());
    assert!(format!("{:?}", result).contains("Cannot decompress"));
    assert!(Ed25519Verifier::new(&public_key_bytes).is_err());
}

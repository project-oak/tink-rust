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
use tink::{subtle::random::get_random_bytes, Signer, TinkError, Verifier};
use tink_signature::subtle::{Ed25519Signer, Ed25519Verifier};
use tink_testutil::WycheproofResult;

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

#[derive(Debug, Deserialize)]
struct TestDataEd25519 {
    #[serde(flatten)]
    pub suite: tink_testutil::WycheproofSuite,
    #[serde(rename = "testGroups")]
    pub test_groups: Vec<TestGroupEd25519>,
}

#[derive(Debug, Deserialize)]
struct TestGroupEd25519 {
    #[serde(flatten)]
    pub group: tink_testutil::WycheproofGroup,
    #[serde(rename = "keyDer")]
    pub key_der: String,
    #[serde(rename = "keyPem")]
    pub key_pem: String,
    pub key: TestKeyEd25519,
    pub tests: Vec<TestCaseEd25519>,
}

#[derive(Debug, Deserialize)]
struct TestKeyEd25519 {
    #[serde(with = "tink_testutil::hex_string")]
    sk: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pk: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct TestCaseEd25519 {
    #[serde(flatten)]
    pub case: tink_testutil::WycheproofCase,
    #[serde(with = "tink_testutil::hex_string")]
    pub msg: Vec<u8>,
    #[serde(with = "tink_testutil::hex_string")]
    pub sig: Vec<u8>,
}

#[test]
fn test_vectors_ed25519() {
    // signing tests are same between ecdsa and ed25519
    let filename = "testvectors/eddsa_test.json";
    println!("wycheproof file '{}'", filename);
    let bytes = tink_testutil::wycheproof_data(filename);
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
            if tc.case.result == tink_testutil::WycheproofResult::Valid {
                match result {
                    Err(e) => panic!(
                        "sign failed in test case {}: with error {:?}",
                        tc.case.case_id, e
                    ),
                    Ok(got) =>
                    // Ed25519 is deterministic.
                    // Getting an alternative signature may leak the private key.
                    // This is especially the case if an attacker can also learn the valid
                    // signature.
                    {
                        assert_eq!(
                            tc.sig,
                            got,
                            "sign failed in test case {}: invalid signature generated {}",
                            tc.case.case_id,
                            hex::encode(&got)
                        )
                    }
                }
            } else if result.is_ok() && tc.sig == result.unwrap() {
                panic!(
                    "sign failed in test case {}: invalid signature generated",
                    tc.case.case_id
                )
            }

            let result = verifier.verify(&tc.sig, &tc.msg);
            if tc.case.result == WycheproofResult::Valid && result.is_err() {
                panic!(
                    "verify failed in test case {}: valid signature is rejected with error {:?}",
                    tc.case.case_id, result
                )
            }
            if tc.case.result == WycheproofResult::Invalid && result.is_ok() {
                panic!(
                    "verify failed in test case {}: invalid signature is accepted",
                    tc.case.case_id
                )
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

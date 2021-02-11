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

use std::{env, path::PathBuf};
use tink_core::{registry::KmsClient, subtle::random::get_random_bytes, TinkError};

use super::common::*;

fn init() {
    tink_aead::init();
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../third_party/pki.goog",
        "roots.pem",
    ]
    .iter()
    .collect();
    let cert_path = path.to_str().unwrap();

    // The `SSL_CERT_FILE` environment variable gives the location of a non-default CA bundle file.
    std::env::set_var("SSL_CERT_FILE", cert_path);
}

fn setup_kms() {
    init();
    let creds = cred_file();
    let g = if creds.components().next().is_some() {
        tink_gcpkms::GcpClient::new_with_credentials(&key_uri(), &creds)
    } else {
        // Use default credentials if credentials file path is empty.
        tink_gcpkms::GcpClient::new(&key_uri())
    }
    .expect("error setting up aws client");
    tink_core::registry::register_kms_client(g);
}

fn basic_aead_test(a: Box<dyn tink_core::Aead>) -> Result<(), TinkError> {
    for _ in 0..10 {
        let pt = get_random_bytes(20);
        let ad = get_random_bytes(20);
        let ct = a.encrypt(&pt, &ad)?;
        let dt = a.decrypt(&ct, &ad)?;
        if dt != pt {
            return Err("decrypt not inverse of encrypt".into());
        }
    }
    Ok(())
}

// This test is ignored because it requires a valid live GCP key URI (and GCP credentials) to
// succeed.
#[test]
#[ignore]
fn test_gcpkms_basic_aead() {
    setup_kms();
    let dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let kh =
        tink_core::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(&key_uri(), dek))
            .expect("error getting a new keyset handle");
    let a = tink_aead::new(&kh).expect("error getting the primitive");
    let result = basic_aead_test(a);
    assert!(result.is_ok(), "error in basic aead tests: {:?}", result);
}

#[test]
fn test_aead_with_invalid_key_fail() {
    init();
    let key_uri = "gcp-kms://projects/absent/locations/global/keyRings/nope/cryptoKeys/bogus";
    let client = tink_gcpkms::GcpClient::new(key_uri).unwrap();
    let aead = client.get_aead(key_uri).unwrap();

    // Not a valid key URI so everything will fail.
    let result = aead.encrypt(b"data", b"aad");
    tink_tests::expect_err(result, "request failed");
    let result = aead.encrypt(b"data", b"");
    tink_tests::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"aad");
    tink_tests::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"");
    tink_tests::expect_err(result, "request failed");
}

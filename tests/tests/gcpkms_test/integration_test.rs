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

use super::common::*;

// This test is ignored because it requires a valid live GCP key URI (and GCP credentials) to
// succeed.
#[test]
#[ignore]
fn gcpkms_example() {
    tink_aead::init();
    let key_uri = key_uri(); // something like "gcp-kms://......";
    let creds = cred_file(); // e.g. "/mysecurestorage/credentials.json";
    println!("Running with key {} and creds {:?}", key_uri, creds);

    let gcp_client = if creds.components().next().is_some() {
        tink_gcpkms::GcpClient::new_with_credentials(&key_uri, &creds)
    } else {
        // Use default credentials if credentials file path is empty.
        tink_gcpkms::GcpClient::new(&key_uri)
    }
    .unwrap();
    tink_core::registry::register_kms_client(gcp_client);

    let dek_template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let kh = tink_core::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(
        &key_uri,
        dek_template,
    ))
    .unwrap();
    let a = tink_aead::new(&kh).unwrap();

    // Each encryption operation uses a new key (generated from `dek_template`), which is also
    // included in the ciphertext (in encrypted form).
    let pt = b"this data needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct = a.encrypt(pt, aad).unwrap();

    let pt2 = a.decrypt(&ct, aad).unwrap();
    assert_eq!(&pt[..], pt2);
}

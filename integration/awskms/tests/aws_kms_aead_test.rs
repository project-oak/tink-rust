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

use std::path::PathBuf;
use tink::{registry::KmsClient, subtle::random::get_random_bytes, TinkError};

const KEY_URI: &str =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

const CRED_FILE: &str = "../../testdata/credentials_aws.csv";
const CRED_INI_FILE: &str = "../../testdata/credentials_aws.ini";

fn init() {
    tink_aead::init();
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../../../third_party/pki.goog",
        "roots.pem",
    ]
    .iter()
    .collect();
    let cert_path = path.to_str().unwrap();

    // The `SSL_CERT_FILE` environment variable gives the location of a non-default CA bundle file.
    std::env::set_var("SSL_CERT_FILE", cert_path);
}

fn setup_kms(cf: &std::path::Path) {
    let g = tink_awskms::AwsClient::new_with_credentials(KEY_URI, cf)
        .expect("error setting up aws client");
    tink::registry::register_kms_client(g);
}

fn basic_aead_test(a: Box<dyn tink::Aead>) -> Result<(), TinkError> {
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

// The AWS key used in the following tests are not generally accessible.
#[test]
#[ignore]
fn test_basic_aead() {
    init();
    for file in &[CRED_FILE, CRED_INI_FILE] {
        setup_kms(&std::path::PathBuf::from(file));
        let dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
        let kh =
            tink::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(KEY_URI, dek))
                .expect("error getting a new keyset handle");
        let a = tink_aead::new(&kh).expect("error getting the primitive");
        assert!(basic_aead_test(a).is_ok(), "error in basic aead tests");
    }
}

#[test]
#[ignore]
fn test_basic_aead_without_additional_data() {
    init();
    for file in &[CRED_FILE, CRED_INI_FILE] {
        setup_kms(&std::path::PathBuf::from(file));
        let dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
        let kh =
            tink::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(KEY_URI, dek))
                .expect("error getting a new keyset handle");
        let a = tink_aead::new(&kh).expect("error getting the primitive");
        // Only test 10 times (instead of 100) because each test makes HTTP requests to AWS.
        for _ in 0..10 {
            let pt = get_random_bytes(20);
            let ct = a.encrypt(&pt, &[]).expect("error encrypting data");
            let dt = a.decrypt(&ct, &[]).expect("error decrypting data");
            assert_eq!(dt, pt, "decrypt not inverse of encrypt");
        }
    }
}

#[test]
fn test_aead_with_invalid_key_fail() {
    init();
    let key_uri = "aws-kms://arn:aws:kms:us-east-2:1234567:key/aaaaa-bbbb-cccc-dddd-eeeee";
    let client = tink_awskms::AwsClient::new(key_uri).unwrap();
    let aead = client.get_aead(key_uri).unwrap();

    // Not a valid key URI so everything will fail.
    let result = aead.encrypt(b"data", b"aad");
    tink_testutil::expect_err(result, "request failed");
    let result = aead.encrypt(b"data", b"");
    tink_testutil::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"aad");
    tink_testutil::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"");
    tink_testutil::expect_err(result, "request failed");
}

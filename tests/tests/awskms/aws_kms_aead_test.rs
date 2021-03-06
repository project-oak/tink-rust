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
use tink_core::{registry::KmsClient, subtle::random::get_random_bytes, TinkError};

const KEY_ALIAS_URI: &str =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:alias/unit-and-integration-testing";
const KEY_URI: &str =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

const CRED_FILE: &str = "testdata/credentials_aws.csv";
const CRED_INI_FILE: &str = "testdata/credentials_aws.ini";

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

fn setup_kms(cf: &std::path::Path) {
    setup_kms_with_uri(cf, KEY_URI);
}

fn setup_kms_with_uri(cf: &std::path::Path, uri: &str) {
    let g =
        tink_awskms::AwsClient::new_with_credentials(uri, cf).expect("error setting up aws client");

    // The registry will return the first KMS client that claims support for
    // the keyURI.  The tests re-use the same keyURI, so clear any clients
    // registered by earlier tests before registering the new client.
    tink_core::registry::clear_kms_clients();
    tink_core::registry::register_kms_client(g);
}

fn basic_aead_test(a: Box<dyn tink_core::Aead>) -> Result<(), TinkError> {
    basic_aead_test_with_options(
        a, /* loop_count= */ 10, /* with_additional_data = */ true,
    )
}
fn basic_aead_test_with_options(
    a: Box<dyn tink_core::Aead>,
    loop_count: usize,
    with_additional_data: bool,
) -> Result<(), TinkError> {
    for _ in 0..loop_count {
        let pt = get_random_bytes(20);
        let ad = if with_additional_data {
            get_random_bytes(20)
        } else {
            vec![]
        };
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
        let kh = tink_core::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(
            KEY_URI, dek,
        ))
        .expect("error getting a new keyset handle");
        let a = tink_aead::new(&kh).expect("error getting the primitive");
        assert!(basic_aead_test(a).is_ok(), "error in basic aead tests");
    }
}

#[test]
#[ignore]
fn test_basic_aead_without_additional_data() {
    init();
    for uri in &[KEY_URI, KEY_ALIAS_URI] {
        for file in &[CRED_FILE, CRED_INI_FILE] {
            setup_kms_with_uri(&std::path::PathBuf::from(file), uri);
            let dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
            let kh = tink_core::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(
                uri, dek,
            ))
            .expect("error getting a new keyset handle");
            let a = tink_aead::new(&kh).expect("error getting the primitive");
            // Only test 10 times (instead of 100) because each test makes HTTP requests to AWS.
            assert!(basic_aead_test_with_options(
                a, /* loop_count= */ 19, /* with_additional_data= */ false
            )
            .is_ok())
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
    tink_tests::expect_err(result, "request failed");
    let result = aead.encrypt(b"data", b"");
    tink_tests::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"aad");
    tink_tests::expect_err(result, "request failed");
    let result = aead.decrypt(b"data", b"");
    tink_tests::expect_err(result, "request failed");
}

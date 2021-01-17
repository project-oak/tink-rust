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

use tink_core::registry::KmsClient;
use tink_tests::{fakekms, fakekms::FakeClient};

const KEY_URI: &str = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE";
const ANOTHER_KEY_URI: &str = "fake-kms://CLHW_5cHElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIZ-2h9InfZTbbkJjaJBsVgYARABGLHW_5cHIAE";

#[test]
fn test_valid_key_uris() {
    tink_aead::init();
    let new_key_uri = fakekms::new_key_uri().unwrap();
    let test_cases = vec![KEY_URI, ANOTHER_KEY_URI, &new_key_uri];
    for key_uri in test_cases {
        let client = fakekms::FakeClient::new(key_uri).unwrap();
        assert!(client.supported(key_uri));
        let primitive = client.get_aead(key_uri).unwrap();

        let plaintext = b"some data to encrypt";
        let aad = b"extra data to authenticate";
        let ciphertext = primitive.encrypt(&plaintext[..], &aad[..]).unwrap();
        let decrypted = primitive.decrypt(&ciphertext, &aad[..]).unwrap();
        assert_eq!(&plaintext[..], decrypted);
    }
}

#[test]
fn test_bad_uri_prefix() {
    tink_aead::init();
    assert!(fakekms::FakeClient::new("bad-prefix://encodedkeyset").is_err());
}

#[test]
fn test_valid_prefix() {
    tink_aead::init();
    let uri_prefix = "fake-kms://CM2b"; // is a prefix of KEY_URI
    let client = FakeClient::new(uri_prefix).unwrap();
    assert!(client.supported(KEY_URI));
    let result = client.get_aead(KEY_URI);
    assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn test_invalid_prefix() {
    tink_aead::init();
    let uri_prefix = "fake-kms://CM2x"; // is not a prefix of KEY_URI
    let client = FakeClient::new(uri_prefix).unwrap();
    assert!(!client.supported(KEY_URI));
    assert!(client.get_aead(KEY_URI).is_err());
}

#[test]
fn test_get_aead_fails_with_bad_keyset_encoding() {
    tink_aead::init();
    let client = FakeClient::new("fake-kms://bad").unwrap();
    assert!(client.get_aead("fake-kms://badencoding").is_err());
}

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
use tink::registry::KmsClient;
use tink_gcpkms::GcpClient;

#[test]
fn test_new_client_good_uri_prefix_with_gcp_partition() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let client = GcpClient::new(uri_prefix);
    assert!(
        client.is_ok(),
        "error getting new client with good URI prefix"
    );
}

#[test]
fn test_new_client_bad_uri_prefix() {
    let uri_prefix =
    "bad-prefix://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    tink_tests::expect_err(
        GcpClient::new(uri_prefix),
        "uri_prefix must start with gcp-kms",
    );
}

#[test]
fn test_new_client_with_credentials_with_good_credentials() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let cred_ini_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "../testdata", "credential.json"]
        .iter()
        .collect();
    let result = GcpClient::new_with_credentials(uri_prefix, &cred_ini_file);
    assert!(
        result.is_ok(),
        "reject good INI cred file: {:?}",
        result.err()
    );
}

#[test]
fn test_new_client_with_credentials_with_bad_credentials() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let bad_cred_file: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "../testdata",
        "malformed_gcp_credential.json",
    ]
    .iter()
    .collect();

    let result = GcpClient::new_with_credentials(uri_prefix, &bad_cred_file);
    tink_tests::expect_err(result, "failed to decode credentials");
}

#[test]
fn test_new_client_with_credentials_with_empty_credentials() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys/tink-rust-key";
    let bad_cred_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "../testdata", "empty.csv"]
        .iter()
        .collect();

    let result = GcpClient::new_with_credentials(uri_prefix, &bad_cred_file);
    tink_tests::expect_err(result, "failed to decode credential");
}

#[test]
fn test_new_client_with_missing_credentials() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";

    let result = GcpClient::new_with_credentials(uri_prefix, &std::path::PathBuf::from(""));
    tink_tests::expect_err(result, "invalid credential path");
}

#[test]
fn test_supported() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let supported_key_uri =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys/tink-rust-key";
    let non_supported_key_uri =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/different-keyring/cryptoKeys/tink-rust-key";

    let client = GcpClient::new(uri_prefix).unwrap();
    assert!(
        client.supported(supported_key_uri),
        "client with URI prefix {} should support key URI {}",
        uri_prefix,
        supported_key_uri
    );

    assert!(
        !client.supported(non_supported_key_uri),
        "client with URI prefix {} should NOT support key URI {}",
        uri_prefix,
        non_supported_key_uri
    );
}

#[test]
fn test_get_aead_supported_uri() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let supported_key_uri =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys/tink-rust-key";

    let client = GcpClient::new(uri_prefix).unwrap();
    assert!(
        client.get_aead(supported_key_uri).is_ok(),
        "client with URI prefix {} should support key URI {}",
        uri_prefix,
        supported_key_uri
    );
}

#[test]
fn test_get_aead_non_supported_uri() {
    let uri_prefix =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/tink-rust-keyring/cryptoKeys";
    let non_supported_key_uri =
    "gcp-kms://projects/tink-rust-project/locations/global/keyRings/different-keyring/cryptoKeys/tink-rust-key";

    let client = GcpClient::new(uri_prefix).unwrap();
    tink_tests::expect_err(
        client.get_aead(non_supported_key_uri),
        "unsupported key_uri",
    );
}

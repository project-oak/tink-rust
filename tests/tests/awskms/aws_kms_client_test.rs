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

use std::path::PathBuf;
use tink_awskms::AwsClient;
use tink_core::registry::KmsClient;

#[test]
fn test_new_client_good_uri_prefix_with_aws_partition() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    assert!(
        AwsClient::new(uri_prefix).is_ok(),
        "error getting new client with good URI prefix"
    );
}
#[test]
fn test_client_debug() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    let client = AwsClient::new(uri_prefix).unwrap();
    assert_eq!(format!("{:?}", client), "AwsClient { key_uri_prefix: \"aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f\" }");
}

#[test]
fn test_new_client_good_uri_prefix_with_aws_us_gov_partition() {
    let uri_prefix = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    assert!(
        AwsClient::new(uri_prefix).is_ok(),
        "error getting new client with good URI prefix"
    );
}

#[test]
fn test_new_client_good_uri_prefix_with_aws_cn_partition() {
    let uri_prefix =
        "aws-kms://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    assert!(
        AwsClient::new(uri_prefix).is_ok(),
        "error getting new client with good URI prefix"
    );
}

#[test]
fn test_new_client_bad_uri_prefix() {
    let uri_prefix = "bad-prefix://arn:aws-cn:kms:cn-north-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    assert!(
        AwsClient::new(uri_prefix).is_err(),
        "does not reject bad URI prefix: {}",
        uri_prefix
    );
}

#[test]
fn test_new_client_with_credentials_with_good_credentials_csv() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

    let good_csv_cred_file: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "credentials_aws.csv",
    ]
    .iter()
    .collect();
    assert!(
        AwsClient::new_with_credentials(uri_prefix, &good_csv_cred_file).is_ok(),
        "reject good CSV cred file"
    );
}

#[test]
fn test_new_client_with_credentials_with_good_credentials_ini() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    let cred_ini_file: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "credentials_aws.cred",
    ]
    .iter()
    .collect();
    assert!(
        AwsClient::new_with_credentials(uri_prefix, &cred_ini_file).is_ok(),
        "reject good INI cred file"
    );
}

#[test]
fn test_new_client_with_credentials_with_bad_credentials() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    let bad_cred_file: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "testdata",
        "bad_access_keys_aws.csv",
    ]
    .iter()
    .collect();

    let result = AwsClient::new_with_credentials(uri_prefix, &bad_cred_file);
    tink_tests::expect_err(result, "malformed credential");
}

#[test]
fn test_new_client_with_credentials_with_empty_credentials() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    let bad_cred_file: PathBuf = [env!("CARGO_MANIFEST_DIR"), "testdata", "empty.csv"]
        .iter()
        .collect();

    let result = AwsClient::new_with_credentials(uri_prefix, &bad_cred_file);
    tink_tests::expect_err(result, "malformed credential");
}

#[test]
fn test_new_client_with_missing_credentials() {
    let uri_prefix =
        "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

    let result = AwsClient::new_with_credentials(uri_prefix, &std::path::PathBuf::from(""));
    tink_tests::expect_err(result, "invalid credential path");
}

#[test]
fn test_supported() {
    let uri_prefix = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/";
    let supported_key_uri = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
    let non_supported_key_uri = "aws-kms://arn:aws-us-gov:kms:us-gov-east-DOES-NOT-EXIST:key/";

    let client = AwsClient::new(uri_prefix).unwrap();
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
    let uri_prefix = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/";
    let supported_key_uri = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";

    let client = AwsClient::new(uri_prefix).unwrap();
    assert!(
        client.get_aead(supported_key_uri).is_ok(),
        "client with URI prefix {} should support key URI {}",
        uri_prefix,
        supported_key_uri
    );
}

#[test]
fn test_get_aead_non_supported_uri() {
    let uri_prefix = "aws-kms://arn:aws-us-gov:kms:us-gov-east-1:235739564943:key/";
    let non_supported_key_uri = "aws-kms://arn:aws-us-gov:kms:us-gov-east-DOES-NOT-EXIST:key/";

    let client = AwsClient::new(uri_prefix).unwrap();
    tink_tests::expect_err(
        client.get_aead(non_supported_key_uri),
        "must start with prefix",
    );
}

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

//! AWS Cloud KMS client code.

use regex::Regex;
use rusoto_core::region::Region;
use rusoto_credential::AwsCredentials;
use std::str::FromStr;
use tink::{utils::wrap_err, TinkError};

/// Prefix for any AWS-KMS key URIs.
pub const AWS_PREFIX: &str = "aws-kms://";

/// `AwsClient` represents a client that connects to the AWS KMS backend.
pub struct AwsClient {
    key_uri_prefix: String,
    kms: rusoto_kms::KmsClient,
}

impl std::fmt::Debug for AwsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwsClient")
            .field("key_uri_prefix", &self.key_uri_prefix)
            .finish()
    }
}

impl AwsClient {
    /// Return a new AWS KMS client which will use default credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format:
    /// `aws-kms://arn:<partition>:kms:<region>:[:path]`
    /// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    pub fn new(uri_prefix: &str) -> Result<AwsClient, TinkError> {
        let r = get_region(uri_prefix)?;

        let kms = rusoto_kms::KmsClient::new(r);
        Self::new_with_kms(uri_prefix, kms)
    }

    /// Return a new AWS KMS client which will use given credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format:
    /// `aws-kms://arn:<partition>:kms:<region>:[:path]`
    /// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    pub fn new_with_credentials(
        uri_prefix: &str,
        credential_path: &std::path::Path,
    ) -> Result<AwsClient, TinkError> {
        if !credential_path.exists() {
            return Err("invalid credential path".into());
        }
        let region = get_region(uri_prefix)?;
        let request_dispatcher = rusoto_core::request::HttpClient::new()
            .map_err(|e| wrap_err("failed to create AWS HTTP client", e))?;

        let kms = match extract_creds_csv(credential_path) {
            Ok(c) => {
                let creds_provider = rusoto_credential::StaticProvider::from(c);
                rusoto_kms::KmsClient::new_with(request_dispatcher, creds_provider, region)
            }
            Err(CredentialsErr::BadFile) => return Err("cannot open credential path".into()),
            Err(CredentialsErr::CredCsv) => return Err("malformed credential csv file".into()),
            Err(_) => {
                // fallback to load the credential path as .ini shared credentials.
                let creds_provider = rusoto_credential::ProfileProvider::with_configuration(
                    credential_path,
                    "default",
                );
                rusoto_kms::KmsClient::new_with(request_dispatcher, creds_provider, region)
            }
        };
        Self::new_with_kms(uri_prefix, kms)
    }

    /// Return a new AWS KMS client with user created KMS client.  Client is responsible for keeping
    /// the region consistency between key URI and KMS client.  `uri_prefix` must have the
    /// following format: `aws-kms://arn:<partition>:kms:<region>:[:path]`
    /// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    pub fn new_with_kms(
        uri_prefix: &str,
        kms: rusoto_kms::KmsClient,
    ) -> Result<AwsClient, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(AWS_PREFIX) {
            return Err(format!(
                "uri_prefix must start with {}, but got {}",
                AWS_PREFIX, uri_prefix
            )
            .into());
        }

        Ok(AwsClient {
            key_uri_prefix: uri_prefix.to_string(),
            kms,
        })
    }
}

impl tink::registry::KmsClient for AwsClient {
    fn supported(&self, key_uri: &str) -> bool {
        key_uri.starts_with(&self.key_uri_prefix)
    }

    /// Get an AEAD backed by `key_uri`.
    /// `key_uri` must have the following format: `aws-kms://arn:<partition>:kms:<region>:[:path]`.
    /// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    fn get_aead(&self, key_uri: &str) -> Result<Box<dyn tink::Aead>, tink::TinkError> {
        if !self.supported(key_uri) {
            return Err(format!(
                "key_uri must start with prefix {}, but got {}",
                self.key_uri_prefix, key_uri
            )
            .into());
        }

        let uri = if let Some(stripped) = key_uri.strip_prefix(AWS_PREFIX) {
            stripped
        } else {
            key_uri
        };
        Ok(Box::new(crate::AwsAead::new(uri, self.kms.clone())?))
    }
}

enum CredentialsErr {
    BadFile, // File unreadable
    CredCsv, // CSV data not matching AWS credentials layout
    BadCsv,  // CSV data unparseable
    TooFewColumns,
}

fn extract_creds_csv(filename: &std::path::Path) -> Result<AwsCredentials, CredentialsErr> {
    let mut rdr = csv::Reader::from_path(filename).map_err(|_| CredentialsErr::BadFile)?;
    let mut lines = vec![];
    for result in rdr.records() {
        match result {
            Ok(sr) => lines.push(sr),
            Err(_) => return Err(CredentialsErr::BadCsv),
        }
    }

    // It is possible that the file is an AWS .ini credential file, and it can be
    // parsed as 1-column CSV file as well. A real AWS credentials.csv is never 1 column.
    if !lines.is_empty() && lines[0].len() == 1 {
        return Err(CredentialsErr::TooFewColumns);
    }

    // credentials.csv can be obtained when a AWS IAM user is created through IAM console.
    // The first line of the csv file is the "User name,Password,Access key ID,Secret access
    // key,Console login link" header line, which is automatically skipped.
    // The 2nd line of (returned as [0]) contains 5 comma separated values.
    // Parse the file with a strict format assumption as follows:
    // 1. There must be at least 4 columns and 1 row.
    // 2. The access key id and the secret access key must be on (0-based) column 2 and 3.
    if lines.is_empty() {
        return Err(CredentialsErr::CredCsv);
    }
    if lines[0].len() < 4 {
        return Err(CredentialsErr::CredCsv);
    }
    Ok(rusoto_credential::AwsCredentials::new(
        lines[0][2].to_string(),
        lines[0][3].to_string(),
        None,
        None,
    ))
}

fn get_region(key_uri: &str) -> Result<Region, TinkError> {
    // key_uri must have the following format: 'aws-kms://arn:<partition>:kms:<region>:[:path]'.
    // See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
    let re1 = Regex::new(r"aws-kms://arn:(aws[a-zA-Z0-9-_]*):kms:([a-z0-9-]+):")
        .map_err(|e| wrap_err("failed to compile regex", e))?;
    let r = re1
        .captures(key_uri)
        .ok_or_else(|| TinkError::new("extracting region from URI failed"))?;
    if r.len() != 3 {
        return Err("extracting region from URI failed".into());
    }
    Region::from_str(&r[2]).map_err(|e| wrap_err("unknown region", e))
}

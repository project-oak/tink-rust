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

//! GCP Cloud KMS client code.

use tink_core::{utils::wrap_err, TinkError};

/// Prefix for any GCP-KMS key URIs.
pub const GCP_PREFIX: &str = "gcp-kms://";

/// `GcpClient` represents a client that connects to the GCP KMS backend, providing appropriate
/// authorization credentials.
pub struct GcpClient {
    key_uri_prefix: String,
    sa_key: Option<yup_oauth2::ServiceAccountKey>,
}

impl GcpClient {
    /// Return a new GCP KMS client which will use default credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format: `gcp-kms://[:path]`.
    pub fn new(uri_prefix: &str) -> Result<GcpClient, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(GCP_PREFIX) {
            return Err(format!("uri_prefix must start with {GCP_PREFIX}").into());
        }

        Ok(GcpClient {
            key_uri_prefix: uri_prefix.to_string(),
            sa_key: None,
        })
    }

    /// Return a new GCP KMS client which will use given credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format: `gcp-kms://[:path]`.
    pub fn new_with_credentials(
        uri_prefix: &str,
        credential_path: &std::path::Path,
    ) -> Result<GcpClient, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(GCP_PREFIX) {
            return Err(format!("uri_prefix must start with {GCP_PREFIX}").into());
        }
        let credential_path = credential_path.to_string_lossy();
        if credential_path.is_empty() {
            return Err("invalid credential path".into());
        }

        let data = std::fs::read(credential_path.as_ref())
            .map_err(|e| wrap_err("failed to read credentials", e))?;
        let sa_key: yup_oauth2::ServiceAccountKey = serde_json::from_slice(&data)
            .map_err(|e| wrap_err("failed to decode credentials", e))?;

        Ok(GcpClient {
            key_uri_prefix: uri_prefix.to_string(),
            sa_key: Some(sa_key),
        })
    }
}

impl tink_core::registry::KmsClient for GcpClient {
    fn supported(&self, key_uri: &str) -> bool {
        key_uri.starts_with(&self.key_uri_prefix)
    }
    fn get_aead(&self, key_uri: &str) -> Result<Box<dyn tink_core::Aead>, tink_core::TinkError> {
        if !self.supported(key_uri) {
            return Err("unsupported key_uri".into());
        }
        let uri = if let Some(rest) = key_uri.strip_prefix(GCP_PREFIX) {
            rest
        } else {
            key_uri
        };
        Ok(Box::new(crate::GcpAead::new(uri, &self.sa_key)?))
    }
}

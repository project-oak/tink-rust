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

use google_cloudkms1::CloudKMS;
use std::sync::{Arc, Mutex};
use tink::{utils::wrap_err, TinkError};
use yup_oauth2::{
    ApplicationSecret, Authenticator, DefaultAuthenticatorDelegate, MemoryStorage,
    ServiceAccountAccess,
};

/// Prefix for any GCP-KMS key URIs.
pub const GCP_PREFIX: &str = "gcp-kms://";

type DefaultCloudKMS = CloudKMS<
    hyper::Client,
    Authenticator<DefaultAuthenticatorDelegate, MemoryStorage, hyper::Client>,
>;

#[derive(Clone)]
pub enum CloudKmsClient {
    WithDefaultCreds(Arc<Mutex<DefaultCloudKMS>>),
    WithServiceAccount(Arc<Mutex<CloudKMS<hyper::Client, ServiceAccountAccess<hyper::Client>>>>),
}

/// `GcpClient` represents a client that connects to the GCP KMS backend.
pub struct GcpClient {
    key_uri_prefix: String,
    kms: CloudKmsClient,
}

impl GcpClient {
    /// Return a new GCP KMS client which will use default credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format: `gcp-kms://[:path]`.
    pub fn new(uri_prefix: &str) -> Result<GcpClient, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(GCP_PREFIX) {
            return Err(format!("uri_prefix must start with {}", GCP_PREFIX).into());
        }
        let secret = ApplicationSecret::default();
        let client = hyper::Client::with_connector(hyper::net::HttpsConnector::new(
            hyper_rustls::TlsClient::new(),
        ));
        let auth = Authenticator::new(
            &secret,
            DefaultAuthenticatorDelegate,
            client,
            MemoryStorage::default(),
            None,
        );

        let client = hyper::Client::with_connector(hyper::net::HttpsConnector::new(
            hyper_rustls::TlsClient::new(),
        ));
        let mut kms_service = google_cloudkms1::CloudKMS::new(client, auth);
        kms_service.user_agent(format!(
            "Tink-Rust/{}  Rust/{}",
            tink::UPSTREAM_VERSION,
            env!("CARGO_PKG_VERSION")
        ));
        Ok(GcpClient {
            key_uri_prefix: uri_prefix.to_string(),
            kms: CloudKmsClient::WithDefaultCreds(Arc::new(Mutex::new(kms_service))),
        })
    }

    /// Return a new GCP KMS client which will use given credentials to handle keys with
    /// `uri_prefix` prefix. `uri_prefix` must have the following format: `gcp-kms://[:path]`.
    pub fn new_with_credentials(
        uri_prefix: &str,
        credential_path: &std::path::Path,
    ) -> Result<GcpClient, TinkError> {
        if !uri_prefix.to_lowercase().starts_with(GCP_PREFIX) {
            return Err(format!("uri_prefix must start with {}", GCP_PREFIX).into());
        }
        let credential_path = credential_path.to_string_lossy();

        if credential_path.is_empty() {
            return Err("invalid credential path".into());
        }
        let sa_key = yup_oauth2::service_account_key_from_file(&credential_path.to_string())
            .map_err(|e| wrap_err("failed to decode credentials", e))?;
        let client = hyper::Client::with_connector(hyper::net::HttpsConnector::new(
            hyper_rustls::TlsClient::new(),
        ));
        let sa_access = yup_oauth2::ServiceAccountAccess::new(sa_key, client);

        let client = hyper::Client::with_connector(hyper::net::HttpsConnector::new(
            hyper_rustls::TlsClient::new(),
        ));
        let mut kms_service = google_cloudkms1::CloudKMS::new(client, sa_access);
        kms_service.user_agent(format!(
            "Tink-Rust/{}  Rust/{}",
            tink::UPSTREAM_VERSION,
            env!("CARGO_PKG_VERSION")
        ));
        Ok(GcpClient {
            key_uri_prefix: uri_prefix.to_string(),
            kms: CloudKmsClient::WithServiceAccount(Arc::new(Mutex::new(kms_service))),
        })
    }
}

impl tink::registry::KmsClient for GcpClient {
    fn supported(&self, key_uri: &str) -> bool {
        key_uri.starts_with(&self.key_uri_prefix)
    }
    fn get_aead(&self, key_uri: &str) -> Result<Box<dyn tink::Aead>, tink::TinkError> {
        if !self.supported(key_uri) {
            return Err("unsupported key_uri".into());
        }
        let uri = if let Some(rest) = key_uri.strip_prefix(GCP_PREFIX) {
            rest
        } else {
            key_uri
        };
        Ok(Box::new(crate::GcpAead::new(uri, self.kms.clone())))
    }
}

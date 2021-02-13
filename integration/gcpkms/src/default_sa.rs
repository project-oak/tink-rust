// Copyright 2021 The Tink-Rust Authors
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

//! Default authentication when running within GCP
//!
//! Inspired by golang.org/x/oauth2/google and cloud.google.com/go/compute/metadata

use chrono::{DateTime, Utc};
use futures::join;
use lazy_static::lazy_static;
use percent_encoding::percent_encode;
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
    sync::Mutex,
};
use tink_core::{utils::wrap_err, TinkError};
use tokio::time::timeout;

/// Metadata server IP address when running within GCP.
const METADATA_IP_STR: &str = "169.254.169.254";
const METADATA_IP: [u8; 4] = [169, 254, 169, 254];

/// Environment variable specifying the GCE metadata hostname. If the environment variable is empty,
/// the default [`METADATA_IP`] value will be used. Name chosen to match the one used by Go package
/// cloud.google.com/go/compute/metadata.
const METADATA_HOST_ENV: &str = "GCE_METADATA_HOST";

/// User agent to report on requests to GCE metadata server.
const USER_AGENT: &str = "tink-gcpkms/Rust";

lazy_static! {
    /// Cached indication of whether code is running on GCE.
    static ref ON_GCE: Mutex<Option<bool>> = Mutex::new(None);
}

/// Indicate whether code is running on GCE.  First use of this function may be slow; subsequent
/// invocations return cached result.
async fn on_gce() -> bool {
    if let Some(v) = *ON_GCE.lock().unwrap(/* safe: lock */) {
        return v;
    }
    let result = on_gce_test().await;
    *ON_GCE.lock().unwrap() = Some(result); // safe: lock
    result
}

/// Determine whether code is running on GCE.
async fn on_gce_test() -> bool {
    // If `GCE_METADATA_HOST` is set in the environment, assume we're on GCE.
    if let Ok(val) = std::env::var(METADATA_HOST_ENV) {
        if !val.is_empty() {
            return true;
        }
    }

    // Method 1: check header returned by metadata server
    let http_result = async {
        let client = hyper::Client::new();
        let uri = match format!("http://{}", METADATA_IP_STR).parse() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let rsp = match client.get(uri).await {
            Ok(v) => v,
            Err(_) => return false,
        };
        return rsp.headers().get("Metadata-Flavor")
            == Some(&http::HeaderValue::from_static("Google"));
    };
    // Ensure the HTTP request times out in a reasonable period.
    let timed_http_result = async {
        timeout(std::time::Duration::from_secs(2), http_result)
            .await
            .unwrap_or(false)
    };

    // Method 2: check DNS resolution of metadata server name
    let dns_result = async {
        if let Ok(iter) = "metadata.google.internal:80".to_socket_addrs() {
            let needle = SocketAddr::from((METADATA_IP, 80));
            for addr in iter {
                if addr == needle {
                    return true;
                }
            }
        }
        false
    };

    // Run both methods in parallel and combine.
    let results = join!(timed_http_result, dns_result);
    return results.0 || results.1;
}

/// Retrieve a specified piece of metadata from the metadata server.
async fn get_gce_metadata(name: &str) -> Result<String, TinkError> {
    // Allow the metadata server location to be overridden by environment (to allow testing).
    let host = std::env::var(METADATA_HOST_ENV).unwrap_or_else(|_e| METADATA_IP_STR.to_string());
    let authority: http::uri::Authority = host
        .parse()
        .map_err(|e| wrap_err("failed to parse host", e))?;
    let uri = hyper::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(format!("/computeMetadata/v1/{}", name))
        .build()
        .map_err(|e| wrap_err("failed to build Uri", e))?;
    let client = hyper::Client::new();

    let req = hyper::Request::builder()
        .method(http::method::Method::GET)
        .uri(uri)
        .header(http::header::USER_AGENT, USER_AGENT)
        .header("Metadata-Flavor", "Google")
        .body(hyper::Body::empty())
        .map_err(|e| wrap_err("failed to build request", e))?;
    let rsp = client
        .request(req)
        .await
        .map_err(|e| wrap_err("failed to execute request", e))?;
    if rsp.status() != http::StatusCode::OK {
        return Err("failed HTTP request".into());
    }
    let bytes = hyper::body::to_bytes(rsp.into_body())
        .await
        .map_err(|e| wrap_err("failed to retrieve response body", e))?;
    String::from_utf8(bytes.to_vec()).map_err(|e| wrap_err("failed to convert body to string", e))
}

/// Token structure for JSON returned by metadata server
#[derive(Deserialize)]
struct Token {
    pub access_token: String,
    pub expires_in: i64,
    // Also has `token_type: String` which we ignore.
}

/// Local copy of [`yup_oauth2::AccessToken`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
struct AccessTokenClone {
    pub value: String,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct DefaultServiceAccountAuthenticator {
    // Map from scopelist to access tokens.
    // We don't attempt to canonicalize the scopelist (so a,b is different than b,a).
    tokens: RefCell<HashMap<String, yup_oauth2::AccessToken>>,
}

impl DefaultServiceAccountAuthenticator {
    pub async fn new() -> Result<Self, TinkError> {
        if !on_gce().await {
            return Err("not running on GCE".into());
        }
        Ok(Self {
            tokens: RefCell::new(HashMap::new()),
        })
    }

    pub async fn token(&self, scopes: &[&str]) -> Result<yup_oauth2::AccessToken, TinkError> {
        let scopelist = scopes.join(",");

        if let Some(token) = self.tokens.borrow().get(&scopelist) {
            if !token.is_expired() {
                return Ok(token.clone());
            }
        }

        let token = self.refresh_token(&scopelist).await?;

        // Cache the token until expiry time.
        self.tokens
            .borrow_mut()
            .insert(scopelist.to_string(), token.clone());
        Ok(token)
    }
    pub async fn refresh_token(
        &self,
        scopelist: &str,
    ) -> Result<yup_oauth2::AccessToken, TinkError> {
        if !on_gce().await {
            return Err("not running on GCE".into());
        }

        // Retrieve a token from the local metadata server.
        let token_json = get_gce_metadata(&format!(
            "instance/service-accounts/default/token?{}",
            percent_encode(scopelist.as_bytes(), crate::DEFAULT_URL_ENCODE_SET),
        ))
        .await?;

        let token: Token = serde_json::from_str(&token_json)
            .map_err(|e| wrap_err("failed to parse token JSON", e))?;
        if token.access_token.is_empty() || token.expires_in == 0 {
            return Err("invalid token contents".into());
        }
        let token_expiry = Utc::now()
            .checked_add_signed(chrono::Duration::seconds(token.expires_in))
            .ok_or_else(|| TinkError::new("failed to calculate expiry time"))?;

        // The internals of [`yup_oauth2::TokenInfo`] and [`yup_oauth2::AccessToken`] are
        // private, but deserialization is accessible, so round-trip via JSON using a clone
        // of the structure.
        let token_clone = AccessTokenClone {
            value: token.access_token,
            expires_at: Some(token_expiry),
        };
        let token_json = serde_json::to_string(&token_clone)
            .map_err(|e| wrap_err("failed to JSON encode", e))?;
        let token: yup_oauth2::AccessToken = serde_json::from_str(&token_json)
            .map_err(|e| wrap_err("failed to parse internal JSON", e))?;

        Ok(token)
    }
}

impl super::Authenticator for DefaultServiceAccountAuthenticator {
    fn get_token(
        &self,
        runtime: &mut tokio::runtime::Runtime,
        scopes: &[&str],
    ) -> Result<yup_oauth2::AccessToken, TinkError> {
        runtime.block_on(self.token(scopes))
    }
}

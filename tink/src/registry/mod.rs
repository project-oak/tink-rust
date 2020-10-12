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

//! Provides a container that for each supported key type holds a corresponding `KeyManager` object,
//! which can generate new keys or instantiate the primitive corresponding to given key.
//!
//! Registry is initialized at startup, and is later used to instantiate primitives for given keys
//! or keysets. Keeping [`KeyManager`]s for all primitives in a single Registry (rather than having
//! a separate [`KeyManager`] per primitive) enables modular construction of compound primitives
//! from "simple" ones, e.g., AES-CTR-HMAC AEAD encryption uses IND-CPA encryption and a MAC.
//!
//! Note that regular users will usually not work directly with Registry, but rather via primitive
//! factories, which in the background query the Registry for specific [`KeyManager`]s. Registry is
//! public though, to enable configurations with custom primitives and [`KeyManager`]s.

use crate::TinkError;
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

mod kms_client;
pub use kms_client::*;
mod key_manager;
pub use key_manager::*;
mod key_templates;
pub use key_templates::*;

lazy_static! {
    /// Global registry of key manager objects, indexed by type URL.
    static ref KEY_MANAGERS: RwLock<HashMap<&'static str, Arc<dyn KeyManager>>> =
        RwLock::new(HashMap::new());
    /// Global list of KMS client objects.
    static ref KMS_CLIENTS: RwLock<Vec<Arc<dyn KmsClient>>> = RwLock::new(Vec::new());
}

/// Error message for global key manager registry lock.
const MERR: &str = "global KEY_MANAGERS lock poisoned";
/// Error message for global KMS client list lock.
const CERR: &str = "global KMS_CLIENTS lock poisoned";

/// Register the given key manager. Does not allow overwrite of existing key managers.
pub fn register_key_manager<T>(km: Arc<T>) -> Result<(), TinkError>
where
    T: 'static + KeyManager,
{
    let mut key_mgrs = KEY_MANAGERS.write().expect(MERR);

    let type_url = km.type_url();
    if key_mgrs.contains_key(type_url) {
        return Err(format!(
            "registry::register_key_manager: type {} already registered",
            type_url
        )
        .into());
    }
    key_mgrs.insert(type_url, km);
    Ok(())
}

/// Return the key manager for the given `type_url` if it exists.
pub fn get_key_manager(type_url: &str) -> Result<Arc<dyn KeyManager>, TinkError> {
    let key_mgrs = KEY_MANAGERS.read().expect(MERR);
    let km = key_mgrs.get(type_url).ok_or_else(|| {
        TinkError::new(&format!(
            "registry::get_key_manager: unsupported key type: {}",
            type_url
        ))
    })?;
    Ok(km.clone())
}

/// Generate a new [`KeyData`](crate::proto::KeyData) for the given key template.
pub fn new_key_data(kt: &crate::proto::KeyTemplate) -> Result<crate::proto::KeyData, TinkError> {
    get_key_manager(&kt.type_url)?.new_key_data(&kt.value)
}

/// Generate a new key for the given key template as a serialized protobuf message.
pub fn new_key(kt: &crate::proto::KeyTemplate) -> Result<Vec<u8>, TinkError> {
    get_key_manager(&kt.type_url)?.new_key(&kt.value)
}

/// Create a new primitive for the key given in the given [`KeyData`](crate::proto::KeyData).
pub fn primitive_from_key_data(kd: &crate::proto::KeyData) -> Result<crate::Primitive, TinkError> {
    primitive(&kd.type_url, &kd.value)
}

/// Create a new primitive for the given serialized key using the [`KeyManager`]
/// identified by the given `type_url`.
pub fn primitive(type_url: &str, sk: &[u8]) -> Result<crate::Primitive, TinkError> {
    if sk.is_empty() {
        return Err("registry::primitive: invalid serialized key".into());
    }
    get_key_manager(type_url)?.primitive(sk)
}

/// Register a new KMS client
pub fn register_kms_client<T>(k: T)
where
    T: 'static + KmsClient,
{
    let mut kms_clients = KMS_CLIENTS.write().expect(CERR);
    kms_clients.push(Arc::new(k));
}

/// Fetches a [`KmsClient`] by a given URI.
pub fn get_kms_client(key_uri: &str) -> Result<Arc<dyn KmsClient>, TinkError> {
    let kms_clients = KMS_CLIENTS.read().expect(CERR);
    for k in kms_clients.iter() {
        if k.supported(key_uri) {
            return Ok(k.clone());
        }
    }
    Err(format!("KMS client supporting {} not found", key_uri).into())
}

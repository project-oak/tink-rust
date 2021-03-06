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

//! Provides an implementation of PRF using HMAC.

use ::hmac::{Hmac, Mac, NewMac};
use std::{
    cmp::min,
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use tink_core::TinkError;
use tink_proto::HashType;

const MIN_HMAC_KEY_SIZE_IN_BYTES: usize = 16;

/// `HmacPrf` is a type that can be used to compute several HMACs with the same key material.
#[derive(Clone)]
pub struct HmacPrf {
    mac: Arc<Mutex<HmacPrfVariant>>,
    mac_size: usize,
}

enum HmacPrfVariant {
    Sha1(Hmac<sha1::Sha1>),
    Sha224(Hmac<sha2::Sha224>),
    Sha256(Hmac<sha2::Sha256>),
    Sha384(Hmac<sha2::Sha384>),
    Sha512(Hmac<sha2::Sha512>),
}

impl HmacPrf {
    /// Create a new [`HmacPrf`] object and initialize it with the correct key material.
    pub fn new(hash_alg: HashType, key: &[u8]) -> Result<HmacPrf, TinkError> {
        let mac = match hash_alg {
            HashType::Sha1 => HmacPrfVariant::Sha1(
                Hmac::<sha1::Sha1>::new_from_slice(key)
                    .map_err(|_| TinkError::new("HmacPrf: invalid key size"))?,
            ),
            HashType::Sha224 => HmacPrfVariant::Sha224(
                Hmac::<sha2::Sha224>::new_from_slice(key)
                    .map_err(|_| TinkError::new("HmacPrf: invalid key size"))?,
            ),
            HashType::Sha256 => HmacPrfVariant::Sha256(
                Hmac::<sha2::Sha256>::new_from_slice(key)
                    .map_err(|_| TinkError::new("HmacPrf: invalid key size"))?,
            ),
            HashType::Sha384 => HmacPrfVariant::Sha384(
                Hmac::<sha2::Sha384>::new_from_slice(key)
                    .map_err(|_| TinkError::new("HmacPrf: invalid key size"))?,
            ),
            HashType::Sha512 => HmacPrfVariant::Sha512(
                Hmac::<sha2::Sha512>::new_from_slice(key)
                    .map_err(|_| TinkError::new("HmacPrf: invalid key size"))?,
            ),
            h => return Err(format!("HmacPrf: unsupported hash {:?}", h).into()),
        };
        let mac_size = match &mac {
            HmacPrfVariant::Sha1(_) => 20,
            HmacPrfVariant::Sha224(_) => 28,
            HmacPrfVariant::Sha256(_) => 32,
            HmacPrfVariant::Sha384(_) => 48,
            HmacPrfVariant::Sha512(_) => 64,
        };

        Ok(HmacPrf {
            mac: Arc::new(Mutex::new(mac)),
            mac_size,
        })
    }
}

/// Validate parameters of HMAC constructor.
pub fn validate_hmac_prf_params(hash: HashType, key_size: usize) -> Result<(), TinkError> {
    // validate key size
    if key_size < MIN_HMAC_KEY_SIZE_IN_BYTES {
        Err("key too short".into())
    } else if tink_core::subtle::get_hash_func(hash).is_none() {
        Err("invalid hash function".into())
    } else {
        Ok(())
    }
}

impl tink_core::Prf for HmacPrf {
    fn compute_prf(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>, TinkError> {
        if output_length > self.mac_size {
            return Err(format!(
                "HmacPrf: output_length must be between 0 and {}",
                self.mac_size
            )
            .into());
        }
        Ok(
            match self
                .mac
                .lock()
                .expect("internal lock corrupted") // safe: lock
                .deref_mut()
            {
                HmacPrfVariant::Sha1(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                HmacPrfVariant::Sha224(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                HmacPrfVariant::Sha256(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                HmacPrfVariant::Sha384(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                HmacPrfVariant::Sha512(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
            },
        )
    }
}

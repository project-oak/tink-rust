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

//! Provides an implementation of PRF using AES-CMAC.

use aes::{Aes128, Aes192, Aes256};
use cmac::{Cmac, Mac, NewMac};
use std::{
    cmp::min,
    ops::DerefMut,
    sync::{Arc, Mutex},
};
use tink::TinkError;

const RECOMMENDED_KEY_SIZE: usize = 32;
const AES_BLOCK_SIZE_IN_BYTES: usize = 16;

enum AesCmacVariant {
    Aes128(Box<Cmac<Aes128>>),
    Aes192(Box<Cmac<Aes192>>),
    Aes256(Box<Cmac<Aes256>>),
}

/// `AesCmacPrf` is a type that can be used to compute several CMACs with the same key material.
#[derive(Clone)]
pub struct AesCmacPrf {
    mac: Arc<Mutex<AesCmacVariant>>,
}

impl AesCmacPrf {
    /// Create a new `AesCmacPrf` object and initialize it with the correct key material.
    pub fn new(key: &[u8]) -> Result<AesCmacPrf, TinkError> {
        let aes_cmac = match key.len() {
            16 => AesCmacVariant::Aes128(Box::new(
                Cmac::<Aes128>::new_varkey(key)
                    .map_err(|_| TinkError::new("failed to create key"))?,
            )),
            24 => AesCmacVariant::Aes192(Box::new(
                Cmac::<Aes192>::new_varkey(key)
                    .map_err(|_| TinkError::new("failed to create key"))?,
            )),
            32 => AesCmacVariant::Aes256(Box::new(
                Cmac::<Aes256>::new_varkey(key)
                    .map_err(|_| TinkError::new("failed to create key"))?,
            )),
            _ => return Err("AesCmacPrf: invalid key length for AES".into()),
        };
        Ok(AesCmacPrf {
            mac: Arc::new(Mutex::new(aes_cmac)),
        })
    }
}

/// Check that the key is the recommended size for AES-CMAC.
pub fn validate_aes_cmac_prf_params(key_size: usize) -> Result<(), TinkError> {
    if key_size != RECOMMENDED_KEY_SIZE {
        Err(format!(
            "Recommended key size for AES-CMAC is {}, but {} given",
            RECOMMENDED_KEY_SIZE, key_size
        )
        .into())
    } else {
        Ok(())
    }
}

impl tink::Prf for AesCmacPrf {
    /// Compute the AES-CMAC for the given key and data, returning `output_length` bytes.
    /// The timing of this function will only depend on `data.len()`, and not leak any additional
    /// information about the key or the data.
    fn compute_prf(&self, data: &[u8], output_length: usize) -> Result<Vec<u8>, TinkError> {
        if output_length > AES_BLOCK_SIZE_IN_BYTES {
            return Err(format!(
                "AesCmacPrf: output_length must be between 0 and {}",
                AES_BLOCK_SIZE_IN_BYTES
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
                AesCmacVariant::Aes128(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                AesCmacVariant::Aes192(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
                AesCmacVariant::Aes256(mac) => {
                    mac.update(data);
                    let result = mac.finalize_reset().into_bytes();
                    result[..min(result.len(), output_length)].to_vec()
                }
            },
        )
    }
}

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

//! Provides an implementation of MAC using HMAC.

use tink::{proto::HashType, utils::wrap_err, Prf, TinkError};

/// Minimum key size in bytes.
const MIN_KEY_SIZE_IN_BYTES: usize = 16;

/// Minimum tag size in bytes. This provides minimum 80-bit security strength.
const MIN_TAG_SIZE_IN_BYTES: usize = 10;

/// Implementation of trait `tink::Mac`.
#[derive(Clone)]
pub struct Hmac {
    prf: tink_prf::subtle::HmacPrf,
    tag_size: usize,
}

impl Hmac {
    /// Create a new instance of [`Hmac`] with the specified key and tag size.
    pub fn new(hash_alg: HashType, key: &[u8], tag_size: usize) -> Result<Self, TinkError> {
        let key_size = key.len();
        if let Err(e) = validate_hmac_params(hash_alg, key_size, tag_size) {
            return Err(wrap_err("Hmac", e));
        }
        let prf = tink_prf::subtle::HmacPrf::new(hash_alg, key)?;
        Ok(Hmac { prf, tag_size })
    }
}

/// Validate parameters of [`Hmac`] constructor.
pub fn validate_hmac_params(
    hash: HashType,
    key_size: usize,
    tag_size: usize,
) -> Result<(), TinkError> {
    // validate tag size
    let digest_size = tink::subtle::get_hash_digest_size(hash)?;
    if tag_size > digest_size {
        return Err("tag size too big".into());
    }
    if tag_size < MIN_TAG_SIZE_IN_BYTES {
        return Err("tag size too small".into());
    }
    // validate key size
    if key_size < MIN_KEY_SIZE_IN_BYTES {
        return Err("key too short".into());
    }
    Ok(())
}

impl tink::Mac for Hmac {
    fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>, TinkError> {
        self.prf.compute_prf(data, self.tag_size)
    }
}

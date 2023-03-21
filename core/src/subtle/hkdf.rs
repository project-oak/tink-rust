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

//! HKDF functions.

use crate::{utils::wrap_err, TinkError};
use tink_proto::HashType;

/// Minimum tag size in bytes. This provides minimum 80-bit security strength.
const MIN_TAG_SIZE_IN_BYTES: usize = 10;

/// Validate parameters of HKDF constructor.
fn validate_hkdf_params(
    hash: HashType,
    _key_size: usize,
    tag_size: usize,
) -> Result<(), TinkError> {
    // validate tag size
    let digest_size = super::get_hash_digest_size(hash)?;
    if tag_size > 255 * digest_size {
        Err("tag size too big".into())
    } else if tag_size < MIN_TAG_SIZE_IN_BYTES {
        Err("tag size too small".into())
    } else {
        Ok(())
    }
}

/// Extract a pseudorandom key.
pub fn compute_hkdf(
    hash_alg: HashType,
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>, TinkError> {
    let key_size = key.len();
    validate_hkdf_params(hash_alg, key_size, tag_size).map_err(|e| wrap_err("hkdf", e))?;

    let mut okm = vec![0; tag_size];
    match hash_alg {
        HashType::Sha1 => {
            let prk = hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), key);
            prk.expand(info, &mut okm)
                .map_err(|_| "compute of hkdf failed")?;
        }
        HashType::Sha256 => {
            let prk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), key);
            prk.expand(info, &mut okm)
                .map_err(|_| "compute of hkdf failed")?;
        }
        HashType::Sha384 => {
            let prk = hkdf::Hkdf::<sha2::Sha384>::new(Some(salt), key);
            prk.expand(info, &mut okm)
                .map_err(|_| "compute of hkdf failed")?;
        }
        HashType::Sha512 => {
            let prk = hkdf::Hkdf::<sha2::Sha512>::new(Some(salt), key);
            prk.expand(info, &mut okm)
                .map_err(|_| "compute of hkdf failed")?;
        }
        h => return Err(format!("hkdf: unsupported hash {h:?}").into()),
    }
    Ok(okm)
}

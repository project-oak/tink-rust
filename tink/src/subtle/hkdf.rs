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

use crate::{proto::HashType, utils::wrap_err, TinkError};

/// Minimum tag size in bytes. This provides minimum 80-bit security strength.
const MIN_TAG_SIZE_IN_BYTES: usize = 10;

/// Validate parameters of HKDF constructor.
fn validate_hkdf_params(
    hash: HashType,
    _key_size: usize,
    tag_size: usize,
) -> Result<(), crate::TinkError> {
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
) -> Result<Vec<u8>, crate::TinkError> {
    let key_size = key.len();
    validate_hkdf_params(hash_alg, key_size, tag_size).map_err(|e| wrap_err("hkdf", e))?;

    match hash_alg {
        HashType::Sha1 => compute_hkdf_with::<sha1::Sha1>(key, salt, info, tag_size),
        HashType::Sha256 => compute_hkdf_with::<sha2::Sha256>(key, salt, info, tag_size),
        HashType::Sha384 => compute_hkdf_with::<sha2::Sha384>(key, salt, info, tag_size),
        HashType::Sha512 => compute_hkdf_with::<sha2::Sha512>(key, salt, info, tag_size),
        h => Err(format!("hkdf: unsupported hash {:?}", h).into()),
    }
}

/// Extract a pseudorandom key.
fn compute_hkdf_with<D>(
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>, crate::TinkError>
where
    D: digest::Update + digest::BlockInput + digest::FixedOutput + digest::Reset + Default + Clone,
{
    let prk = hkdf::Hkdf::<D>::new(Some(salt), key);
    let mut okm = vec![0; tag_size];
    prk.expand(info, &mut okm)
        .map_err(|_| TinkError::new("compute of hkdf failed"))?;

    Ok(okm)
}

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

//! Provides an implementation of PRF using HKDF.

use tink_core::TinkError;
use tink_proto::HashType;

// We use a somewhat larger minimum key size than usual, because PRFs might be
// used by many users, in which case the security can degrade by a factor
// depending on the number of users. (Discussed for example in
// https://eprint.iacr.org/2012/159)
const MIN_HKDF_KEY_SIZE_IN_BYTES: usize = 32;

/// `HkdfPrf` is a type that can be used to compute several HKDFs with the same key material.
#[derive(Clone)]
pub struct HkdfPrf {
    prk: HkdfPrfVariant,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum HkdfPrfVariant {
    Sha1(hkdf::Hkdf<sha1::Sha1>),
    Sha256(hkdf::Hkdf<sha2::Sha256>),
    Sha512(hkdf::Hkdf<sha2::Sha512>),
}

impl HkdfPrf {
    /// Create a new [`HkdfPrf`] object and initialize it with the correct key material.
    pub fn new(hash_alg: HashType, key: &[u8], salt: &[u8]) -> Result<HkdfPrf, TinkError> {
        let prk = match hash_alg {
            HashType::Sha1 => HkdfPrfVariant::Sha1(hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), key)),
            HashType::Sha256 => {
                HkdfPrfVariant::Sha256(hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), key))
            }
            HashType::Sha512 => {
                HkdfPrfVariant::Sha512(hkdf::Hkdf::<sha2::Sha512>::new(Some(salt), key))
            }
            h => return Err(format!("HkdfPrf: unsupported hash {:?}", h).into()),
        };
        Ok(HkdfPrf { prk })
    }
}

/// Validate parameters of HKDF constructor.
pub fn validate_hkdf_prf_params(
    hash: HashType,
    key_size: usize,
    _salt: &[u8],
) -> Result<(), TinkError> {
    // validate key size
    if key_size < MIN_HKDF_KEY_SIZE_IN_BYTES {
        Err("key too short".into())
    } else if tink_core::subtle::get_hash_func(hash).is_none() {
        Err("invalid hash function".into())
    } else if hash != HashType::Sha256 && hash != HashType::Sha512 {
        Err("Only SHA-256 and SHA-512 currently allowed for HKDF".into())
    } else {
        Ok(())
    }
}

impl tink_core::Prf for HkdfPrf {
    fn compute_prf(&self, data: &[u8], out_len: usize) -> Result<Vec<u8>, TinkError> {
        let mut okm = vec![0; out_len];
        match &self.prk {
            HkdfPrfVariant::Sha1(prk) => prk
                .expand(data, &mut okm)
                .map_err(|_| "HkdfPrf: compute of hkdf failed")?,
            HkdfPrfVariant::Sha256(prk) => prk
                .expand(data, &mut okm)
                .map_err(|_| "HkdfPrf: compute of hkdf failed")?,
            HkdfPrfVariant::Sha512(prk) => prk
                .expand(data, &mut okm)
                .map_err(|_| "HkdfPrf: compute of hkdf failed")?,
        }
        Ok(okm)
    }
}

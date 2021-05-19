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

//! Common methods needed in subtle implementations.

use crate::TinkError;
use digest::Digest;
use subtle::ConstantTimeEq;
use tink_proto::HashType;

mod hkdf;
pub use self::hkdf::*;
pub mod random;

/// Return the digest size of the specified hash algorithm.
pub fn get_hash_digest_size(hash: HashType) -> Result<usize, TinkError> {
    match hash {
        HashType::Sha1 => Ok(20),
        HashType::Sha224 => Ok(28),
        HashType::Sha256 => Ok(32),
        HashType::Sha384 => Ok(48),
        HashType::Sha512 => Ok(64),
        _ => Err("invalid hash algorithm".into()),
    }
}

/// Hash function object.
pub enum HashFunc {
    Sha1(sha1::Sha1),
    Sha224(sha2::Sha224),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

/// Return the corresponding hash function of the given hash.
pub fn get_hash_func(hash: HashType) -> Option<HashFunc> {
    match hash {
        HashType::Sha1 => Some(HashFunc::Sha1(sha1::Sha1::new())),
        HashType::Sha224 => Some(HashFunc::Sha224(sha2::Sha224::new())),
        HashType::Sha256 => Some(HashFunc::Sha256(sha2::Sha256::new())),
        HashType::Sha384 => Some(HashFunc::Sha384(sha2::Sha384::new())),
        HashType::Sha512 => Some(HashFunc::Sha512(sha2::Sha512::new())),
        _ => None,
    }
}

/// Calculate a hash of the given data using the given hash function.
pub fn compute_hash(hash_fn: &mut HashFunc, data: &[u8]) -> Result<Vec<u8>, TinkError> {
    Ok(match hash_fn {
        HashFunc::Sha1(h) => compute_hash_with(h, data),
        HashFunc::Sha224(h) => compute_hash_with(h, data),
        HashFunc::Sha256(h) => compute_hash_with(h, data),
        HashFunc::Sha384(h) => compute_hash_with(h, data),
        HashFunc::Sha512(h) => compute_hash_with(h, data),
    })
}

/// Calculate a hash of the given data with the given hash function.
fn compute_hash_with<T>(hash_func: &mut T, data: &[u8]) -> Vec<u8>
where
    T: digest::Digest,
{
    hash_func.reset();
    hash_func.update(data);
    hash_func.finalize_reset().to_vec()
}

/// Compare two slices in constant time. Return `true` if they are equal, `false` otherwise.
pub fn constant_time_compare(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

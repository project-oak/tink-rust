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

//! Provides constants and convenience methods that define the format of ciphertexts and signatures.

use crate::TinkError;
use tink_proto::OutputPrefixType;

#[cfg(test)]
mod tests;

/// Prefix size of Tink and Legacy key types.
pub const NON_RAW_PREFIX_SIZE: usize = 5;

/// Prefix size of legacy key types.
/// The prefix starts with \x00 and followed by a 4-byte key id.
pub const LEGACY_PREFIX_SIZE: usize = NON_RAW_PREFIX_SIZE;
/// First byte of the prefix of legacy key types.
pub const LEGACY_START_BYTE: u8 = 0;

/// Prefix size of Tink key types.
/// The prefix starts with \x01 and followed by a 4-byte key id.
pub const TINK_PREFIX_SIZE: usize = NON_RAW_PREFIX_SIZE;
/// First byte of the prefix of Tink key types.
pub const TINK_START_BYTE: u8 = 1;

/// Prefix size of Raw key types.
/// Raw prefix is empty.
pub const RAW_PREFIX_SIZE: usize = 0;
/// Empty prefix for Raw key types.
pub const RAW_PREFIX: Vec<u8> = Vec::new();

/// Generate the prefix of ciphertexts produced by the crypto primitive obtained from key.  The
/// prefix can be either empty (for RAW-type prefix), or consists of a 1-byte indicator of the type
/// of the prefix, followed by 4 bytes of the key ID in big endian encoding.
pub fn output_prefix(key: &tink_proto::keyset::Key) -> Result<Vec<u8>, TinkError> {
    match OutputPrefixType::from_i32(key.output_prefix_type) {
        Some(OutputPrefixType::Legacy) | Some(OutputPrefixType::Crunchy) => Ok(
            create_output_prefix(LEGACY_PREFIX_SIZE, LEGACY_START_BYTE, key.key_id),
        ),
        Some(OutputPrefixType::Tink) => Ok(create_output_prefix(
            TINK_PREFIX_SIZE,
            TINK_START_BYTE,
            key.key_id,
        )),
        Some(OutputPrefixType::Raw) => Ok(RAW_PREFIX),
        Some(OutputPrefixType::UnknownPrefix) | None => {
            Err("cryptofmt: unknown output prefix type".into())
        }
    }
}

/// Build a vector of requested size with key ID prefix pre-filled.
fn create_output_prefix(size: usize, start_byte: u8, key_id: crate::KeyId) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(size);
    prefix.push(start_byte);
    prefix.extend_from_slice(&key_id.to_be_bytes());
    prefix
}

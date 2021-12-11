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

use crate::{subtle, subtle::EcPrivateKey};
use tink_core::TinkError;
use tink_proto::{EcPointFormat, HashType};

/// Represents a HKDF-based KEM (key encapsulation mechanism) for ECIES recipient.
pub(crate) struct EciesHkdfRecipientKem<'a> {
    recipient_private_key: &'a EcPrivateKey,
}

impl<'a> EciesHkdfRecipientKem<'a> {
    pub fn new(priv_key: &'a EcPrivateKey) -> Self {
        Self {
            recipient_private_key: priv_key,
        }
    }

    /// Uses the KEM to generate a new HKDF-based key.
    pub(crate) fn decapsulate(
        &self,
        kem: &[u8],
        hash_alg: HashType,
        salt: &[u8],
        info: &[u8],
        key_size: usize,
        point_format: EcPointFormat,
    ) -> Result<Vec<u8>, TinkError> {
        let pub_point = subtle::point_decode(
            self.recipient_private_key.public_key().curve(),
            point_format,
            kem,
        )?;
        let secret = subtle::compute_shared_secret(&pub_point, self.recipient_private_key)?;
        let mut i = kem.to_vec();
        i.extend_from_slice(&secret);

        tink_core::subtle::compute_hkdf(hash_alg, &i, salt, info, key_size)
    }
}

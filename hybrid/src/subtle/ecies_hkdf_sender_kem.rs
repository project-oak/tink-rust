// Copyright 2020-2021 The Tink-Rust Authors
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

use crate::{subtle, subtle::EcPublicKey};
use tink_core::TinkError;
use tink_proto::{EcPointFormat, HashType};

/// Representation of a KEM managed key.
pub struct KemKey {
    pub(crate) kem: Vec<u8>,
    pub(crate) symmetric_key: Vec<u8>,
}

/// Representation of an HKDF-based ECIES-KEM (key encapsulation mechanism) for ECIES sender.
pub(crate) struct EciesHkdfSenderKem<'a> {
    recipient_public_key: &'a EcPublicKey,
}

impl<'a> EciesHkdfSenderKem<'a> {
    pub fn new(pub_key: &'a EcPublicKey) -> Self {
        Self {
            recipient_public_key: pub_key,
        }
    }

    /// Generate a HDKF based KEM.
    pub(crate) fn encapsulate(
        &self,
        hash_alg: HashType,
        salt: &[u8],
        info: &[u8],
        key_size: usize,
        point_format: EcPointFormat,
    ) -> Result<KemKey, TinkError> {
        let pvt = subtle::generate_ecdh_key_pair(self.recipient_public_key.curve())?;
        let pub_key = pvt.public_key();
        let secret = subtle::compute_shared_secret(self.recipient_public_key, &pvt)?;

        let sdata = subtle::point_encode(pub_key.curve(), point_format, &pub_key)?;
        let mut i = sdata.clone();
        i.extend_from_slice(&secret);

        let s_key = tink_core::subtle::compute_hkdf(hash_alg, &i, salt, info, key_size)?;

        Ok(KemKey {
            kem: sdata,
            symmetric_key: s_key,
        })
    }
}

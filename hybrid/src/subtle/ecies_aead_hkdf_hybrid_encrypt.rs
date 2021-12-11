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

use crate::subtle::{EcPublicKey, EciesAeadHkdfDemHelper, EciesHkdfSenderKem};
use tink_core::TinkError;
use tink_proto::{EcPointFormat, HashType};

/// Instance of ECIES encryption with HKDF-KEM (key encapsulation mechanism)
/// and AEAD-DEM (data encapsulation mechanism).
#[derive(Clone)]
pub struct EciesAeadHkdfHybridEncrypt {
    public_key: EcPublicKey,
    hkdf_salt: Vec<u8>,
    hkdf_hmac_algo: HashType,
    point_format: EcPointFormat,
    dem_helper: crate::EciesAeadHkdfDemHelper,
}

impl EciesAeadHkdfHybridEncrypt {
    /// Return an ECIES encryption construct with HKDF-KEM (key encapsulation mechanism)
    /// and AEAD-DEM (data encapsulation mechanism).
    pub fn new(
        public_key: &EcPublicKey,
        hkdf_salt: &[u8],
        hkdf_hmac_algo: HashType,
        point_format: EcPointFormat,
        dem_helper: crate::EciesAeadHkdfDemHelper,
    ) -> Result<EciesAeadHkdfHybridEncrypt, TinkError> {
        Ok(EciesAeadHkdfHybridEncrypt {
            public_key: public_key.clone(),
            hkdf_salt: hkdf_salt.to_vec(),
            hkdf_hmac_algo,
            point_format,
            dem_helper,
        })
    }
}

impl tink_core::HybridEncrypt for EciesAeadHkdfHybridEncrypt {
    /// Encrypt using ECIES with a HKDF-KEM and AEAD-DEM mechanisms.
    fn encrypt(&self, plaintext: &[u8], context_info: &[u8]) -> Result<Vec<u8>, TinkError> {
        let s_kem = EciesHkdfSenderKem::new(&self.public_key);
        let kem_key = s_kem.encapsulate(
            self.hkdf_hmac_algo,
            &self.hkdf_salt,
            context_info,
            self.dem_helper.get_symmetric_key_size(),
            self.point_format,
        )?;
        let prim = self.dem_helper.get_aead_or_daead(&kem_key.symmetric_key)?;
        let ct = match prim {
            tink_core::Primitive::Aead(a) => a.encrypt(plaintext, &[])?,
            tink_core::Primitive::DeterministicAead(a) => {
                a.encrypt_deterministically(plaintext, &[])?
            }
            _ => return Err("Internal error: unexpected primitive type".into()),
        };
        let mut b = kem_key.kem;
        b.extend_from_slice(&ct);
        Ok(b)
    }
}

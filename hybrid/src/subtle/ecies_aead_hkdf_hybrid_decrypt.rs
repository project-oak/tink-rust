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

use crate::subtle::{
    encoding_size_in_bytes, EcPrivateKey, EciesAeadHkdfDemHelper, EciesHkdfRecipientKem,
};
use tink_core::TinkError;
use tink_proto::{EcPointFormat, HashType};

/// An instance of ECIES decryption with HKDF-KEM (key encapsulation mechanism)
/// and AEAD-DEM (data encapsulation mechanism).
#[derive(Clone)]
pub struct EciesAeadHkdfHybridDecrypt {
    private_key: EcPrivateKey,
    hkdf_salt: Vec<u8>,
    hkdf_hmac_algo: HashType,
    point_format: EcPointFormat,
    dem_helper: crate::EciesAeadHkdfDemHelper,
}

impl EciesAeadHkdfHybridDecrypt {
    /// Return an ECIES decryption construct with HKDF-KEM (key encapsulation mechanism)
    /// and AEAD-DEM (data encapsulation mechanism).
    pub fn new(
        private_key: EcPrivateKey,
        hkdf_salt: &[u8],
        hkdf_hmac_algo: HashType,
        point_format: EcPointFormat,
        dem_helper: crate::EciesAeadHkdfDemHelper,
    ) -> Result<EciesAeadHkdfHybridDecrypt, TinkError> {
        Ok(EciesAeadHkdfHybridDecrypt {
            private_key,
            hkdf_salt: hkdf_salt.to_vec(),
            hkdf_hmac_algo,
            point_format,
            dem_helper,
        })
    }
}

impl tink_core::HybridDecrypt for EciesAeadHkdfHybridDecrypt {
    /// Decrypt using ECIES with a HKDF-KEM and AEAD-DEM mechanisms.
    fn decrypt(&self, ciphertext: &[u8], context_info: &[u8]) -> Result<Vec<u8>, TinkError> {
        let curve = self.private_key.public_key().curve();
        let header_size = encoding_size_in_bytes(curve, self.point_format)?;
        if ciphertext.len() < header_size {
            return Err("ciphertext too short".into());
        }
        let kem_bytes = &ciphertext[..header_size].to_vec();
        let ct = &ciphertext[header_size..].to_vec();
        let r_kem = EciesHkdfRecipientKem::new(&self.private_key);
        let symmetric_key = r_kem.decapsulate(
            kem_bytes,
            self.hkdf_hmac_algo,
            &self.hkdf_salt,
            context_info,
            self.dem_helper.get_symmetric_key_size(),
            self.point_format,
        )?;
        let prim = self.dem_helper.get_aead_or_daead(&symmetric_key)?;
        match prim {
            tink_core::Primitive::Aead(a) => a.decrypt(ct, &[]),
            tink_core::Primitive::DeterministicAead(a) => a.decrypt_deterministically(ct, &[]),
            _ => Err("Internal error: unexpected primitive type".into()),
        }
    }
}

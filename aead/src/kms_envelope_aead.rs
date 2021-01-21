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

//! Provide an implementation of AEAD using a KMS.

use std::convert::TryInto;
use tink_core::{utils::wrap_err, TinkError};

const LEN_DEK: usize = 4;

/// `KmsEnvelopeAead` represents an instance of Envelope AEAD.
pub struct KmsEnvelopeAead {
    dek_template: tink_proto::KeyTemplate,
    remote: Box<dyn tink_core::Aead>,
}

/// Manual implementation of [`Clone`] relying on the trait bounds for
/// primitives to provide `.box_clone()` methods.
impl Clone for KmsEnvelopeAead {
    fn clone(&self) -> Self {
        Self {
            dek_template: self.dek_template.clone(),
            remote: self.remote.box_clone(),
        }
    }
}

impl KmsEnvelopeAead {
    pub fn new(kt: tink_proto::KeyTemplate, remote: Box<dyn tink_core::Aead>) -> KmsEnvelopeAead {
        KmsEnvelopeAead {
            dek_template: kt,
            remote,
        }
    }
}

impl tink_core::Aead for KmsEnvelopeAead {
    fn encrypt(&self, pt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // Create a new key for each encryption operation.
        let dek = tink_core::registry::new_key(&self.dek_template)?;
        let encrypted_dek = self.remote.encrypt(&dek, &[])?;

        let primitive = match tink_core::registry::primitive(&self.dek_template.type_url, &dek)? {
            tink_core::Primitive::Aead(p) => p,
            _ => return Err("KmsEnvelopeAead: failed to convert AEAD primitive".into()),
        };
        let payload = primitive.encrypt(pt, aad)?;
        build_cipher_text(&encrypted_dek, &payload)
    }

    fn decrypt(&self, ct: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        // Verify we have enough bytes for the length of the encrypted DEK.
        if ct.len() <= LEN_DEK {
            return Err("KmsEnvelopeAead: invalid ciphertext".into());
        }

        // Extract length of encrypted DEK and advance past that length.
        let ed = u32::from_be_bytes(ct[..LEN_DEK].try_into().unwrap()) as usize; // safe: checked above
        let ct = &ct[LEN_DEK..];

        // Verify we have enough bytes for the encrypted DEK.
        if ed == 0 || ct.len() < ed {
            return Err("KmsEnvelopeAead: invalid ciphertext".into());
        }

        // Extract the encrypted DEK and the payload.
        let encrypted_dek = &ct[..ed];
        let payload = &ct[ed..];

        // Decrypt the DEK.
        let dek = self.remote.decrypt(encrypted_dek, &[])?;

        // Get an AEAD primitive corresponding to the DEK.
        let p = tink_core::registry::primitive(&self.dek_template.type_url, &dek)
            .map_err(|e| wrap_err("KmsEnvelopeAead", e))?;
        let primitive = match p {
            tink_core::Primitive::Aead(p) => p,
            _ => return Err("KmsEnvelopeAead: failed to convert AEAD primitive".into()),
        };

        // Decrypt the payload.
        primitive.decrypt(payload, aad)
    }
}

/// Build the cipher text by appending the length of the DEK, the encrypted DEK, and the encrypted
/// payload.
fn build_cipher_text(encrypted_dek: &[u8], payload: &[u8]) -> Result<Vec<u8>, TinkError> {
    let mut b = Vec::with_capacity(LEN_DEK + encrypted_dek.len() + payload.len());

    // Write the length of the encrypted DEK.
    b.extend_from_slice(&(encrypted_dek.len() as u32).to_be_bytes());
    b.extend_from_slice(encrypted_dek);
    b.extend_from_slice(payload);
    Ok(b)
}

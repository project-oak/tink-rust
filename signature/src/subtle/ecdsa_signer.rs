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

use generic_array::typenum::Unsigned;
use p256::{
    ecdsa::signature::{RandomizedSigner, Signature},
    elliptic_curve,
};
use tink::{utils::wrap_err, TinkError};
use tink_proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType};

// An ECDSA private key.
pub enum EcdsaPrivateKey {
    NistP256(p256::ecdsa::SigningKey),
}

/// Manual implementation of [`Clone`].
impl Clone for EcdsaPrivateKey {
    fn clone(&self) -> Self {
        match self {
            EcdsaPrivateKey::NistP256(k) => {
                EcdsaPrivateKey::NistP256(
                    p256::ecdsa::SigningKey::from_bytes(&k.to_bytes()).unwrap(), /* safe: round-trip */
                )
            }
        }
    }
}

/// `EcdsaSigner` is an implementation of [`tink::Signer`] for ECDSA.
/// At the moment, the implementation only accepts DER encoding.
#[derive(Clone)]
pub struct EcdsaSigner {
    private_key: EcdsaPrivateKey,
    encoding: super::SignatureEncoding,
}

impl EcdsaSigner {
    /// Create a new instance of [`EcdsaSigner`].
    pub fn new(
        hash_alg: HashType,
        curve: EllipticCurveType,
        encoding: EcdsaSignatureEncoding,
        key_value: &[u8],
    ) -> Result<Self, TinkError> {
        let priv_key = match curve {
            EllipticCurveType::NistP256 => {
                if key_value.len()
                    != <p256::NistP256 as elliptic_curve::Curve>::FieldSize::to_usize()
                {
                    return Err("EcdsaSigner: invalid private key len".into());
                }
                EcdsaPrivateKey::NistP256(
                    p256::ecdsa::SigningKey::from_bytes(key_value)
                        .map_err(|e| wrap_err("EcdsaSigner: invalid private key", e))?,
                )
            }
            _ => return Err(format!("EcdsaSigner: unsupported curve {:?}", curve).into()),
        };
        Self::new_from_private_key(hash_alg, curve, encoding, priv_key)
    }

    /// Create a new instance of [`EcdsaSigner`] from a private key.
    pub fn new_from_private_key(
        hash_alg: HashType,
        curve: EllipticCurveType,
        encoding: EcdsaSignatureEncoding,
        private_key: EcdsaPrivateKey,
    ) -> Result<Self, TinkError> {
        let encoding = super::ecdsa_common::validate_ecdsa_params(hash_alg, curve, encoding)
            .map_err(|e| wrap_err("EcdsaSigner", e))?;
        Ok(EcdsaSigner {
            private_key,
            encoding,
        })
    }
}

impl tink::Signer for EcdsaSigner {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, tink::TinkError> {
        let mut csprng = rand::rngs::OsRng {};
        match &self.private_key {
            EcdsaPrivateKey::NistP256(secret_key) => match self.encoding {
                super::SignatureEncoding::Der => {
                    let signature = secret_key.sign_with_rng(&mut csprng, data).to_asn1();
                    Ok(signature.as_bytes().to_vec())
                }
                super::SignatureEncoding::IeeeP1363 => {
                    let signature = secret_key.sign_with_rng(&mut csprng, data);
                    Ok(signature.as_bytes().to_vec())
                }
            },
        }
    }
}

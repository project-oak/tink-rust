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

use elliptic_curve::sec1::EncodedPoint;
use generic_array::typenum::Unsigned;
use p256::ecdsa::{signature::Verifier, Signature};
use signature::Signature as _;
use tink::{
    proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType},
    utils::wrap_err,
    TinkError,
};

/// An ECDSA public key.
#[derive(Clone)]
pub enum EcdsaPublicKey {
    NistP256(p256::ecdsa::VerifyKey),
}

// `EcdsaVerifier` is an implementation of [`tink::Verifier`] for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
#[derive(Clone)]
pub struct EcdsaVerifier {
    public_key: EcdsaPublicKey,
    encoding: EcdsaSignatureEncoding,
}

impl EcdsaVerifier {
    /// Create a new instance of [`EcdsaVerifier`].
    pub fn new(
        hash_alg: HashType,
        curve: EllipticCurveType,
        encoding: EcdsaSignatureEncoding,
        x: &[u8],
        y: &[u8],
    ) -> Result<Self, TinkError> {
        let public_key = match curve {
            EllipticCurveType::NistP256 => {
                let x = element_from_padded_slice::<p256::NistP256>(x)?;
                let y = element_from_padded_slice::<p256::NistP256>(y)?;
                let pt = EncodedPoint::from_affine_coordinates(&x, &y, /* compress= */ false);
                let verify_key = p256::ecdsa::VerifyKey::from_encoded_point(&pt)
                    .map_err(|e| wrap_err("EcdsaVerifier: invalid point", e))?;
                EcdsaPublicKey::NistP256(verify_key)
            }
            _ => return Err(format!("EcdsaVerifier: unsupported curve {:?}", curve,).into()),
        };
        Self::new_from_public_key(hash_alg, curve, encoding, public_key)
    }

    /// Create a new instance of [`EcdsaVerifier`] from a public key.
    pub fn new_from_public_key(
        hash_alg: HashType,
        curve: EllipticCurveType,
        encoding: EcdsaSignatureEncoding,
        public_key: EcdsaPublicKey,
    ) -> Result<Self, TinkError> {
        super::validate_ecdsa_params(hash_alg, curve, encoding)
            .map_err(|e| wrap_err("EcdsaVerifier", e))?;
        Ok(EcdsaVerifier {
            public_key,
            encoding,
        })
    }
}

fn element_from_padded_slice<C: elliptic_curve::Curve>(
    data: &[u8],
) -> Result<elliptic_curve::FieldBytes<C>, TinkError> {
    // TODO: reduce copies here
    let point_len = C::FieldSize::to_usize();
    if data.len() >= point_len {
        let offset = data.len() - point_len;
        for v in data.iter().take(offset) {
            if *v != 0 {
                return Err("EcdsaVerifier: point too large".into());
            }
        }
        Ok(elliptic_curve::FieldBytes::<C>::from_slice(&data[offset..]).clone())
    } else {
        let mut data_copy = vec![0; point_len];
        data_copy[(point_len - data.len())..].copy_from_slice(data);
        Ok(elliptic_curve::FieldBytes::<C>::clone_from_slice(
            &data_copy,
        ))
    }
}

impl tink::Verifier for EcdsaVerifier {
    fn verify(&self, signature: &[u8], data: &[u8]) -> Result<(), tink::TinkError> {
        let signature = match self.encoding {
            EcdsaSignatureEncoding::Der => {
                // The ecdsa::asn1 module panics on too-small inputs, so filter them here.
                // TODO: remove when ecdsa crate includes https://github.com/RustCrypto/signatures/pull/192
                if signature.len() < 6 {
                    return Err("EcdsaVerifier: signature too small".into());
                }
                Signature::from_asn1(signature)
                    .map_err(|e| wrap_err("EcdsaVerifier: invalid ASN.1 signature", e))?
            }
            EcdsaSignatureEncoding::IeeeP1363 => Signature::from_bytes(signature)
                .map_err(|e| wrap_err("EcdsaVerifier: invalid IEEE-P1363 signature", e))?,
            _ => return Err("EcdsaVerifier: unknown encoding".into()),
        };
        match &self.public_key {
            EcdsaPublicKey::NistP256(verify_key) => verify_key
                .verify(&data, &signature)
                .map_err(|e| wrap_err("EcdsaVerifier: invalid signature", e)),
        }
    }
}

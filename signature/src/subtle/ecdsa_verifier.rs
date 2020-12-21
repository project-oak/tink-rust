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
    ecdsa::{signature::Verifier, Signature},
    elliptic_curve,
    elliptic_curve::sec1::EncodedPoint,
};
use signature::Signature as _;
use tink::{utils::wrap_err, TinkError};
use tink_proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType};

/// An ECDSA public key.
#[derive(Clone)]
pub enum EcdsaPublicKey {
    NistP256(p256::ecdsa::VerifyingKey),
}

// `EcdsaVerifier` is an implementation of [`tink::Verifier`] for ECDSA.
// At the moment, the implementation only accepts signatures with strict DER encoding.
#[derive(Clone)]
pub struct EcdsaVerifier {
    public_key: EcdsaPublicKey,
    encoding: super::SignatureEncoding,
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
                let verify_key = p256::ecdsa::VerifyingKey::from_encoded_point(&pt)
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
        let encoding = super::validate_ecdsa_params(hash_alg, curve, encoding)
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
    let point_len = C::FieldSize::to_usize();
    if data.len() >= point_len {
        let offset = data.len() - point_len;
        for v in data.iter().take(offset) {
            // Check that any excess bytes on the left over and above
            // the field size are all zeroes.
            if *v != 0 {
                return Err("EcdsaVerifier: point too large".into());
            }
        }
        Ok(elliptic_curve::FieldBytes::<C>::clone_from_slice(
            &data[offset..],
        ))
    } else {
        // We have been given data that is too short for the field size.
        // Left-pad it with zero bytes up to the field size.
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
            super::SignatureEncoding::Der => Signature::from_asn1(signature)
                .map_err(|e| wrap_err("EcdsaVerifier: invalid ASN.1 signature", e))?,
            super::SignatureEncoding::IeeeP1363 => Signature::from_bytes(signature)
                .map_err(|e| wrap_err("EcdsaVerifier: invalid IEEE-P1363 signature", e))?,
        };
        match &self.public_key {
            EcdsaPublicKey::NistP256(verify_key) => verify_key
                .verify(&data, &signature)
                .map_err(|e| wrap_err("EcdsaVerifier: invalid signature", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_element_from_padded_slice() {
        let testcases = vec![
            (
                "b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                true, // two bytes skipped at start
            ),
            (
                "00b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                true, // one byte skipped, one byte zeroed
            ),
            (
                "0000b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                true, // first two bytes zeroed
            ),
            (
                "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                true, // correct 32-byte field element
            ),
            (
                "00002927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                true, // extra leading zero bytes ('0000')
            ),
            (
                "00012927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
                false, // extra leading non-zero byte ('0001')
            ),
        ];
        for (value, valid) in testcases {
            let x = hex::decode(value).unwrap(); // safe: test
            if valid {
                assert!(super::element_from_padded_slice::<p256::NistP256>(&x).is_ok());
            } else {
                assert!(super::element_from_padded_slice::<p256::NistP256>(&x).is_err());
            }
        }
    }
}

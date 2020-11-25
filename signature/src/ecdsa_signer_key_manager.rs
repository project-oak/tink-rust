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

//! Key manager for ECDSA signing keys.

use generic_array::typenum::Unsigned;
use prost::Message;
use tink::{proto::EllipticCurveType, utils::wrap_err, TinkError};

/// Maximal version of ECDSA keys.
pub const ECDSA_SIGNER_KEY_VERSION: u32 = 0;
/// Type URL of ECDSA keys that Tink supports.
pub const ECDSA_SIGNER_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

/// An implementation of the [`tink::registry::KeyManager`] trait.
/// It generates new ECDSA private keys and produces new instances of
/// [`crate::subtle::EcdsaSigner`].
#[derive(Default)]
pub(crate) struct EcdsaSignerKeyManager {}

/// Prefix for uncompressed elliptic curve points.
pub const ECDSA_UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

impl tink::registry::KeyManager for EcdsaSignerKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("EcdsaSignerKeyManager: invalid key".into());
        }
        let key = tink::proto::EcdsaPrivateKey::decode(serialized_key)
            .map_err(|e| wrap_err("EcdsaSignerKeyManager: invalid key", e))?;
        validate_key(&key)?;
        let params = match &key.public_key {
            Some(pub_key) => match &pub_key.params {
                Some(params) => params,
                None => return Err("EcdsaSignerKeyManager: no public key parameters".into()),
            },
            None => return Err("EcdsaSignerKeyManager: no public key".into()),
        };

        let (hash, curve, encoding) = crate::get_ecdsa_param_ids(&params);
        match crate::subtle::EcdsaSigner::new(hash, curve, encoding, &key.key_value) {
            Ok(p) => Ok(tink::Primitive::Signer(Box::new(p))),
            Err(e) => Err(wrap_err("EcdsaSignerKeyManager: invalid key", e)),
        }
    }

    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("EcdsaSignerKeyManager: invalid key format".into());
        }
        let key_format = tink::proto::EcdsaKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("EcdsaSignerKeyManager: invalid key", e))?;
        validate_key_format(&key_format)?;

        // generate key
        let params = match key_format.params {
            Some(p) => p,
            None => return Err("EcdsaSignerKeyManager: no params".into()),
        };
        let mut csprng = rand::rngs::OsRng {};

        let (secret_key_data, pub_x_data, pub_y_data) =
            match EllipticCurveType::from_i32(params.curve) {
                Some(EllipticCurveType::NistP256) => {
                    // Generate a new keypair.
                    let secret_key = p256::ecdsa::SigningKey::random(&mut csprng);
                    let public_key = p256::ecdsa::VerifyKey::from(&secret_key);
                    let public_key_point = public_key.to_encoded_point(/* compress= */ false);
                    let public_key_data = public_key_point.as_bytes();

                    // Check that the public key data is in the expected uncompressed format:
                    //  - 1 byte uncompressed prefix (0x04)
                    //  - P bytes of X coordinate
                    //  - P bytes of Y coordinate
                    // where P is the field element size.
                    let point_len =
                        <p256::NistP256 as elliptic_curve::Curve>::FieldSize::to_usize();
                    if public_key_data.len() != 2 * point_len + 1
                        || public_key_data[0] != ECDSA_UNCOMPRESSED_POINT_PREFIX
                    {
                        return Err(
                            "EcdsaSignerKeyManager: unexpected public key data format".into()
                        );
                    }
                    (
                        secret_key.to_bytes().to_vec(),
                        public_key_data[1..point_len + 1].to_vec(),
                        public_key_data[point_len + 1..].to_vec(),
                    )
                }
                Some(curve) => {
                    return Err(
                        format!("EcdsaSignerKeyManager: unsupported curve {:?}", curve).into(),
                    )
                }
                None => return Err("EcdsaSignerKeyManager: no curve specified".into()),
            };
        let pub_key = tink::proto::EcdsaPublicKey {
            version: ECDSA_SIGNER_KEY_VERSION,
            params: Some(params),
            x: pub_x_data,
            y: pub_y_data,
        };

        let priv_key = tink::proto::EcdsaPrivateKey {
            version: ECDSA_SIGNER_KEY_VERSION,
            public_key: Some(pub_key),
            key_value: secret_key_data,
        };

        let mut sk = Vec::new();
        priv_key
            .encode(&mut sk)
            .map_err(|e| wrap_err("EcdsaSignerKeyManager: failed to encode new key", e))?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        ECDSA_SIGNER_TYPE_URL
    }

    fn key_material_type(&self) -> tink::proto::key_data::KeyMaterialType {
        tink::proto::key_data::KeyMaterialType::AsymmetricPrivate
    }

    fn supports_private_keys(&self) -> bool {
        true
    }

    fn public_key_data(
        &self,
        serialized_priv_key: &[u8],
    ) -> Result<tink::proto::KeyData, TinkError> {
        let priv_key = tink::proto::EcdsaPrivateKey::decode(serialized_priv_key)
            .map_err(|e| wrap_err("EcdsaSignerKeyManager: invalid private key", e))?;
        let mut serialized_pub_key = Vec::new();
        priv_key
            .public_key
            .ok_or_else(|| TinkError::new("EcdsaSignerKeyManager: no public key"))?
            .encode(&mut serialized_pub_key)
            .map_err(|e| wrap_err("EcdsaSignerKeyManager: invalid public key", e))?;
        Ok(tink::proto::KeyData {
            type_url: crate::ECDSA_VERIFIER_TYPE_URL.to_string(),
            value: serialized_pub_key,
            key_material_type: tink::proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
        })
    }
}

/// Validate the given [`EcdsaPrivateKey`](tink::proto::EcdsaPrivateKey).
fn validate_key(key: &tink::proto::EcdsaPrivateKey) -> Result<(), TinkError> {
    tink::keyset::validate_key_version(key.version, ECDSA_SIGNER_KEY_VERSION)
        .map_err(|e| wrap_err("EcdsaSignerKeyManager", e))?;
    let pub_key = key
        .public_key
        .as_ref()
        .ok_or_else(|| TinkError::new("EcdsaSignerKeyManager: no public key"))?;
    crate::validate_ecdsa_public_key(pub_key).map_err(|e| wrap_err("EcdsaSignerKeyManager", e))?;
    let params = pub_key
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("EcdsaSignerKeyManager: no public key parameters"))?;
    let (hash, curve, encoding) = crate::get_ecdsa_param_ids(&params);
    // Check the public key points are on the curve by creating a verifier.
    crate::subtle::EcdsaVerifier::new(hash, curve, encoding, &pub_key.x, &pub_key.y)
        .map_err(|e| wrap_err("EcdsaVerifierKeyManager: invalid key", e))?;
    crate::subtle::validate_ecdsa_params(hash, curve, encoding)
}

/// Validate the given [`EcdsaKeyFormat`](tink::proto::EcdsaKeyFormat).
fn validate_key_format(key_format: &tink::proto::EcdsaKeyFormat) -> Result<(), TinkError> {
    let params = key_format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("no public key parameters"))?;
    let (hash, curve, encoding) = crate::get_ecdsa_param_ids(&params);
    crate::subtle::validate_ecdsa_params(hash, curve, encoding)
}

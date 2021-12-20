// Copyright 2019-2021 The Tink-Rust Authors
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

//! Key manager for ECIES-AEAD-HKDF public keys.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{
    prost::Message, EcPointFormat, EciesHkdfKemParams, EllipticCurveType, HashType, KeyTemplate,
};

/// Maximal version of ECIES-AEAD-HKDF public keys.
pub const ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION: u32 = 0;
/// Type URL of ECIES-AEAD-HKDF public keys that Tink supports.
pub const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

/// An implementation of the [`tink_core::registry::KeyManager`] trait.
/// It generates new [`tink_proto::EciesAeadHkdfPublicKey`] keys and produces new instances of
/// [`crate::subtle::EciesAeadHkdfHybridEncrypt`].
#[derive(Default)]
pub(crate) struct EciesAeadHkdfPublicKeyKeyManager {}

impl tink_core::registry::KeyManager for EciesAeadHkdfPublicKeyKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("EciesAeadHkdfPublicKeyKeyManager: invalid key".into());
        }
        let key = tink_proto::EciesAeadHkdfPublicKey::decode(serialized_key)
            .map_err(|e| wrap_err("EciesAeadHkdfPublicKeyKeyManager: invalid key", e))?;
        let (pt_format, curve, hash, kem_params, aead_dem) =
            validate_key(&key).map_err(|e| wrap_err("EciesAeadHkdfPublicKeyKeyManager", e))?;

        let pub_key = crate::subtle::EcPublicKey::new(curve, &key.x, &key.y)
            .map_err(|e| wrap_err("EciesAeadHkdfPublicKeyKeyManager", e))?;
        let r_dem = crate::EciesAeadHkdfDemHelper::new(aead_dem)?;
        let salt = &kem_params.hkdf_salt;
        match crate::subtle::EciesAeadHkdfHybridEncrypt::new(&pub_key, salt, hash, pt_format, r_dem)
        {
            Ok(p) => Ok(tink_core::Primitive::HybridEncrypt(Box::new(p))),
            Err(e) => Err(wrap_err("EciesAeadHkdfPublicKeyKeyManager: invalid key", e)),
        }
    }

    fn new_key(&self, _serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        Err("EciesAeadHkdfPublicKeyKeyManager: new_key not implemented".into())
    }

    fn type_url(&self) -> &'static str {
        ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    }
}

/// Validate the given [`tink_proto::EciesAeadHkdfPublicKey`] and return the parameters.
fn validate_key(
    key: &tink_proto::EciesAeadHkdfPublicKey,
) -> Result<
    (
        EcPointFormat,
        EllipticCurveType,
        HashType,
        &EciesHkdfKemParams,
        &KeyTemplate,
    ),
    TinkError,
> {
    tink_core::keyset::validate_key_version(key.version, ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION)?;
    crate::check_ecies_aead_hkdf_params(
        key.params
            .as_ref()
            .ok_or_else(|| TinkError::new("no params"))?,
    )
}

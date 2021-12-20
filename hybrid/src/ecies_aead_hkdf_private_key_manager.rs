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

//! Key manager for ECIES-AEAD-HKDF private keys.

use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{
    prost::Message, EcPointFormat, EciesHkdfKemParams, EllipticCurveType, HashType, KeyTemplate,
};

/// Maximal version of ECIES-AEAD-HKDF private keys.
pub const ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION: u32 = 0;
/// Type URL of ECIES-AEAD-HKDF private keys that Tink supports.
pub const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

/// An implementation of the [`tink_core::registry::KeyManager`] trait.
/// It generates new [`tink_proto::EciesAeadHkdfPrivateKey`] keys and produces new instances of
/// [`crate::subtle::EciesAeadHkdfHybridDecrypt`].
#[derive(Default)]
pub(crate) struct EciesAeadHkdfPrivateKeyKeyManager {}

impl tink_core::registry::KeyManager for EciesAeadHkdfPrivateKeyKeyManager {
    fn primitive(&self, serialized_key: &[u8]) -> Result<tink_core::Primitive, TinkError> {
        if serialized_key.is_empty() {
            return Err("EciesAeadHkdfPrivateKeyKeyManager: invalid key".into());
        }
        let key = tink_proto::EciesAeadHkdfPrivateKey::decode(serialized_key)
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager: invalid key", e))?;
        let (pt_format, curve, hash, kem_params, aead_dem) =
            validate_key(&key).map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager", e))?;

        let pvt = crate::subtle::EcPrivateKey::new(curve, &key.key_value)
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager", e))?;
        let r_dem = crate::EciesAeadHkdfDemHelper::new(aead_dem)?;
        let salt = &kem_params.hkdf_salt;
        match crate::subtle::EciesAeadHkdfHybridDecrypt::new(pvt, salt, hash, pt_format, r_dem) {
            Ok(p) => Ok(tink_core::Primitive::HybridDecrypt(Box::new(p))),
            Err(e) => Err(wrap_err(
                "EciesAeadHkdfPrivateKeyKeyManager: invalid key",
                e,
            )),
        }
    }

    fn new_key(&self, serialized_key_format: &[u8]) -> Result<Vec<u8>, TinkError> {
        if serialized_key_format.is_empty() {
            return Err("EciesAeadHkdfPrivateKeyKeyManager: invalid key format".into());
        }
        let key_format = tink_proto::EciesAeadHkdfKeyFormat::decode(serialized_key_format)
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager: invalid key format", e))?;
        let (_pt_format, curve, _hash, _kem_params, _aead_dem) =
            validate_key_format(&key_format)
                .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager", e))?;
        let pvt = crate::subtle::generate_ecdh_key_pair(curve)?;
        let (x, y) = pvt
            .public_key()
            .x_y_bytes()
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager", e))?;

        let priv_key = tink_proto::EciesAeadHkdfPrivateKey {
            version: ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
            key_value: pvt.d_bytes(),
            public_key: Some(tink_proto::EciesAeadHkdfPublicKey {
                version: ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                params: key_format.params,
                x,
                y,
            }),
        };
        let mut sk = Vec::new();
        priv_key.encode(&mut sk).map_err(|e| {
            wrap_err(
                "EciesAeadHkdfPrivateKeyKeyManager: failed to encode new key",
                e,
            )
        })?;
        Ok(sk)
    }

    fn type_url(&self) -> &'static str {
        ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL
    }

    fn key_material_type(&self) -> tink_proto::key_data::KeyMaterialType {
        tink_proto::key_data::KeyMaterialType::AsymmetricPrivate
    }

    fn supports_private_keys(&self) -> bool {
        true
    }

    fn public_key_data(
        &self,
        serialized_priv_key: &[u8],
    ) -> Result<tink_proto::KeyData, TinkError> {
        let priv_key = tink_proto::EciesAeadHkdfPrivateKey::decode(serialized_priv_key)
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager: invalid private key", e))?;
        let mut serialized_pub_key = Vec::new();
        priv_key
            .public_key
            .ok_or_else(|| TinkError::new("EciesAeadHkdfPrivateKeyKeyManager: no public key"))?
            .encode(&mut serialized_pub_key)
            .map_err(|e| wrap_err("EciesAeadHkdfPrivateKeyKeyManager: invalid public key", e))?;
        Ok(tink_proto::KeyData {
            type_url: crate::ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL.to_string(),
            value: serialized_pub_key,
            key_material_type: tink_proto::key_data::KeyMaterialType::AsymmetricPublic as i32,
        })
    }
}

/// Validate the given [`tink_proto::EciesAeadHkdfPrivateKey`] and return the parameters.
fn validate_key(
    key: &tink_proto::EciesAeadHkdfPrivateKey,
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
    tink_core::keyset::validate_key_version(key.version, ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION)?;
    let pub_key = key
        .public_key
        .as_ref()
        .ok_or_else(|| TinkError::new("no public key"))?;
    tink_core::keyset::validate_key_version(
        pub_key.version,
        crate::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
    )?;
    check_ecies_aead_hkdf_params(
        pub_key
            .params
            .as_ref()
            .ok_or_else(|| TinkError::new("no params"))?,
    )
}

/// Validate the given [`tink_proto::EciesAeadHkdfKeyFormat`] and return the parameters.
fn validate_key_format(
    format: &tink_proto::EciesAeadHkdfKeyFormat,
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
    check_ecies_aead_hkdf_params(
        format
            .params
            .as_ref()
            .ok_or_else(|| TinkError::new("no params"))?,
    )
}

pub(crate) fn check_ecies_aead_hkdf_params(
    params: &tink_proto::EciesAeadHkdfParams,
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
    let kem_params = params
        .kem_params
        .as_ref()
        .ok_or_else(|| TinkError::new("no kem_params"))?;
    let dem_params = params
        .dem_params
        .as_ref()
        .ok_or_else(|| TinkError::new("no dem_params"))?;

    let curve = EllipticCurveType::from_i32(kem_params.curve_type)
        .unwrap_or(EllipticCurveType::UnknownCurve);

    let hkdf_hash = match HashType::from_i32(kem_params.hkdf_hash_type) {
        Some(HashType::UnknownHash) => return Err("unsupported HKDF hash".into()),
        Some(h) => h,
        None => return Err("unknown HKDF hash".into()),
    };
    let ec_point_format = match EcPointFormat::from_i32(params.ec_point_format) {
        Some(EcPointFormat::UnknownFormat) => return Err("unknown EC point format".into()),
        Some(f) => f,
        None => return Err("unknown EC point format".into()),
    };
    let aead_dem = dem_params
        .aead_dem
        .as_ref()
        .ok_or_else(|| TinkError::new("no aead_dem"))?;
    // Check that the relevant data encapsulation mechanism is supported in Tink.
    let km = tink_core::registry::get_key_manager(&aead_dem.type_url)?;
    let _ = km.new_key_data(&aead_dem.value)?;
    Ok((ec_point_format, curve, hkdf_hash, kem_params, aead_dem))
}

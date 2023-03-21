// Copyright 2021 The Tink-Rust Authors
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

use crate::subtle;
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::prost::Message;

const AES_GCM_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmKey";
const AES_CTR_HMAC_AEAD_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";
const AES_SIV_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesSivKey";

/// Generator for [`tink_core::Aead`] or [`tink_core::DeterministicAead`] primitives for the
/// specified [`tink_proto::KeyTemplate`] and key material. in order to implement the
/// [`subtle::EciesAeadHkdfDemHelper`] interface.
#[derive(Clone)]
pub struct EciesAeadHkdfDemHelper {
    /// Protobuf key structure of the relevant type.  Note that the key material held in this key
    /// is not used; it is overwritten on each call to `get_aead_or_daead()`.
    key: AeadKey,
    /// Overall size of key material in bytes.
    symmetric_key_size: usize,
}

/// Supported AEAD/Deterministic-AEAD algorithms.
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug)]
enum AeadKey {
    AesGcm(tink_proto::AesGcmKey),
    AesCtrHmac(usize, tink_proto::AesCtrHmacAeadKey), // Also holds AES-CTR key size.
    AesSiv(tink_proto::AesSivKey),
}

impl AeadKey {
    fn type_url(&self) -> &'static str {
        match self {
            AeadKey::AesGcm(_) => AES_GCM_TYPE_URL,
            AeadKey::AesCtrHmac(_, _) => AES_CTR_HMAC_AEAD_TYPE_URL,
            AeadKey::AesSiv(_) => AES_SIV_TYPE_URL,
        }
    }
}

impl EciesAeadHkdfDemHelper {
    pub fn new(k: &tink_proto::KeyTemplate) -> Result<Self, TinkError> {
        let km = tink_core::registry::get_key_manager(&k.type_url)
            .map_err(|e| wrap_err("failed to fetch KeyManager", e))?;
        let key_data = km
            .new_key(&k.value)
            .map_err(|e| wrap_err("failed to fetch key", e))?;

        let (symmetric_key_size, key) = match k.type_url.as_str() {
            AES_GCM_TYPE_URL => {
                let gcm_key_format = tink_proto::AesGcmKeyFormat::decode(&*k.value)
                    .map_err(|e| wrap_err("failed to decode key format", e))?;
                let gcm_key = tink_proto::AesGcmKey::decode(&*key_data)
                    .map_err(|e| wrap_err("failed to decode key", e))?;
                (gcm_key_format.key_size as usize, AeadKey::AesGcm(gcm_key))
            }
            AES_CTR_HMAC_AEAD_TYPE_URL => {
                let aead_key_format = tink_proto::AesCtrHmacAeadKeyFormat::decode(&*k.value)
                    .map_err(|e| wrap_err("failed to decode key format", e))?;
                let aes_ctr_key_format = aead_key_format
                    .aes_ctr_key_format
                    .ok_or_else(|| TinkError::new("invalid key format"))?;
                let hmac_key_format = aead_key_format
                    .hmac_key_format
                    .ok_or_else(|| TinkError::new("invalid key format"))?;
                let aes_ctr_size = aes_ctr_key_format.key_size;
                let aes_ctr_key = tink_proto::AesCtrHmacAeadKey::decode(&*key_data)
                    .map_err(|e| wrap_err("failed to decode key", e))?;
                (
                    (aes_ctr_size + hmac_key_format.key_size) as usize,
                    AeadKey::AesCtrHmac(aes_ctr_size as usize, aes_ctr_key),
                )
            }
            AES_SIV_TYPE_URL => {
                let daead_key_format = tink_proto::AesSivKeyFormat::decode(&*k.value)
                    .map_err(|e| wrap_err("failed to decode key format", e))?;
                let siv_key = tink_proto::AesSivKey::decode(&*key_data)
                    .map_err(|e| wrap_err("failed to decode", e))?;
                (daead_key_format.key_size as usize, AeadKey::AesSiv(siv_key))
            }
            _ => return Err(format!("unsupported AEAD DEM key type: {}", k.type_url).into()),
        };

        Ok(Self {
            key,
            symmetric_key_size,
        })
    }
}

impl subtle::EciesAeadHkdfDemHelper for EciesAeadHkdfDemHelper {
    fn get_symmetric_key_size(&self) -> usize {
        self.symmetric_key_size
    }

    fn get_aead_or_daead(
        &self,
        symmetric_key_value: &[u8],
    ) -> Result<tink_core::Primitive, tink_core::TinkError> {
        if symmetric_key_value.len() != self.get_symmetric_key_size() {
            return Err("symmetric key has incorrect length".into());
        }
        let mut sk = Vec::new();
        match self.key.clone() {
            AeadKey::AesGcm(mut gcm_key) => {
                gcm_key.key_value = symmetric_key_value.to_vec();
                gcm_key
                    .encode(&mut sk)
                    .map_err(|e| wrap_err("failed to serialize key", e))?;
            }
            AeadKey::AesCtrHmac(aes_ctr_size, mut aes_ctr) => {
                let aes_ctr_key = aes_ctr
                    .aes_ctr_key
                    .as_mut()
                    .ok_or_else(|| TinkError::new("invalid key"))?;
                aes_ctr_key.key_value = symmetric_key_value[..aes_ctr_size].to_vec();

                let mut hmac_key = aes_ctr
                    .hmac_key
                    .as_mut()
                    .ok_or_else(|| TinkError::new("invalid key"))?;
                hmac_key.key_value = symmetric_key_value[aes_ctr_size..].to_vec();
                aes_ctr
                    .encode(&mut sk)
                    .map_err(|e| wrap_err("failed to serialize key", e))?;
            }
            AeadKey::AesSiv(mut siv_key) => {
                siv_key.key_value = symmetric_key_value.to_vec();
                siv_key
                    .encode(&mut sk)
                    .map_err(|e| wrap_err("failed to serialize key", e))?;
            }
        }
        let p = tink_core::registry::primitive(self.key.type_url(), &sk)?;
        match p {
            tink_core::Primitive::Aead(_) | tink_core::Primitive::DeterministicAead(_) => Ok(p),
            _ => Err("Unexpected primitive type returned by the registry for the DEM".into()),
        }
    }
}

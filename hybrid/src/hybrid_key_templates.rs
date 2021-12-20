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

//! This module contains pre-generated `KeyTemplate`s for `HybridEncrypt` keys
/// One can use these templates to generate new Keysets.
use tink_proto::{prost::Message, EcPointFormat, EllipticCurveType, HashType, KeyTemplate};

/// Return a [`KeyTemplate`] that generates an ECDH P-256 and decapsulation key AES128-GCM key with
/// the following parameters:
///  - KEM: ECDH over NIST P-256
///  - DEM: AES128-GCM
///  - KDF: HKDF-HMAC-SHA256 with an empty salt
#[cfg(feature = "aead")]
#[cfg_attr(docsrs, doc(cfg(feature = "aead")))]
pub fn ecies_hkdf_aes128_gcm_key_template() -> KeyTemplate {
    create_ecies_aead_hkdf_key_template(
        EllipticCurveType::NistP256,
        HashType::Sha256,
        EcPointFormat::Uncompressed,
        tink_aead::aes128_gcm_key_template(),
        &[],
    )
}

/// Return a [`KeyTemplate`] that generates an ECDH P-256 and decapsulation key
/// AES128-CTR-HMAC-SHA256 with the following parameters:
///  - KEM: ECDH over NIST P-256
///  - DEM: AES128-CTR-HMAC-SHA256 with the following parameters
///      - AES key size: 16 bytes
///      - AES CTR IV size: 16 bytes
///      - HMAC key size: 32 bytes
///      - HMAC tag size: 16 bytes
///  - KDF: HKDF-HMAC-SHA256 with an empty salt
#[cfg(feature = "aead")]
#[cfg_attr(docsrs, doc(cfg(feature = "aead")))]
pub fn ecies_hkdf_aes128_ctr_hmac_sha256_key_template() -> KeyTemplate {
    create_ecies_aead_hkdf_key_template(
        EllipticCurveType::NistP256,
        HashType::Sha256,
        EcPointFormat::Uncompressed,
        tink_aead::aes128_ctr_hmac_sha256_key_template(),
        &[],
    )
}

/// Create a new ECIES-AEAD-HKDF key template with the given key size in bytes.
fn create_ecies_aead_hkdf_key_template(
    ct: EllipticCurveType,
    ht: HashType,
    ptfmt: EcPointFormat,
    dek_t: KeyTemplate,
    salt: &[u8],
) -> KeyTemplate {
    let format = tink_proto::EciesAeadHkdfKeyFormat {
        params: Some(tink_proto::EciesAeadHkdfParams {
            kem_params: Some(tink_proto::EciesHkdfKemParams {
                curve_type: ct as i32,
                hkdf_hash_type: ht as i32,
                hkdf_salt: salt.to_vec(),
            }),
            dem_params: Some(tink_proto::EciesAeadDemParams {
                aead_dem: Some(dek_t),
            }),
            ec_point_format: ptfmt as i32,
        }),
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
    }
}

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

//! This module contains pre-generated [`KeyTemplate`] instances for PRF.

use prost::Message;
use tink::proto::KeyTemplate;

/// Return a [`KeyTemplate`] that generates an HMAC key with the following parameters:
///  - Key size: 32 bytes
///  - Hash function: SHA256
pub fn hmac_sha256_prf_key_template() -> KeyTemplate {
    create_hmac_prf_key_template(32, tink::proto::HashType::Sha256)
}

/// Return a [`KeyTemplate`] that generates an HMAC key with the following parameters:
///  - Key size: 64 bytes
///  - Hash function: SHA512
pub fn hmac_sha512_prf_key_template() -> KeyTemplate {
    create_hmac_prf_key_template(64, tink::proto::HashType::Sha512)
}

/// Return a [`KeyTemplate`] that generates an HKDF key with the following parameters:
///  - Key size: 32 bytes
///  - Salt: empty
///  - Hash function: SHA256
pub fn hkdf_sha256_prf_key_template() -> KeyTemplate {
    create_hkdf_prf_key_template(32, tink::proto::HashType::Sha256, &[])
}

/// Return a [`KeyTemplate`] that generates an AES-CMAC key with the following parameters:
///  - Key size: 32 bytes
pub fn aes_cmac_prf_key_template() -> KeyTemplate {
    create_aes_cmac_prf_key_template(32)
}

/// Create a new [`KeyTemplate`] for HMAC using the given parameters.
fn create_hmac_prf_key_template(key_size: u32, hash_type: tink::proto::HashType) -> KeyTemplate {
    let params = tink::proto::HmacPrfParams {
        hash: hash_type as i32,
    };
    let format = tink::proto::HmacPrfKeyFormat {
        params: Some(params),
        key_size,
        version: super::HMAC_PRF_KEY_VERSION,
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap();
    KeyTemplate {
        type_url: super::HMAC_PRF_TYPE_URL.to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
        value: serialized_format,
    }
}

/// Creates a new [`KeyTemplate`] for HKDF using the given parameters.
fn create_hkdf_prf_key_template(
    key_size: u32,
    hash_type: tink::proto::HashType,
    salt: &[u8],
) -> KeyTemplate {
    let params = tink::proto::HkdfPrfParams {
        hash: hash_type as i32,
        salt: salt.to_vec(),
    };
    let format = tink::proto::HkdfPrfKeyFormat {
        params: Some(params),
        key_size,
        version: super::HKDF_PRF_KEY_VERSION,
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap();
    KeyTemplate {
        type_url: super::HKDF_PRF_TYPE_URL.to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
        value: serialized_format,
    }
}

// Create a new [`KeyTemplate`] for AES-CMAC using the given parameters.
fn create_aes_cmac_prf_key_template(key_size: u32) -> KeyTemplate {
    let format = tink::proto::AesCmacPrfKeyFormat {
        key_size,
        version: super::AES_CMAC_PRF_KEY_VERSION,
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap();
    KeyTemplate {
        type_url: super::AES_CMAC_PRF_TYPE_URL.to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
        value: serialized_format,
    }
}

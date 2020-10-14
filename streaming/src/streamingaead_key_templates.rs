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

//! This module contains pre-generated [`KeyTemplate`]s for streaming AEAD keys. One can use these
//! templates to generate new Keysets.

use prost::Message;
use tink::proto::{HashType, KeyTemplate, OutputPrefixType};

/// Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:
///   - Main key size: 16 bytes
///   - HKDF algo: HMAC-SHA256
///   - Size of AES-GCM derived keys: 16 bytes
///   - Ciphertext segment size: 4096 bytes
pub fn aes128_gcm_hkdf_4kb_key_template() -> KeyTemplate {
    new_aes_gcm_hkdf_key_template(16, HashType::Sha256, 16, 4096)
}

/// Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:
///   - Main key size: 16 bytes
///   - HKDF algo: HMAC-SHA256
///   - Size of AES-GCM derived keys: 16 bytes
///   - Ciphertext segment size: 1048576 bytes (1 MB)
pub fn aes128_gcm_hkdf_1mb_key_template() -> KeyTemplate {
    new_aes_gcm_hkdf_key_template(16, HashType::Sha256, 16, 1048576)
}

/// Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:
///   - Main key size: 32 bytes
///   - HKDF algo: HMAC-SHA256
///   - Size of AES-GCM derived keys: 32 bytes
///   - Ciphertext segment size: 4096 bytes
pub fn aes256_gcm_hkdf_4kb_key_template() -> KeyTemplate {
    new_aes_gcm_hkdf_key_template(32, HashType::Sha256, 32, 4096)
}

/// Return a [`KeyTemplate`] that generates an AES-GCM key with the following parameters:
///   - Main key size: 32 bytes
///   - HKDF algo: HMAC-SHA256
///   - Size of AES-GCM derived keys: 32 bytes
///   - Ciphertext segment size: 1048576 bytes (1 MB)
pub fn aes256_gcm_hkdf_1mb_key_template() -> KeyTemplate {
    new_aes_gcm_hkdf_key_template(32, HashType::Sha256, 32, 1048576)
}

/// Return a [`KeyTemplate`] that generates an AES-CTR-HMAC key with the following parameters:
///   - Main key size: 16 bytes
///   - HKDF algorthim: HMAC-SHA256
///   - AES-CTR derived key size: 16 bytes
///   - Tag algorithm: HMAC-SHA256
///   - Tag size: 32 bytes
///   - Ciphertext segment size: 4096 bytes (4 KB)
pub fn aes128_ctr_hmac_sha256_segment_4kb_key_template() -> KeyTemplate {
    new_aes_ctr_hmac_key_template(16, HashType::Sha256, 16, HashType::Sha256, 32, 4096)
}

/// Return a [`KeyTemplate`] that generates an AES-CTR-HMAC key with the following parameters:
///   - Main key size: 16 bytes
///   - HKDF algorthim: HMAC-SHA256
///   - AES-CTR derived key size: 16 bytes
///   - Tag algorithm: HMAC-SHA256
///   - Tag size: 32 bytes
///   - Ciphertext segment size: 1048576 bytes (1 MB)
pub fn aes128_ctr_hmac_sha256_segment_1mb_key_template() -> KeyTemplate {
    new_aes_ctr_hmac_key_template(16, HashType::Sha256, 16, HashType::Sha256, 32, 1048576)
}

/// Return a [`KeyTemplate`] that generates an AES-CTR-HMAC key with the following parameters:
///   - Main key size: 32 bytes
///   - HKDF algorthim: HMAC-SHA256
///   - AES-CTR derived key size: 32 bytes
///   - Tag algorithm: HMAC-SHA256
///   - Tag size: 32 bytes
///   - Ciphertext segment size: 4096 bytes (4 KB)
pub fn aes256_ctr_hmac_sha256_segment_4kb_key_template() -> KeyTemplate {
    new_aes_ctr_hmac_key_template(32, HashType::Sha256, 32, HashType::Sha256, 32, 4096)
}

/// Return a [`KeyTemplate`] that generates an AES-CTR-HMAC key with the following parameters:
///   - Main key size: 32 bytes
///   - HKDF algorthim: HMAC-SHA256
///   - AES-CTR derived key size: 32 bytes
///   - Tag algorithm: HMAC-SHA256
///   - Tag size: 32 bytes
///   - Ciphertext segment size: 1048576 bytes (1 MB)
pub fn aes256_ctr_hmac_sha256_segment_1mb_key_template() -> KeyTemplate {
    new_aes_ctr_hmac_key_template(32, HashType::Sha256, 32, HashType::Sha256, 32, 1048576)
}

/// Create a [`KeyTemplate`] containing a [`tink::proto::AesGcmHkdfStreamingKeyFormat`] with
/// specified parameters.
fn new_aes_gcm_hkdf_key_template(
    main_key_size: u32,
    hkdf_hash_type: HashType,
    derived_key_size: u32,
    ciphertext_segment_size: u32,
) -> KeyTemplate {
    let format = tink::proto::AesGcmHkdfStreamingKeyFormat {
        version: crate::AES_GCM_HKDF_KEY_VERSION,
        key_size: main_key_size,
        params: Some(tink::proto::AesGcmHkdfStreamingParams {
            ciphertext_segment_size,
            derived_key_size,
            hkdf_hash_type: hkdf_hash_type as i32,
        }),
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::AES_GCM_HKDF_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: OutputPrefixType::Raw as i32,
    }
}

/// Create a KeyTemplate containing a [`tink::proto::AesCtrHmacStreamingKeyFormat`] with the
/// specified parameters.
fn new_aes_ctr_hmac_key_template(
    main_key_size: u32,
    hkdf_hash_type: HashType,
    derived_key_size: u32,
    tag_alg: HashType,
    tag_size: u32,
    ciphertext_segment_size: u32,
) -> KeyTemplate {
    let format = tink::proto::AesCtrHmacStreamingKeyFormat {
        version: crate::AES_CTR_HMAC_KEY_VERSION,
        key_size: main_key_size,
        params: Some(tink::proto::AesCtrHmacStreamingParams {
            ciphertext_segment_size,
            derived_key_size,
            hkdf_hash_type: hkdf_hash_type as i32,
            hmac_params: Some(tink::proto::HmacParams {
                hash: tag_alg as i32,
                tag_size,
            }),
        }),
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::AES_CTR_HMAC_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: OutputPrefixType::Raw as i32,
    }
}

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

//! Constant definitions.

// AEAD

/// Maximal version of AES-CTR-HMAC-AEAD keys that Tink supports.
pub const AES_CTR_HMAC_AEAD_KEY_VERSION: u32 = 0;
/// Type URL of AES-CTR-HMAC-AEAD keys that Tink supports.
pub const AES_CTR_HMAC_AEAD_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

/// Maximal version of AES-GCM keys.
pub const AES_GCM_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM keys that Tink supports.
pub const AES_GCM_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmKey";

/// Maximal version of AES-GCM-SIV keys.
pub const AES_GCM_SIV_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM-SIV keys that Tink supports.
pub const AES_GCM_SIV_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesGcmSivKey";

/// Maximal version of ChaCha20Poly1305 keys that Tink supports.
pub const CHA_CHA20_POLY1305_KEY_VERSION: u32 = 0;
/// Type URL of ChaCha20Poly1305 keys.
pub const CHA_CHA20_POLY1305_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key";

/// Maximal version of KMSEnvelopeAEAD keys that Tink supports.
pub const KMS_ENVELOPE_AEAD_KEY_VERSION: u32 = 0;
/// Type URL of KMSEnvelopeAEAD keys.
pub const KMS_ENVELOPE_AEAD_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey";

/// Maximal version of XChaCha20Poly1305 keys that Tink supports.
pub const X_CHA_CHA20_POLY1305_KEY_VERSION: u32 = 0;
/// Type URL of XChaCha20Poly1305 keys.
pub const X_CHA_CHA20_POLY1305_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key";

/// Maximal version of keys that this key manager supports.
pub const ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION: u32 = 0;

/// Type URL that this key manager supports.
pub const ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

/// Maximal version of keys that this key manager supports.
pub const ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION: u32 = 0;

/// Type url that this key manager supports.
pub const ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

// DeterministicAEAD

/// Maximal version of AES-SIV keys that Tink supports.
pub const AES_SIV_KEY_VERSION: u32 = 0;
/// Type URL of AES-SIV keys.
pub const AES_SIV_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesSivKey";

// MAC

/// Maximal version of HMAC keys that Tink supports.
pub const HMAC_KEY_VERSION: u32 = 0;
/// Type URL of HMAC keys.
pub const HMAC_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HmacKey";
/// Maximal version of HMAC keys that Tink supports.
pub const AES_CMAC_KEY_VERSION: u32 = 0;
/// Type URL of AES-CMAC keys.
pub const AES_CMAC_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesCmacKey";

// PRF Set

/// Maximal version of AES CMAC PRF keys that Tink supports.
pub const AES_CMAC_PRF_KEY_VERSION: u32 = 0;
/// Type URL of AES CMAC PRF keys.
pub const AES_CMAC_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.AesCmacPrfKey";

/// Maximal version of HKDF PRF keys that Tink supports.
pub const HKDF_PRF_KEY_VERSION: u32 = 0;
/// Type URL of HKDF PRF keys.
pub const HKDF_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HkdfPrfKey";

/// Maximal version of HMAC PRF keys that Tink supports.
pub const HMAC_PRF_KEY_VERSION: u32 = 0;
/// Type URL of HMAC PRF keys.
pub const HMAC_PRF_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.HmacPrfKey";

// Digital signatures

/// Maximum version of ECDSA private keys that Tink supports.
pub const ECDSA_SIGNER_KEY_VERSION: u32 = 0;
/// Type URL of ECDSA private keys.
pub const ECDSA_SIGNER_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";

/// Maximum version of ECDSA public keys that Tink supports.
pub const ECDSA_VERIFIER_KEY_VERSION: u32 = 0;
/// Type URL of ECDSA public keys.
pub const ECDSA_VERIFIER_TYPE_URL: &str = "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";

/// Maximum version of ED25519 private keys that Tink supports.
pub const ED25519_SIGNER_KEY_VERSION: u32 = 0;
/// Type URL of ED25519 private keys.
pub const ED25519_SIGNER_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.Ed25519PrivateKey";

/// Maximum version of ED25519 public keys that Tink supports.
pub const ED25519_VERIFIER_KEY_VERSION: u32 = 0;
/// Type URL of ED25519 public keys.
pub const ED25519_VERIFIER_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";

// Streaming AEAD

/// Maximum version of AES-GCM-HKDF keys that Tink supports.
pub const AES_GCM_HKDF_KEY_VERSION: u32 = 0;
/// Type URL of AES-GCM-HKDF keys that Tink supports.
pub const AES_GCM_HKDF_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey";

/// Maximum version of AES-CTR-HMAC keys that Tink supports.
pub const AES_CTR_HMAC_KEY_VERSION: u32 = 0;
/// Type URL of AES-CTR-HMAC keys that Tink supports.
pub const AES_CTR_HMAC_TYPE_URL: &str =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey";

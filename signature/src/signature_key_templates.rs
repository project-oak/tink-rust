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

//! This module contains pre-generated KeyTemplates for Signer and Verifier.
/// One can use these templates to generate new Keysets.
use tink_proto::{prost::Message, KeyTemplate};

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: DER
///   - Output prefix type: TINK
///
/// Note that this template uses a different encoding than ESDSA_P256_RAW in Tinkey / `rinkey`.
pub fn ecdsa_p256_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha256,
        tink_proto::EllipticCurveType::NistP256,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: IEEE_P1363
///   - Output prefix type: TINK
pub fn ecdsa_p256_key_p1363_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha256,
        tink_proto::EllipticCurveType::NistP256,
        tink_proto::EcdsaSignatureEncoding::IeeeP1363,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: IEEE_P1363
///   - Output prefix type: RAW
pub fn ecdsa_p256_raw_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha256,
        tink_proto::EllipticCurveType::NistP256,
        tink_proto::EcdsaSignatureEncoding::IeeeP1363,
        tink_proto::OutputPrefixType::Raw,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following
/// parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: DER
///   - Output prefix type: RAW
pub fn ecdsa_p256_key_without_prefix_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha256,
        tink_proto::EllipticCurveType::NistP256,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Raw,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-384
///   - Signature encoding: DER
///   - Output prefix type: TINK
#[deprecated(
    since = "0.2.3",
    note = "Use `ecdsa_p384_sha384_key_template()` or `ecdsa_p384_sha512_key_template()` instead."
)]
pub fn ecdsa_p384_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha512,
        tink_proto::EllipticCurveType::NistP384,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA384
///   - Curve: NIST P-384
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p384_sha384_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha384,
        tink_proto::EllipticCurveType::NistP384,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-384
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p384_sha512_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha512,
        tink_proto::EllipticCurveType::NistP384,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following
/// parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-384
///   - Signature encoding: DER
///   - Output prefix type: RAW
pub fn ecdsa_p384_key_without_prefix_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha512,
        tink_proto::EllipticCurveType::NistP384,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Raw,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-521
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p521_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha512,
        tink_proto::EllipticCurveType::NistP521,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following
/// parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-521
///   - Signature encoding: DER
///   - Output prefix type: RAW
pub fn ecdsa_p521_key_without_prefix_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink_proto::HashType::Sha512,
        tink_proto::EllipticCurveType::NistP521,
        tink_proto::EcdsaSignatureEncoding::Der,
        tink_proto::OutputPrefixType::Raw,
    )
}

// createECDSAKeyTemplate creates a KeyTemplate containing a EcdasKeyFormat
// with the given parameters.
fn create_ecdsa_key_template(
    hash_type: tink_proto::HashType,
    curve: tink_proto::EllipticCurveType,
    encoding: tink_proto::EcdsaSignatureEncoding,
    prefix_type: tink_proto::OutputPrefixType,
) -> KeyTemplate {
    let params = tink_proto::EcdsaParams {
        hash_type: hash_type as i32,
        curve: curve as i32,
        encoding: encoding as i32,
    };
    let format = tink_proto::EcdsaKeyFormat {
        params: Some(params),
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap(); // safe: proto-encode
    KeyTemplate {
        type_url: crate::ECDSA_SIGNER_TYPE_URL.to_string(),
        value: serialized_format,
        output_prefix_type: prefix_type as i32,
    }
}

/// Return a [`KeyTemplate`] that generates a new ED25519 private key.
pub fn ed25519_key_template() -> KeyTemplate {
    KeyTemplate {
        type_url: crate::ED25519_SIGNER_TYPE_URL.to_string(),
        output_prefix_type: tink_proto::OutputPrefixType::Tink as i32,
        value: vec![],
    }
}

/// Return a [`KeyTemplate`] that generates a new ED25519 private key.
pub fn ed25519_key_without_prefix_template() -> KeyTemplate {
    KeyTemplate {
        type_url: crate::ED25519_SIGNER_TYPE_URL.to_string(),
        output_prefix_type: tink_proto::OutputPrefixType::Raw as i32,
        value: vec![],
    }
}

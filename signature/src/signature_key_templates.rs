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
use prost::Message;
use tink::proto::KeyTemplate;

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p256_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink::proto::HashType::Sha256,
        tink::proto::EllipticCurveType::NistP256,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Tink,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA256
///   - Curve: NIST P-256
///   - Signature encoding: IEEE_P1363
///   - Output prefix type: TINK
pub fn ecdsa_p256_key_p1363_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink::proto::HashType::Sha256,
        tink::proto::EllipticCurveType::NistP256,
        tink::proto::EcdsaSignatureEncoding::IeeeP1363,
        tink::proto::OutputPrefixType::Tink,
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
        tink::proto::HashType::Sha256,
        tink::proto::EllipticCurveType::NistP256,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Raw,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-384
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p384_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP384,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Tink,
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
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP384,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Raw,
    )
}

/// Return a [`KeyTemplate`] that generates a new ECDSA private key with the following parameters:
///   - Hash function: SHA512
///   - Curve: NIST P-521
///   - Signature encoding: DER
///   - Output prefix type: TINK
pub fn ecdsa_p521_key_template() -> KeyTemplate {
    create_ecdsa_key_template(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP521,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Tink,
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
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP521,
        tink::proto::EcdsaSignatureEncoding::Der,
        tink::proto::OutputPrefixType::Raw,
    )
}

// createECDSAKeyTemplate creates a KeyTemplate containing a EcdasKeyFormat
// with the given parameters.
fn create_ecdsa_key_template(
    hash_type: tink::proto::HashType,
    curve: tink::proto::EllipticCurveType,
    encoding: tink::proto::EcdsaSignatureEncoding,
    prefix_type: tink::proto::OutputPrefixType,
) -> KeyTemplate {
    let params = tink::proto::EcdsaParams {
        hash_type: hash_type as i32,
        curve: curve as i32,
        encoding: encoding as i32,
    };
    let format = tink::proto::EcdsaKeyFormat {
        params: Some(params),
    };
    let mut serialized_format = Vec::new();
    format.encode(&mut serialized_format).unwrap();
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
        output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
        value: vec![],
    }
}

/// Return a [`KeyTemplate`] that generates a new ED25519 private key.
pub fn ed25519_key_without_prefix_template() -> KeyTemplate {
    KeyTemplate {
        type_url: crate::ED25519_SIGNER_TYPE_URL.to_string(),
        output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
        value: vec![],
    }
}

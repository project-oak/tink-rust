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

use prost::Message;
use tink::TinkError;

#[test]
fn test_ecdsa_key_templates() {
    struct FlagTest {
        tc_name: &'static str,
        type_url: &'static str,
        sig_template: tink_proto::KeyTemplate,
        curve_type: tink_proto::EllipticCurveType,
        hash_type: tink_proto::HashType,
        sig_encoding: tink_proto::EcdsaSignatureEncoding,
        prefix_type: tink_proto::OutputPrefixType,
    };
    let flag_tests = vec![
        FlagTest {
            tc_name: "P-256 with SHA256, DER format and TINK output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p256_key_template(),
            curve_type: tink_proto::EllipticCurveType::NistP256,
            hash_type: tink_proto::HashType::Sha256,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Tink,
        },
        FlagTest {
            tc_name: "P-384 with SHA512, DER format and TINK output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p384_key_template(),
            curve_type: tink_proto::EllipticCurveType::NistP384,
            hash_type: tink_proto::HashType::Sha512,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Tink,
        },
        FlagTest {
            tc_name: "P-521 with SHA512, DER format and TINK output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p521_key_template(),
            curve_type: tink_proto::EllipticCurveType::NistP521,
            hash_type: tink_proto::HashType::Sha512,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Tink,
        },
        FlagTest {
            tc_name: "P-256 with SHA256, DER format and RAW output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p256_key_without_prefix_template(),
            curve_type: tink_proto::EllipticCurveType::NistP256,
            hash_type: tink_proto::HashType::Sha256,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Raw,
        },
        FlagTest {
            tc_name: "P-384 with SHA512, DER format and RAW output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p384_key_without_prefix_template(),
            curve_type: tink_proto::EllipticCurveType::NistP384,
            hash_type: tink_proto::HashType::Sha512,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Raw,
        },
        FlagTest {
            tc_name: "P-521 with SHA512, DER format and RAW output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p521_key_without_prefix_template(),
            curve_type: tink_proto::EllipticCurveType::NistP521,
            hash_type: tink_proto::HashType::Sha512,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::Der,
            prefix_type: tink_proto::OutputPrefixType::Raw,
        },
        FlagTest {
            tc_name: "P-256 with SHA256, P1363 format and TINK output prefix",
            type_url: tink_testutil::ECDSA_SIGNER_TYPE_URL,
            sig_template: tink_signature::ecdsa_p256_key_p1363_template(),
            curve_type: tink_proto::EllipticCurveType::NistP256,
            hash_type: tink_proto::HashType::Sha256,
            sig_encoding: tink_proto::EcdsaSignatureEncoding::IeeeP1363,
            prefix_type: tink_proto::OutputPrefixType::Tink,
        },
    ];

    for tt in flag_tests {
        let tc_name = tt.tc_name;
        check_ecdsa_key_template(
            &tt.sig_template,
            tt.type_url,
            tt.hash_type,
            tt.curve_type,
            tt.sig_encoding,
            tt.prefix_type,
        )
        .unwrap_or_else(|e| panic!("failed {}: {}", tc_name, e));
    }
}

#[test]
fn test_ed25519_key_templates() {
    struct FlagTest {
        tc_name: &'static str,
        type_url: &'static str,
        sig_template: tink_proto::KeyTemplate,
        prefix_type: tink_proto::OutputPrefixType,
    };
    let flag_tests = vec![
        FlagTest {
            tc_name: "ED25519 with TINK output prefix",
            type_url: tink_testutil::ED25519_SIGNER_TYPE_URL,
            sig_template: tink_signature::ed25519_key_template(),
            prefix_type: tink_proto::OutputPrefixType::Tink,
        },
        FlagTest {
            tc_name: "ED25519 with RAW output prefix",
            type_url: tink_testutil::ED25519_SIGNER_TYPE_URL,
            sig_template: tink_signature::ed25519_key_without_prefix_template(),
            prefix_type: tink_proto::OutputPrefixType::Raw,
        },
    ];

    for tt in flag_tests {
        let tc_name = tt.tc_name;
        check_key_type_and_output_prefix(&tt.sig_template, tt.type_url, tt.prefix_type)
            .unwrap_or_else(|e| panic!("failed {}: {}", tc_name, e));
    }
}

fn check_ecdsa_key_template(
    template: &tink_proto::KeyTemplate,
    type_url: &str,
    hash_type: tink_proto::HashType,
    curve: tink_proto::EllipticCurveType,
    encoding: tink_proto::EcdsaSignatureEncoding,
    prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    check_key_type_and_output_prefix(template, type_url, prefix_type)?;

    let format = tink_proto::EcdsaKeyFormat::decode(template.value.as_ref())
        .map_err(|_| TinkError::new("cannot unmarshal key format"))?;

    let params = format
        .params
        .ok_or_else(|| TinkError::new("missing parameters"))?;
    if params.hash_type != hash_type as i32 {
        return Err(format!(
            "incorrect hash type: expect {:?}, got {}",
            hash_type, params.hash_type
        )
        .into());
    }

    if params.curve != curve as i32 {
        return Err(format!("incorrect curve: expect {:?}, got {}", curve, params.curve).into());
    }

    if params.encoding != encoding as i32 {
        return Err(format!(
            "incorrect encoding: expect {:?}, got {}",
            encoding, params.encoding
        )
        .into());
    }

    Ok(())
}

fn check_key_type_and_output_prefix(
    template: &tink_proto::KeyTemplate,
    type_url: &str,
    prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    if template.type_url != type_url {
        return Err(format!(
            "incorrect typeurl: expect {}, got {}",
            type_url, template.type_url
        )
        .into());
    }

    if template.output_prefix_type != prefix_type as i32 {
        return Err(format!(
            "incorrect outputPrefixType: expect: {:?}, got {}",
            prefix_type, template.output_prefix_type
        )
        .into());
    }

    Ok(())
}

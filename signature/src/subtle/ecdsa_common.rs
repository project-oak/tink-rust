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

use tink::TinkError;
use tink_proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType};

/// Supported signature encodings.  This is a precise subset of the protobuf enum,
/// allowing exact `match`es.
#[derive(Clone, Debug)]
pub enum SignatureEncoding {
    Der,
    IeeeP1363,
}

/// Validate ECDSA parameters.
/// The hash's strength must not be weaker than the curve's strength.
/// Only DER encoding is supported now.
pub fn validate_ecdsa_params(
    hash_alg: tink_proto::HashType,
    curve: tink_proto::EllipticCurveType,
    encoding: tink_proto::EcdsaSignatureEncoding,
) -> Result<SignatureEncoding, TinkError> {
    let encoding = match encoding {
        EcdsaSignatureEncoding::IeeeP1363 => SignatureEncoding::IeeeP1363,
        EcdsaSignatureEncoding::Der => SignatureEncoding::Der,
        _ => return Err("ecdsa: unsupported encoding".into()),
    };
    match curve {
        EllipticCurveType::NistP256 => {
            if hash_alg != HashType::Sha256 {
                return Err("invalid hash type, expect SHA-256".into());
            }
        }
        EllipticCurveType::NistP384 => {
            if hash_alg != HashType::Sha384 && hash_alg != HashType::Sha512 {
                return Err("invalid hash type, expect SHA-384 or SHA-512".into());
            }
        }
        EllipticCurveType::NistP521 => {
            if hash_alg != HashType::Sha512 {
                return Err("invalid hash type, expect SHA-512".into());
            }
        }
        _ => return Err(format!("unsupported curve: {:?}", curve).into()),
    }
    Ok(encoding)
}

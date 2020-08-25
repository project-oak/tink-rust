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

use tink::{
    proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType},
    TinkError,
};

/// Validate ECDSA parameters.
/// The hash's strength must not be weaker than the curve's strength.
/// Only DER encoding is supported now.
pub fn validate_ecdsa_params(
    hash_alg: tink::proto::HashType,
    curve: tink::proto::EllipticCurveType,
    encoding: tink::proto::EcdsaSignatureEncoding,
) -> Result<(), TinkError> {
    match encoding {
        EcdsaSignatureEncoding::IeeeP1363 | EcdsaSignatureEncoding::Der => {}
        _ => return Err("ecdsa: unsupported encoding".into()),
    }
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
    Ok(())
}

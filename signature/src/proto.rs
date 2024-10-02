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

//! Utilities for dealing with protobuf types for signing.

use std::convert::TryFrom;
use tink_proto::{EcdsaParams, EcdsaSignatureEncoding, EllipticCurveType, HashType};

/// Return the enum values of each parameter in
/// the given [`EcdsaParams`](tink_proto::EcdsaParams).
pub(crate) fn get_ecdsa_param_ids(
    params: &EcdsaParams,
) -> (HashType, EllipticCurveType, EcdsaSignatureEncoding) {
    (
        HashType::try_from(params.hash_type).unwrap_or(HashType::UnknownHash),
        EllipticCurveType::try_from(params.curve).unwrap_or(EllipticCurveType::UnknownCurve),
        EcdsaSignatureEncoding::try_from(params.encoding)
            .unwrap_or(EcdsaSignatureEncoding::UnknownEncoding),
    )
}

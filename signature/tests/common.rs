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

use tink::proto::{EllipticCurveType, HashType};

pub struct EcdsaParams {
    pub hash_type: HashType,
    pub curve: EllipticCurveType,
}

pub fn gen_valid_ecdsa_params() -> Vec<EcdsaParams> {
    vec![
        EcdsaParams {
            hash_type: HashType::Sha256,
            curve: EllipticCurveType::NistP256,
        },
        /* TODO(#16): more ECDSA curves
        EcdsaParams {
            hash_type: HashType::Sha384,
            curve: EllipticCurveType::NistP384,
        },
        EcdsaParams {
            hash_type: HashType::Sha512,
            curve: EllipticCurveType::NistP384,
        },
        EcdsaParams {
            hash_type: HashType::Sha512,
            curve: EllipticCurveType::NistP521,
        },
        */
    ]
}

pub fn gen_invalid_ecdsa_params() -> Vec<EcdsaParams> {
    vec![
        EcdsaParams {
            hash_type: HashType::Sha1,
            curve: EllipticCurveType::NistP256,
        },
        /* TODO(#16): more ECDSA curves
        EcdsaParams {
            hash_type: HashType::Sha1,
            curve: EllipticCurveType::NistP384,
        },
        EcdsaParams {
            hash_type: HashType::Sha1,
            curve: EllipticCurveType::NistP521,
        },
        EcdsaParams {
            hash_type: HashType::Sha256,
            curve: EllipticCurveType::NistP384,
        },
        EcdsaParams {
            hash_type: HashType::Sha256,
            curve: EllipticCurveType::NistP521,
        },
        */
        EcdsaParams {
            hash_type: HashType::Sha512,
            curve: EllipticCurveType::NistP256,
        },
    ]
}

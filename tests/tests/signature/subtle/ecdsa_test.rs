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

use tink_proto::{EcdsaSignatureEncoding, EllipticCurveType, HashType};

struct ParamsTestEcdsa {
    hash: HashType,
    curve: EllipticCurveType,
    encoding: EcdsaSignatureEncoding,
}

#[test]
fn test_ecdsa_validate_params() {
    let params = gen_ecdsa_valid_params();
    for (i, param) in params.iter().enumerate() {
        assert!(
            tink_signature::subtle::validate_ecdsa_params(param.hash, param.curve, param.encoding)
                .is_ok(),
            "unexpected error for valid params: i = {}",
            i
        );
    }
    let params = gen_ecdsa_invalid_params();
    for (i, param) in params.iter().enumerate() {
        assert!(
            tink_signature::subtle::validate_ecdsa_params(param.hash, param.curve, param.encoding)
                .is_err(),
            "expect an error when params are invalid, i = {}",
            i
        );
    }
}

fn gen_ecdsa_invalid_params() -> Vec<ParamsTestEcdsa> {
    let encodings = vec![
        EcdsaSignatureEncoding::Der,
        EcdsaSignatureEncoding::IeeeP1363,
    ];
    let mut test_cases = vec![
        // invalid encoding
        ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::NistP256,
            encoding: EcdsaSignatureEncoding::UnknownEncoding,
        },
    ];
    for encoding in encodings {
        // invalid curve
        test_cases.push(ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::UnknownCurve,
            encoding,
        });
        // invalid hash: P256 and SHA-512
        test_cases.push(ParamsTestEcdsa {
            hash: HashType::Sha512,
            curve: EllipticCurveType::NistP256,
            encoding,
        });
        // invalid hash: P521 and SHA-256
        test_cases.push(ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::NistP521,
            encoding,
        });
        // invalid hash: P384 and SHA-256
        test_cases.push(ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::NistP384,
            encoding,
        });
    }
    test_cases
}

fn gen_ecdsa_valid_params() -> Vec<ParamsTestEcdsa> {
    vec![
        ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::NistP256,
            encoding: EcdsaSignatureEncoding::Der,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha256,
            curve: EllipticCurveType::NistP256,
            encoding: EcdsaSignatureEncoding::IeeeP1363,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha384,
            curve: EllipticCurveType::NistP384,
            encoding: EcdsaSignatureEncoding::Der,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha384,
            curve: EllipticCurveType::NistP384,
            encoding: EcdsaSignatureEncoding::IeeeP1363,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha512,
            curve: EllipticCurveType::NistP384,
            encoding: EcdsaSignatureEncoding::Der,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha512,
            curve: EllipticCurveType::NistP384,
            encoding: EcdsaSignatureEncoding::IeeeP1363,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha512,
            curve: EllipticCurveType::NistP521,
            encoding: EcdsaSignatureEncoding::Der,
        },
        ParamsTestEcdsa {
            hash: HashType::Sha512,
            curve: EllipticCurveType::NistP521,
            encoding: EcdsaSignatureEncoding::IeeeP1363,
        },
    ]
}

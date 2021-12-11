// Copyright 2019-2021 The Tink-Rust Authors
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

use tink_core::{subtle::random::get_random_bytes, HybridDecrypt, HybridEncrypt};
use tink_proto::{EcPointFormat, EllipticCurveType, HashType};

fn basic_multiple_encrypts(curve: EllipticCurveType, k: tink_proto::KeyTemplate) {
    let pvt =
        tink_hybrid::subtle::generate_ecdh_key_pair(curve).expect("error generating ECDH key pair");
    let salt = b"some salt";
    let pt = get_random_bytes(20);
    let context = b"context info";
    let r_dem =
        tink_hybrid::EciesAeadHkdfDemHelper::new(&k).expect("error generating a DEM helper");
    let e = tink_hybrid::subtle::EciesAeadHkdfHybridEncrypt::new(
        &pvt.public_key(),
        salt,
        HashType::Sha256,
        EcPointFormat::Uncompressed,
        r_dem.clone(),
    )
    .expect("error generating an encryption construct");
    let d = tink_hybrid::subtle::EciesAeadHkdfHybridDecrypt::new(
        pvt,
        salt,
        HashType::Sha256,
        EcPointFormat::Uncompressed,
        r_dem,
    )
    .expect("error generating an decryption construct");
    let mut cl = Vec::new();
    for _i in 0..8 {
        let ct = e.encrypt(&pt, context).expect("encryption error");
        for c in &cl {
            assert_ne!(&ct, c, "encryption is not randomized");
        }
        cl.push(ct.clone());
        let dt = d.decrypt(&ct, context).expect("decryption error");
        assert_eq!(dt, pt, "decryption not inverse of encryption");
    }
    assert_eq!(cl.len(), 8, "randomized encryption check failed");
}

#[test]
fn test_ec_aes_ctr_hmac_sha256_encrypt() {
    tink_hybrid::init();
    basic_multiple_encrypts(
        EllipticCurveType::NistP256,
        tink_aead::aes256_ctr_hmac_sha256_key_template(),
    );
    /* TODO(#16): support more curves
        basic_multiple_encrypts(
            EllipticCurveType::NistP384,
            tink_aead::aes256_ctr_hmac_sha256_key_template(),
        );
        basic_multiple_encrypts(
            EllipticCurveType::NistP521,
            tink_aead::aes256_ctr_hmac_sha256_key_template(),
        );
    */
    /* TODO(#16): support more curves (P-224 is not in protobuf enum)
        basic_multiple_encrypts(
            EllipticCurveType::NistP224,
            tink_aead::aes256_ctr_hmac_sha256_key_template(),
        );
    */

    basic_multiple_encrypts(
        EllipticCurveType::NistP256,
        tink_aead::aes128_ctr_hmac_sha256_key_template(),
    );
    /* TODO(#16): support more curves
        basic_multiple_encrypts(
            EllipticCurveType::NistP384,
            tink_aead::aes128_ctr_hmac_sha256_key_template(),
        );
        basic_multiple_encrypts(
            EllipticCurveType::NistP521,
            tink_aead::aes128_ctr_hmac_sha256_key_template(),
        );
    */
    /* TODO(#16): support more curves (P-224 is not in protobuf enum)
        basic_multiple_encrypts(
            EllipticCurveType::NistP224,
            tink_aead::aes128_ctr_hmac_sha256_key_template(),
        );
    */
}

#[test]
fn test_ec_aes256_gcm_encrypt() {
    tink_hybrid::init();
    basic_multiple_encrypts(
        EllipticCurveType::NistP256,
        tink_aead::aes256_gcm_key_template(),
    );
    /* TODO(#16): support more curves
        basic_multiple_encrypts(
            EllipticCurveType::NistP384,
            tink_aead::aes256_gcm_key_template(),
        );
        basic_multiple_encrypts(
            EllipticCurveType::NistP521,
            tink_aead::aes256_gcm_key_template(),
        );
    */
    /* TODO(#16): support more curves (P-224 is not in protobuf enum)
        basic_multiple_encrypts(
            EllipticCurveType::NistP224,
            tink_aead::aes256_gcm_key_template(),
        );
    */

    basic_multiple_encrypts(
        EllipticCurveType::NistP256,
        tink_aead::aes128_gcm_key_template(),
    );
    /* TODO(#16): support more curves
        basic_multiple_encrypts(
            EllipticCurveType::NistP384,
            tink_aead::aes128_gcm_key_template(),
        );
        basic_multiple_encrypts(
            EllipticCurveType::NistP521,
            tink_aead::aes128_gcm_key_template(),
        );
    */
    /* TODO(#16): support more curves (P-224 is not in protobuf enum)
        basic_multiple_encrypts(
            EllipticCurveType::NistP224,
            tink_aead::aes128_gcm_key_template(),
        );
    */
}

#[test]
fn test_ec_aes_siv_encrypt() {
    tink_hybrid::init();
    basic_multiple_encrypts(
        EllipticCurveType::NistP256,
        tink_daead::aes_siv_key_template(),
    );
    /* TODO(#16): support more curves
    basic_multiple_encrypts(
        EllipticCurveType::NistP384,
        tink_daead::aes_siv_key_template(),
    );
    basic_multiple_encrypts(
        EllipticCurveType::NistP521,
        tink_daead::aes_siv_key_template(),
    );
    */
    /* TODO(#16): support more curves (P-224 is not in protobuf enum)
        basic_multiple_encrypts(
            EllipticCurveType::NistP224,
            tink_daead::aes_siv_key_template(),
        );
    */
}

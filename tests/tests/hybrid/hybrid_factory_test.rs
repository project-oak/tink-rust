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

use tink_core::subtle::random::get_random_bytes;
use tink_tests::proto_encode;

#[test]
fn test_hybrid_factory_test() {
    tink_hybrid::init();
    let c = tink_proto::EllipticCurveType::NistP256;
    let ht = tink_proto::HashType::Sha256;
    let primary_pt_fmt = tink_proto::EcPointFormat::Uncompressed;
    let raw_pt_fmt = tink_proto::EcPointFormat::Compressed;
    let primary_dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let raw_dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let primary_salt = b"some salt";
    let raw_salt = b"other salt";

    let primary_priv_proto = tink_tests::generate_ecies_aead_hkdf_private_key(
        c,
        ht,
        primary_pt_fmt,
        primary_dek,
        primary_salt,
    )
    .unwrap();
    let s_primary_priv = proto_encode(&primary_priv_proto);

    let primary_priv_key = tink_tests::new_key(
        &tink_tests::new_key_data(
            tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL,
            &s_primary_priv,
            tink_proto::key_data::KeyMaterialType::AsymmetricPrivate,
        ),
        tink_proto::KeyStatusType::Enabled,
        8,
        tink_proto::OutputPrefixType::Raw,
    );

    let raw_priv_proto =
        tink_tests::generate_ecies_aead_hkdf_private_key(c, ht, raw_pt_fmt, raw_dek, raw_salt)
            .unwrap();
    let s_raw_priv = proto_encode(&raw_priv_proto);
    let raw_priv_key = tink_tests::new_key(
        &tink_tests::new_key_data(
            tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL,
            &s_raw_priv,
            tink_proto::key_data::KeyMaterialType::AsymmetricPrivate,
        ),
        tink_proto::KeyStatusType::Enabled,
        11,
        tink_proto::OutputPrefixType::Raw,
    );

    let priv_keys = vec![primary_priv_key, raw_priv_key];
    let priv_keyset = tink_tests::new_keyset(priv_keys[0].key_id, priv_keys);
    let kh_priv = tink_core::keyset::insecure::new_handle(priv_keyset).unwrap();

    let kh_pub = kh_priv.public().unwrap();

    let e = tink_hybrid::new_encrypt(&kh_pub).unwrap();
    let d = tink_hybrid::new_decrypt(&kh_priv).unwrap();

    for _i in 0..200 {
        let pt = get_random_bytes(20);
        let ci = get_random_bytes(20);
        let ct = e.encrypt(&pt, &ci).unwrap();
        let gotpt = d.decrypt(&ct, &ci).unwrap();
        assert_eq!(pt, gotpt);
    }
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_hybrid::init();
    tink_signature::init();
    let wrong_kh =
        tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    tink_tests::expect_err(
        tink_hybrid::new_encrypt(&wrong_kh),
        "not a HybridEncrypt primitive",
    );
    tink_tests::expect_err(
        tink_hybrid::new_decrypt(&wrong_kh),
        "not a HybridDecrypt primitive",
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_hybrid::init();
    let good_kh =
        tink_core::keyset::Handle::new(&tink_hybrid::ecies_hkdf_aes128_gcm_key_template()).unwrap();
    let good_public_kh = good_kh.public().unwrap();

    let result = tink_hybrid::new_encrypt(&good_public_kh);
    assert!(result.is_ok(), "new_encrypt() failed: {:?}", result.err());

    let result = tink_hybrid::new_decrypt(&good_kh);
    assert!(result.is_ok(), "new_decrypt() failed: {:?}", result.err());
}

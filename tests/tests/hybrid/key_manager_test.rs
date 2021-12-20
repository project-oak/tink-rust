// Copyright 2021 The Tink-Rust Authors
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

use tink_proto::{
    AesGcmKeyFormat, EcPointFormat, EciesAeadDemParams, EciesAeadHkdfKeyFormat,
    EciesAeadHkdfParams, EciesAeadHkdfPrivateKey, EciesAeadHkdfPublicKey, EciesHkdfKemParams,
    EllipticCurveType, HashType, KeyTemplate, OutputPrefixType,
};

#[test]
fn test_private_key_manager_params() {
    tink_hybrid::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL)
        .unwrap();

    assert_eq!(
        km.type_url(),
        tink_tests::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL
    );
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::AsymmetricPrivate
    );
    assert!(km.supports_private_keys());
    tink_tests::expect_err(km.primitive(&[]), "invalid key");
}

#[test]
fn test_public_key_manager_params() {
    tink_hybrid::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL)
        .unwrap();

    assert_eq!(
        km.type_url(),
        tink_tests::ECIES_AEAD_HKDF_PUBLIC_KEY_TYPE_URL
    );
    assert_eq!(
        km.key_material_type(),
        tink_proto::key_data::KeyMaterialType::AsymmetricPublic
    );
    assert!(!km.supports_private_keys());

    tink_tests::expect_err(km.new_key(&[]), "not implemented");
    tink_tests::expect_err(km.primitive(&[]), "invalid key");
}

#[test]
fn test_new_key_with_invalid_format() {
    tink_hybrid::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL)
        .unwrap();

    let invalid_formats = vec![
        (
            "unknown HKDF hash",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: 9999, //invalid
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "unsupported curve",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: 9999, // invalid
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "unsupported curve",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP521 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "unknown EC point format",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: 9999, //invalid
                }),
            },
        ),
        (
            "invalid key format",
            EciesAeadHkdfKeyFormat { params: None },
        ),
        (
            "no kem_params",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: None,
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "no dem_params",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: None,
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "no aead_dem",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams { aead_dem: None }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        (
            "invalid key format",
            EciesAeadHkdfKeyFormat {
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: vec![],
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
            },
        ),
        /* All based on this valid key format:
        EciesAeadHkdfKeyFormat {
            params: Some(EciesAeadHkdfParams {
                kem_params: Some(EciesHkdfKemParams {
                    curve_type: EllipticCurveType::NistP256 as i32,
                    hkdf_hash_type: HashType::Sha256 as i32,
                    hkdf_salt: vec![1, 2, 3],
                }),
                dem_params: Some(EciesAeadDemParams {
                    aead_dem: Some(KeyTemplate {
                        type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                        value: tink_tests::proto_encode(&AesGcmKeyFormat {
                            key_size: 32,
                            version: tink_tests::AES_GCM_KEY_VERSION,
                        }),
                        output_prefix_type: OutputPrefixType::Tink as i32,
                    }),
                }),
                ec_point_format: EcPointFormat::Uncompressed as i32,
            }),
        },
        */
    ];
    for (err_msg, format) in &invalid_formats {
        let serialized_format = tink_tests::proto_encode(format);
        let result = km.new_key(&serialized_format);
        tink_tests::expect_err(result, err_msg);
    }
}

#[test]
fn test_primitive_with_invalid_key() {
    tink_hybrid::init();
    let km = tink_core::registry::get_key_manager(tink_tests::ECIES_AEAD_HKDF_PRIVATE_KEY_TYPE_URL)
        .unwrap();
    let pub_x_data =
        hex::decode("7ea7cc506e46cfb2bbdb1503b0fb5f4edbf6e9830459b64a4064455045a7a58c").unwrap();
    let pub_y_data =
        hex::decode("fe38bbb204c8afab3691af996eeb78aa60b8c24ea6dbe13fb6df788786fb2230").unwrap();
    let secret_key_data =
        hex::decode("2fa00a02762046c8797d5cc62cd1ba41ecf11f0996e3c5169ca8c891af8055c3").unwrap();

    let invalid_keys = vec![
        (
            "version in range",
            EciesAeadHkdfPrivateKey {
                version: 9999, // invalid
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "version in range",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: 9999, // invalid
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unsupported curve",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: 9999, // invalid
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unknown HKDF hash",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: 9999, //invalid
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unsupported key type",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: "invalid".to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "invalid key format",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 999, // invalid
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "unknown EC point format",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: 999, // invalid
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "failed to parse D value",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: vec![],
            },
        ),
        (
            "no public key",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: None,
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "no params",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: None,
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "no kem_params",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: None,
                        dem_params: Some(EciesAeadDemParams {
                            aead_dem: Some(KeyTemplate {
                                type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                                value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                    key_size: 32,
                                    version: tink_tests::AES_GCM_KEY_VERSION,
                                }),
                                output_prefix_type: OutputPrefixType::Tink as i32,
                            }),
                        }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "no dem_params",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: None,
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data.clone(),
                    y: pub_y_data.clone(),
                }),
                key_value: secret_key_data.clone(),
            },
        ),
        (
            "no aead_dem",
            EciesAeadHkdfPrivateKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
                public_key: Some(EciesAeadHkdfPublicKey {
                    version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                    params: Some(EciesAeadHkdfParams {
                        kem_params: Some(EciesHkdfKemParams {
                            curve_type: EllipticCurveType::NistP256 as i32,
                            hkdf_hash_type: HashType::Sha256 as i32,
                            hkdf_salt: vec![1, 2, 3],
                        }),
                        dem_params: Some(EciesAeadDemParams { aead_dem: None }),
                        ec_point_format: EcPointFormat::Uncompressed as i32,
                    }),
                    x: pub_x_data,
                    y: pub_y_data,
                }),
                key_value: secret_key_data,
            },
        ),
        /* All based on this valid key:
        EciesAeadHkdfPrivateKey {
            version: tink_hybrid::ECIES_AEAD_HKDF_PRIVATE_KEY_KEY_VERSION,
            public_key: Some(EciesAeadHkdfPublicKey {
                version: tink_hybrid::ECIES_AEAD_HKDF_PUBLIC_KEY_KEY_VERSION,
                params: Some(EciesAeadHkdfParams {
                    kem_params: Some(EciesHkdfKemParams {
                        curve_type: EllipticCurveType::NistP256 as i32,
                        hkdf_hash_type: HashType::Sha256 as i32,
                        hkdf_salt: vec![1, 2, 3],
                    }),
                    dem_params: Some(EciesAeadDemParams {
                        aead_dem: Some(KeyTemplate {
                            type_url: tink_tests::AES_GCM_TYPE_URL.to_string(),
                            value: tink_tests::proto_encode(&AesGcmKeyFormat {
                                key_size: 32,
                                version: tink_tests::AES_GCM_KEY_VERSION,
                            }),
                            output_prefix_type: OutputPrefixType::Tink as i32,
                        }),
                    }),
                    ec_point_format: EcPointFormat::Uncompressed as i32,
                }),
                x: pub_x_data.clone(),
                y: pub_y_data.clone(),
            }),
            key_value: secret_key_data.clone(),
        },
        */
    ];
    for (err_msg, key) in &invalid_keys {
        let serialized_key = tink_tests::proto_encode(key);
        let result = km.primitive(&serialized_key);
        tink_tests::expect_err(result, err_msg);
    }
}

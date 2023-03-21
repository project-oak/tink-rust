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

use lazy_static::lazy_static;
use tink_core::subtle::random::get_random_bytes;
use tink_hybrid::subtle::EciesAeadHkdfDemHelper;
use tink_tests::proto_encode;

lazy_static! {
    static ref KEY_TEMPLATES: Vec<(tink_proto::KeyTemplate, usize)> = vec![
        (tink_aead::aes256_ctr_hmac_sha256_key_template(), 64),
        (tink_aead::aes128_ctr_hmac_sha256_key_template(), 48),
        (tink_aead::aes256_gcm_key_template(), 32),
        (tink_aead::aes128_gcm_key_template(), 16),
        (tink_daead::aes_siv_key_template(), 64),
    ];
    static ref U_TEMPLATES: Vec<tink_proto::KeyTemplate> = vec![
        tink_signature::ecdsa_p256_key_template(),
        tink_mac::hmac_sha256_tag256_key_template(),
        tink_proto::KeyTemplate {
            type_url: "some url".to_string(),
            value: vec![0],
            output_prefix_type: 0
        },
        tink_proto::KeyTemplate {
            type_url: tink_aead::AES_CTR_HMAC_AEAD_TYPE_URL.to_string(),
            value: proto_encode(&tink_proto::AesCtrHmacAeadKeyFormat {
                aes_ctr_key_format: None,
                hmac_key_format: None,
            }),
            output_prefix_type: 0
        },
        tink_proto::KeyTemplate {
            type_url: tink_aead::AES_GCM_TYPE_URL.to_string(),
            value: proto_encode(&tink_proto::AesGcmKeyFormat {
                key_size: 1,
                version: 0,
            }),
            output_prefix_type: 0
        },
        tink_proto::KeyTemplate {
            type_url: tink_daead::AES_SIV_TYPE_URL.to_string(),
            value: proto_encode(&tink_proto::AesSivKeyFormat {
                key_size: 1,
                version: 0,
            }),
            output_prefix_type: 0
        },
    ];
}

#[test]
fn test_cipher_key_size() {
    tink_hybrid::init();
    for (c, l) in KEY_TEMPLATES.iter() {
        let r_dem =
            tink_hybrid::EciesAeadHkdfDemHelper::new(c).expect("error generating a DEM helper");
        assert_eq!(
            r_dem.get_symmetric_key_size(),
            *l,
            "incorrect key size for {c:?} template",
        );
    }
}

#[test]
fn test_unsupported_key_templates() {
    tink_hybrid::init();
    tink_signature::init();
    tink_mac::init();
    for l in U_TEMPLATES.iter() {
        assert!(
            tink_hybrid::EciesAeadHkdfDemHelper::new(l).is_err(),
            "unsupported key template {:?} should have generated error",
            l
        );
    }
}

#[test]
fn test_aead() {
    tink_hybrid::init();
    for (c, _l) in KEY_TEMPLATES.iter() {
        let pt = get_random_bytes(20);
        let ad = get_random_bytes(20);
        let r_dem =
            tink_hybrid::EciesAeadHkdfDemHelper::new(c).expect("error generating a DEM helper");
        let sk = get_random_bytes(r_dem.get_symmetric_key_size());
        let prim = r_dem
            .get_aead_or_daead(&sk)
            .expect("error getting AEAD primitive");
        let ct = match &prim {
            tink_core::Primitive::Aead(a) => a.encrypt(&pt, &ad).expect("error encrypting"),
            tink_core::Primitive::DeterministicAead(a) => a
                .encrypt_deterministically(&pt, &ad)
                .expect("error encrypting"),
            _ => panic!("incorrect primitive type"),
        };
        let dt = match &prim {
            tink_core::Primitive::Aead(a) => a.decrypt(&ct, &ad).expect("error decrypting"),
            tink_core::Primitive::DeterministicAead(a) => a
                .decrypt_deterministically(&ct, &ad)
                .expect("error decrypting"),
            _ => panic!("incorrect primitive type"),
        };

        assert_eq!(
            dt,
            pt,
            "decryption not inverse of encryption,\n want :{},\n got: {}",
            hex::encode(&pt),
            hex::encode(&dt)
        );

        // shorter symmetric key
        let sk = get_random_bytes(r_dem.get_symmetric_key_size() - 1);
        assert!(
            r_dem.get_aead_or_daead(&sk).is_err(),
            "retrieving AEAD primitive should have failed"
        );

        // longer symmetric key
        let sk = get_random_bytes(r_dem.get_symmetric_key_size() + 1);
        assert!(
            r_dem.get_aead_or_daead(&sk).is_err(),
            "retrieving AEAD primitive should have failed"
        );
    }
}

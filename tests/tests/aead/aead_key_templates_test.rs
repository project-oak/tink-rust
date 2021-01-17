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
use tink_core::{utils::wrap_err, TinkError};

#[test]
fn test_aes_gcm_key_templates() {
    // AES-GCM 128 bit
    let template = tink_aead::aes128_gcm_key_template();
    check_aes_gcm_key_template(&template, 16, tink_proto::OutputPrefixType::Tink)
        .expect("invalid AES-128 GCM key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_TYPE_URL).unwrap();

    // AES-GCM 256 bit
    let template = tink_aead::aes256_gcm_key_template();
    check_aes_gcm_key_template(&template, 32, tink_proto::OutputPrefixType::Tink)
        .expect("invalid AES-256 GCM key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_TYPE_URL).unwrap();

    // AES-GCM 256 bit No Prefix
    let template = tink_aead::aes256_gcm_no_prefix_key_template();
    check_aes_gcm_key_template(&template, 32, tink_proto::OutputPrefixType::Raw)
        .expect("invalid AES-256 GCM No Prefix key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_TYPE_URL).unwrap();
}

fn check_aes_gcm_key_template(
    template: &tink_proto::KeyTemplate,
    key_size: u32,
    output_prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_GCM_TYPE_URL {
        return Err("incorrect type url".into());
    }
    if template.output_prefix_type != output_prefix_type as i32 {
        return Err("incorrect output prefix type".into());
    }
    let key_format = tink_proto::AesGcmKeyFormat::decode(template.value.as_ref())
        .map_err(|e| wrap_err("cannot deserialize key format", e))?;
    if key_format.key_size != key_size {
        return Err(format!(
            "incorrect key size, expect {}, got {}",
            key_size, key_format.key_size
        )
        .into());
    }
    Ok(())
}

#[test]
fn test_aes_gcm_siv_key_templates() {
    // AES-GCM-SIV 128 bit
    let template = tink_aead::aes128_gcm_siv_key_template();
    check_aes_gcm_siv_key_template(&template, 16, tink_proto::OutputPrefixType::Tink)
        .expect("invalid AES-128 GCM SIV key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_SIV_TYPE_URL).unwrap();

    // AES-GCM-SIV 256 bit
    let template = tink_aead::aes256_gcm_siv_key_template();
    check_aes_gcm_siv_key_template(&template, 32, tink_proto::OutputPrefixType::Tink)
        .expect("invalid AES-256 GCM SIV key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_SIV_TYPE_URL).unwrap();

    // AES-GCM-SIV 256 bit No Prefix
    let template = tink_aead::aes256_gcm_siv_no_prefix_key_template();
    check_aes_gcm_siv_key_template(&template, 32, tink_proto::OutputPrefixType::Raw)
        .expect("invalid AES-256 GCM No Prefix key template");
    test_encrypt_decrypt(&template, tink_tests::AES_GCM_SIV_TYPE_URL).unwrap();
}

fn check_aes_gcm_siv_key_template(
    template: &tink_proto::KeyTemplate,
    key_size: u32,
    output_prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_GCM_SIV_TYPE_URL {
        return Err("incorrect type url".into());
    }
    if template.output_prefix_type != output_prefix_type as i32 {
        return Err("incorrect output prefix type".into());
    }
    let key_format = tink_proto::AesGcmKeyFormat::decode(template.value.as_ref())
        .map_err(|e| wrap_err("cannot deserialize key format", e))?;
    if key_format.key_size != key_size {
        return Err(format!(
            "incorrect key size, expect {}, got {}",
            key_size, key_format.key_size
        )
        .into());
    }
    Ok(())
}

#[test]
fn test_aes_ctr_hmac_aead_key_templates() {
    // AES-CTR 128 bit with HMAC SHA-256
    let template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    check_aes_ctr_hmac_aead_key_template(&template, 16, 16, 16)
        .expect("invalid AES-128 CTR HMAC SHA256 key template");
    test_encrypt_decrypt(&template, tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL).unwrap();

    // AES-CTR 256 bit with HMAC SHA-256
    let template = tink_aead::aes256_ctr_hmac_sha256_key_template();
    check_aes_ctr_hmac_aead_key_template(&template, 32, 16, 32)
        .expect("invalid AES-256 CTR HMAC SHA256 key template");
    test_encrypt_decrypt(&template, tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL).unwrap();
}

fn check_aes_ctr_hmac_aead_key_template(
    template: &tink_proto::KeyTemplate,
    key_size: u32,
    iv_size: u32,
    tag_size: u32,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_CTR_HMAC_AEAD_TYPE_URL {
        return Err("incorrect type url".into());
    }
    let key_format = tink_proto::AesCtrHmacAeadKeyFormat::decode(template.value.as_ref())
        .map_err(|e| wrap_err("cannot deserialize key format", e))?;
    let aes_format = key_format
        .aes_ctr_key_format
        .as_ref()
        .ok_or_else(|| TinkError::new("missing aes_ctr_key_format"))?;
    if aes_format.key_size != key_size {
        return Err(format!(
            "incorrect key size, expect {}, got {}",
            key_size, aes_format.key_size
        )
        .into());
    }
    if aes_format.params.as_ref().unwrap().iv_size != iv_size {
        return Err(format!(
            "incorrect IV size, expect {}, got {}",
            iv_size,
            aes_format.params.as_ref().unwrap().iv_size
        )
        .into());
    }
    let hmac_format = key_format
        .hmac_key_format
        .as_ref()
        .ok_or_else(|| TinkError::new("missing hmac_key_format"))?;
    if hmac_format.key_size != 32 {
        return Err(format!(
            "incorrect HMAC key size, expect 32, got {}",
            hmac_format.key_size
        )
        .into());
    }
    let hmac_params = hmac_format
        .params
        .as_ref()
        .ok_or_else(|| TinkError::new("missing hmac_format.params"))?;
    if hmac_params.tag_size != tag_size {
        return Err(format!(
            "incorrect HMAC tag size, expect {}, got {}",
            tag_size, hmac_params.tag_size
        )
        .into());
    }
    if hmac_params.hash != tink_proto::HashType::Sha256 as i32 {
        return Err(format!(
            "incorrect HMAC hash, expect {:?}, got {}",
            tink_proto::HashType::Sha256,
            hmac_params.hash
        )
        .into());
    }
    Ok(())
}

#[test]
fn test_cha_cha20_poly1305_key_template() {
    let template = tink_aead::cha_cha20_poly1305_key_template();
    assert_eq!(
        template.type_url,
        tink_tests::CHA_CHA20_POLY1305_TYPE_URL,
        "incorrect type url"
    );
    test_encrypt_decrypt(&template, tink_tests::CHA_CHA20_POLY1305_TYPE_URL).unwrap();
}

#[test]
fn test_x_cha_cha20_poly1305_key_template() {
    let template = tink_aead::x_cha_cha20_poly1305_key_template();
    assert_eq!(
        template.type_url,
        tink_tests::X_CHA_CHA20_POLY1305_TYPE_URL,
        "incorrect type url"
    );
    test_encrypt_decrypt(&template, tink_tests::X_CHA_CHA20_POLY1305_TYPE_URL).unwrap();
}

#[test]
fn test_kms_envelope_aead_key_templates() {
    tink_aead::init();
    let fake_kms_client = tink_tests::fakekms::FakeClient::new("fake-kms://").unwrap();
    tink_core::registry::register_kms_client(fake_kms_client);

    let fixed_key_uri = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE";
    let new_key_uri = tink_tests::fakekms::new_key_uri().unwrap();

    let test_cases = vec![
        (
            "Fixed Fake KMS Envelope AEAD Key with AES128_GCM",
            tink_aead::kms_envelope_aead_key_template(
                fixed_key_uri,
                tink_aead::aes128_gcm_key_template(),
            ),
        ),
        (
            "New Fake KMS Envelope AEAD Key with AES128_GCM",
            tink_aead::kms_envelope_aead_key_template(
                &new_key_uri,
                tink_aead::aes128_gcm_key_template(),
            ),
        ),
    ];
    for (name, template) in test_cases {
        assert!(
            test_encrypt_decrypt(&template, &template.type_url).is_ok(),
            "failed for {}",
            name
        );
    }
}

fn test_encrypt_decrypt(
    template: &tink_proto::KeyTemplate,
    type_url: &str,
) -> Result<(), TinkError> {
    tink_aead::init();
    let sk = tink_core::registry::new_key(template)
        .map_err(|e| wrap_err("failed to get serialized key from template, error", e))?;

    let p = tink_core::registry::primitive(type_url, &sk)
        .map_err(|e| wrap_err("failed to get primitive from serialized key", e))?;
    let primitive = match p {
        tink_core::Primitive::Aead(p) => p,
        _ => return Err("failed to convert AEAD primitive".into()),
    };

    let plaintext = b"some data to encrypt";
    let aad = b"extra data to authenticate";
    let ciphertext = primitive
        .encrypt(&plaintext[..], &aad[..])
        .map_err(|e| wrap_err("encryption failed", e))?;
    let decrypted = primitive
        .decrypt(&ciphertext, &aad[..])
        .map_err(|e| wrap_err("decryption failed", e))?;

    if plaintext.to_vec() != decrypted {
        return Err(format!(
            "decrypted data doesn't match plaintext, got: {}, want: {}",
            hex::encode(&decrypted),
            hex::encode(&plaintext[..])
        )
        .into());
    }
    Ok(())
}

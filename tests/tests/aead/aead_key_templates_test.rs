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

use tink_core::{utils::wrap_err, TinkError};

#[test]
fn test_key_templates() {
    tink_aead::init();
    let test_cases = vec![
        ("AES128_GCM", tink_aead::aes128_gcm_key_template()),
        ("AES256_GCM", tink_aead::aes256_gcm_key_template()),
        (
            "AES128_CTR_HMAC_SHA256",
            tink_aead::aes128_ctr_hmac_sha256_key_template(),
        ),
        (
            "AES256_CTR_HMAC_SHA256",
            tink_aead::aes256_ctr_hmac_sha256_key_template(),
        ),
        ("AES128_GCM_SIV", tink_aead::aes128_gcm_siv_key_template()),
        ("AES256_GCM_SIV", tink_aead::aes256_gcm_siv_key_template()),
        (
            "CHACHA20_POLY1305",
            tink_aead::cha_cha20_poly1305_key_template(),
        ),
        (
            "XCHACHA20_POLY1305",
            tink_aead::x_cha_cha20_poly1305_key_template(),
        ),
    ];
    for (name, template) in test_cases {
        let want = tink_tests::key_template_proto("aead", name).unwrap();
        assert_eq!(want, template);

        // Check that the same template is registered under the same name.
        let generator = tink_core::registry::get_template_generator(name).unwrap();
        let registered = generator();
        assert_eq!(registered, template);

        assert!(test_encrypt_decrypt(&template).is_ok());
    }
}

#[test]
fn test_no_prefix_key_templates() {
    tink_aead::init();
    let test_cases = vec![
        ("AES256_GCM", tink_aead::aes256_gcm_no_prefix_key_template()),
        (
            "AES256_GCM_SIV",
            tink_aead::aes256_gcm_siv_no_prefix_key_template(),
        ),
    ];
    for (name, template) in test_cases {
        let mut want = tink_tests::key_template_proto("aead", name).unwrap();
        want.output_prefix_type = tink_proto::OutputPrefixType::Raw as i32;
        assert_eq!(want, template);
        assert!(test_encrypt_decrypt(&template).is_ok());
    }
}

#[test]
fn test_kms_envelope_aead_key_template() {
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
        assert_eq!(
            template.output_prefix_type,
            tink_proto::OutputPrefixType::Raw as i32,
            "KMS envelope template {} does not use RAW prefix, found '{:?}'",
            name,
            template.output_prefix_type
        );
        assert!(
            test_encrypt_decrypt(&template).is_ok(),
            "failed for {}",
            name
        );
    }
}

// Tests that two `KmsEnvelopeAead` keys that use the same KEK and DEK template should be able to
// decrypt each  other's ciphertexts.
#[test]
fn test_kms_envelope_aead_key_template_multiple_keys_same_kek() {
    tink_aead::init();
    let fake_kms_client = tink_tests::fakekms::FakeClient::new("fake-kms://").unwrap();
    tink_core::registry::register_kms_client(fake_kms_client);

    let fixed_key_uri = "fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE";
    let template1 = tink_aead::kms_envelope_aead_key_template(
        fixed_key_uri,
        tink_aead::aes128_gcm_key_template(),
    );
    let template2 = tink_aead::kms_envelope_aead_key_template(
        fixed_key_uri,
        tink_aead::aes128_gcm_key_template(),
    );

    let handle1 = tink_core::keyset::Handle::new(&template1).unwrap();
    let aead1 = tink_aead::new(&handle1).unwrap();
    let handle2 = tink_core::keyset::Handle::new(&template2).unwrap();
    let aead2 = tink_aead::new(&handle2).unwrap();

    let plaintext = b"some data to encrypt";
    let aad = b"extra data to authenticate";

    let ciphertext = aead1
        .encrypt(&plaintext[..], &aad[..])
        .expect("encryption failed");

    let decrypted = aead2
        .decrypt(&ciphertext, &aad[..])
        .expect("decryption failed");
    assert_eq!(&plaintext[..], decrypted);
}

fn test_encrypt_decrypt(template: &tink_proto::KeyTemplate) -> Result<(), TinkError> {
    tink_aead::init();
    let handle = tink_core::keyset::Handle::new(template).unwrap();
    let primitive = tink_aead::new(&handle).unwrap();

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

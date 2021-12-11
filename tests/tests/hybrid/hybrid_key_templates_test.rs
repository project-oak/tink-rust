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

#[test]
fn test_key_templates() {
    tink_hybrid::init();
    let test_cases = vec![
        (
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM",
            tink_hybrid::ecies_hkdf_aes128_gcm_key_template(),
        ),
        (
            "ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256",
            tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
        ),
    ];
    for (name, template) in test_cases {
        let private_handle = tink_core::keyset::Handle::new(&template).unwrap();
        let public_handle = private_handle.public().unwrap();
        let enc = tink_hybrid::new_encrypt(&public_handle).unwrap();
        let dec = tink_hybrid::new_decrypt(&private_handle).unwrap();
        let test_inputs: Vec<(&'static [u8], &'static [u8], &'static [u8])> = vec![
            (
                b"this data needs to be encrypted",
                b"encryption context",
                b"encryption context",
            ),
            (b"this data needs to be encrypted", b"", b""),
            (b"", b"encryption context", b"encryption context"),
            (b"", b"", b""),
            (b"this data needs to be encrypted", b"", b""),
        ];
        for (plaintext, context1, context2) in test_inputs {
            let ciphertext = enc.encrypt(plaintext, context1).unwrap();
            let decrypted = dec.decrypt(&ciphertext, context2).unwrap();
            assert_eq!(plaintext, decrypted);
        }
        // Check that the same template is registered under the same name.
        let generator = tink_core::registry::get_template_generator(name).unwrap();
        let registered = generator();
        assert_eq!(registered, template);
    }
}

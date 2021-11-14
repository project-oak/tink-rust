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

use tink_tests::SharedBuf;

#[test]
fn test_key_templates() {
    tink_streaming_aead::init();
    let test_cases = vec![
        (
            "AES128_GCM_HKDF_4KB",
            tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template(),
        ),
        (
            "AES128_GCM_HKDF_1MB",
            tink_streaming_aead::aes128_gcm_hkdf_1mb_key_template(),
        ),
        (
            "AES256_GCM_HKDF_4KB",
            tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template(),
        ),
        (
            "AES256_GCM_HKDF_1MB",
            tink_streaming_aead::aes256_gcm_hkdf_1mb_key_template(),
        ),
        (
            "AES128_CTR_HMAC_SHA256_4KB",
            tink_streaming_aead::aes128_ctr_hmac_sha256_segment_4kb_key_template(),
        ),
        (
            "AES128_CTR_HMAC_SHA256_1MB",
            tink_streaming_aead::aes128_ctr_hmac_sha256_segment_1mb_key_template(),
        ),
        (
            "AES256_CTR_HMAC_SHA256_4KB",
            tink_streaming_aead::aes256_ctr_hmac_sha256_segment_4kb_key_template(),
        ),
        (
            "AES256_CTR_HMAC_SHA256_1MB",
            tink_streaming_aead::aes256_ctr_hmac_sha256_segment_1mb_key_template(),
        ),
    ];
    for (name, template) in test_cases {
        let want = tink_tests::key_template_proto("streamingaead", name).unwrap();
        assert_eq!(want, template);

        // Check that the same template is registered under the same name.
        let generator = tink_core::registry::get_template_generator(name).unwrap();
        let registered = generator();
        assert_eq!(registered, template);

        let handle = tink_core::keyset::Handle::new(&template).unwrap();
        let primitive = tink_streaming_aead::new(&handle).unwrap();

        let plaintext = b"some data to encrypt";
        let aad = b"extra data to authenticate";

        let buf = SharedBuf::new();
        let mut w = primitive
            .new_encrypting_writer(Box::new(buf.clone()), aad)
            .unwrap();
        w.write_all(plaintext).unwrap();
        w.close().unwrap();

        let ct = buf.contents();
        let mut r = primitive
            .new_decrypting_reader(Box::new(std::io::Cursor::new(ct.to_vec())), aad)
            .unwrap();

        let mut decrypted = vec![];
        r.read_to_end(&mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}

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
use std::collections::HashSet;

#[test]
fn test_new_key_multiple_times() {
    tink_aead::init();
    let key_template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let _aead_key_format =
        tink::proto::AesCtrHmacAeadKeyFormat::decode(key_template.value.as_ref())
            .expect("cannot unmarshal AES128_CTR_HMAC_SHA256 key template");

    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    let mut keys = HashSet::new();
    let num_tests = 24;
    for _ in 0..num_tests / 2 {
        let sk = key_manager.new_key(&key_template.value).unwrap();
        let key = tink::proto::AesCtrHmacAeadKey::decode(sk.as_ref()).unwrap();

        keys.insert(key.aes_ctr_key.as_ref().unwrap().key_value.clone());
        keys.insert(key.hmac_key.as_ref().unwrap().key_value.clone());
        assert_eq!(
            key.aes_ctr_key.unwrap().key_value.len(),
            16,
            "unexpected AES key size"
        );
        assert_eq!(
            key.hmac_key.unwrap().key_value.len(),
            32,
            "unexpected HMAC key size"
        );
    }
    assert_eq!(keys.len(), num_tests, "unexpected number of keys in set");
}

#[test]
fn test_new_key_with_corrupted_format() {
    tink_aead::init();
    let key_template = tink::proto::KeyTemplate {
        type_url: tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL.to_string(),
        value: vec![0, 128],
        output_prefix_type: tink::proto::OutputPrefixType::UnknownPrefix as i32,
    };

    let key_manager = tink::registry::get_key_manager(tink_testutil::AES_CTR_HMAC_AEAD_TYPE_URL)
        .expect("cannot obtain AES-CTR-HMAC-AEAD key manager");

    key_manager
        .new_key(&key_template.value)
        .expect_err("new_key got: success, want: error due to corrupted format");

    key_manager
        .new_key_data(&key_template.value)
        .expect_err("new_key_data got: success, want: error due to corrupted format");
}

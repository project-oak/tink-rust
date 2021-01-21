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
use tink_core::TinkError;
use tink_proto::HashType;

#[test]
fn test_aes_gcm_hkdf_key_templates() {
    struct TestCase {
        name: &'static str,
        tmpl: tink_proto::KeyTemplate,
        key_size: usize,
        ciphertext_segment_size: usize,
    };
    let tcs = vec![
        TestCase {
            name: "AES128GCMHKDF4KBKeyTemplate",
            tmpl: tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template(),
            key_size: 16,
            ciphertext_segment_size: 4096,
        },
        TestCase {
            name: "AES128GCMHKDF1MBKeyTemplate",
            tmpl: tink_streaming_aead::aes128_gcm_hkdf_1mb_key_template(),
            key_size: 16,
            ciphertext_segment_size: 1048576,
        },
        TestCase {
            name: "AES256GCMHKDF4KBKeyTemplate",
            tmpl: tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template(),
            key_size: 32,
            ciphertext_segment_size: 4096,
        },
        TestCase {
            name: "AES256GCMHKDF1MBKeyTemplate",
            tmpl: tink_streaming_aead::aes256_gcm_hkdf_1mb_key_template(),
            key_size: 32,
            ciphertext_segment_size: 1048576,
        },
    ];
    for tc in tcs {
        check_aes_gcm_hkdf_key_template(
            &tc.tmpl,
            tc.key_size,
            HashType::Sha256,
            tc.ciphertext_segment_size,
            tink_proto::OutputPrefixType::Raw,
        )
        .unwrap_or_else(|e| panic!("{}: failed with {:?}", tc.name, e));
    }
}

fn check_aes_gcm_hkdf_key_template(
    template: &tink_proto::KeyTemplate,
    key_size: usize,
    hkdf_hash_type: HashType,
    ciphertext_segment_size: usize,
    output_prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_GCM_HKDF_TYPE_URL {
        return Err("incorrect type url".into());
    }
    if template.output_prefix_type != output_prefix_type as i32 {
        return Err("incorrect output prefix type".into());
    }
    let key_format = tink_proto::AesGcmHkdfStreamingKeyFormat::decode(template.value.as_ref())
        .expect("cannot deserialize key format");
    if key_format.key_size as usize != key_size {
        return Err(format!(
            "incorrect main key size, expect {}, got {}",
            key_size, key_format.key_size,
        )
        .into());
    }
    let key_params = key_format
        .params
        .ok_or_else(|| TinkError::new("no params"))?;
    if key_params.derived_key_size as usize != key_size {
        return Err(format!(
            "incorrect derived key size, expect {}, got {}",
            key_size, key_params.derived_key_size,
        )
        .into());
    }
    if key_params.ciphertext_segment_size as usize != ciphertext_segment_size {
        return Err(format!(
            "incorrect ciphertext segment size, expect {}, got {}",
            ciphertext_segment_size, key_params.ciphertext_segment_size,
        )
        .into());
    }
    if key_params.hkdf_hash_type != hkdf_hash_type as i32 {
        return Err(format!(
            "incorrect HKDF hash type, expect {}, got {:?}",
            key_params.hkdf_hash_type, hkdf_hash_type
        )
        .into());
    }
    Ok(())
}

#[test]
fn test_aes_ctr_hmac_key_templates() {
    struct TestCase {
        name: &'static str,
        template: tink_proto::KeyTemplate,
        key_size: usize,
        hkdf_hash_type: HashType,
        tag_alg: HashType,
        tag_size: usize,
        ciphertext_segment_size: usize,
    };
    let testcases = vec![
        TestCase {
            name: "AES128CTRHMACSHA256Segment4KBKeyTemplate",
            template: tink_streaming_aead::aes128_ctr_hmac_sha256_segment_4kb_key_template(),
            key_size: 16,
            hkdf_hash_type: HashType::Sha256,
            tag_alg: HashType::Sha256,
            tag_size: 32,
            ciphertext_segment_size: 4096,
        },
        TestCase {
            name: "AES128CTRHMACSHA256Segment1MBKeyTemplate",
            template: tink_streaming_aead::aes128_ctr_hmac_sha256_segment_1mb_key_template(),
            key_size: 16,
            hkdf_hash_type: HashType::Sha256,
            tag_alg: HashType::Sha256,
            tag_size: 32,
            ciphertext_segment_size: 1048576,
        },
        TestCase {
            name: "AES256CTRHMACSHA256Segment4KBKeyTemplate",
            template: tink_streaming_aead::aes256_ctr_hmac_sha256_segment_4kb_key_template(),
            key_size: 32,
            hkdf_hash_type: HashType::Sha256,
            tag_alg: HashType::Sha256,
            tag_size: 32,
            ciphertext_segment_size: 4096,
        },
        TestCase {
            name: "AES256CTRHMACSHA256Segment1MBKeyTemplate",
            template: tink_streaming_aead::aes256_ctr_hmac_sha256_segment_1mb_key_template(),
            key_size: 32,
            hkdf_hash_type: HashType::Sha256,
            tag_alg: HashType::Sha256,
            tag_size: 32,
            ciphertext_segment_size: 1048576,
        },
    ];
    for tc in testcases {
        check_aes_ctr_hmac_key_template(
            &tc.template,
            tc.key_size,
            tc.hkdf_hash_type,
            tc.tag_alg,
            tc.tag_size,
            tc.ciphertext_segment_size,
            tink_proto::OutputPrefixType::Raw,
        )
        .unwrap_or_else(|e| panic!("{}: failed with {:?}", tc.name, e));
    }
}

fn check_aes_ctr_hmac_key_template(
    template: &tink_proto::KeyTemplate,
    key_size: usize,
    hkdf_hash_type: HashType,
    tag_alg: HashType,
    tag_size: usize,
    ciphertext_segment_size: usize,
    output_prefix_type: tink_proto::OutputPrefixType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_CTR_HMAC_TYPE_URL {
        return Err("incorrect type url".into());
    }
    if template.output_prefix_type != output_prefix_type as i32 {
        return Err("incorrect output prefix type".into());
    }
    let key_format = tink_proto::AesCtrHmacStreamingKeyFormat::decode(template.value.as_ref())
        .expect("cannot deserialize key format");
    if key_format.key_size as usize != key_size {
        return Err(format!(
            "incorrect main key size, expect {}, got {}",
            key_size, key_format.key_size
        )
        .into());
    }
    let key_params = key_format
        .params
        .ok_or_else(|| TinkError::new("no params"))?;
    if key_params.derived_key_size as usize != key_size {
        return Err(format!(
            "incorrect derived key size, expect {}, got {}",
            key_size, key_params.derived_key_size
        )
        .into());
    }
    if key_params.hkdf_hash_type != hkdf_hash_type as i32 {
        return Err(format!(
            "incorrect HKDF hash type, expect {:?}, got {}",
            hkdf_hash_type, key_params.hkdf_hash_type
        )
        .into());
    }
    let hmac_params = key_params
        .hmac_params
        .ok_or_else(|| TinkError::new("no params"))?;
    if hmac_params.hash != tag_alg as i32 {
        return Err(format!(
            "incorrect tag algorithm, expect {:?}, got {}",
            tag_alg, hmac_params.hash
        )
        .into());
    }
    if hmac_params.tag_size as usize != tag_size {
        return Err(format!(
            "incorrect tag size, expect {}, got {}",
            tag_size, hmac_params.tag_size
        )
        .into());
    }
    if key_params.ciphertext_segment_size as usize != ciphertext_segment_size {
        return Err(format!(
            "incorrect ciphertext segment size, expect {}, got {}",
            ciphertext_segment_size, key_params.ciphertext_segment_size
        )
        .into());
    }
    Ok(())
}

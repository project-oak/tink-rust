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
fn test_key_templates() {
    tink_mac::init();
    let test_cases = vec![
        (
            "HMAC_SHA256_128BITTAG",
            tink_mac::hmac_sha256_tag128_key_template(),
        ),
        (
            "HMAC_SHA256_256BITTAG",
            tink_mac::hmac_sha256_tag256_key_template(),
        ),
        (
            "HMAC_SHA512_256BITTAG",
            tink_mac::hmac_sha512_tag256_key_template(),
        ),
        (
            "HMAC_SHA512_512BITTAG",
            tink_mac::hmac_sha512_tag512_key_template(),
        ),
        ("AES_CMAC", tink_mac::aes_cmac_tag128_key_template()),
    ];
    for (name, template) in test_cases {
        let want = tink_tests::key_template_proto("mac", name).unwrap();
        assert_eq!(want, template);

        let handle = tink_core::keyset::Handle::new(&template).unwrap();
        let primitive = tink_mac::new(&handle).unwrap();

        let nonempty_msg = b"this data needs to be authenticated";
        let empty_msg = b"";
        let test_inputs = vec![&nonempty_msg[..], &empty_msg[..]];
        for ti in test_inputs {
            let tag = primitive.compute_mac(ti).unwrap();
            assert!(primitive.verify_mac(&tag, ti).is_ok());
        }
    }
}

#[test]
fn test_templates() {
    tink_mac::init();
    let template = tink_mac::hmac_sha256_tag128_key_template();
    check_hmac_template(template, 32, 16, tink_proto::HashType::Sha256)
        .expect("incorrect HMACSHA256Tag128KeyTemplate");
    let template = tink_mac::hmac_sha256_tag256_key_template();
    check_hmac_template(template, 32, 32, tink_proto::HashType::Sha256)
        .expect("incorrect HMACSHA256Tag256KeyTemplate");
    let template = tink_mac::hmac_sha512_tag256_key_template();
    check_hmac_template(template, 64, 32, tink_proto::HashType::Sha512)
        .expect("incorrect HMACSHA512Tag256KeyTemplate");
    let template = tink_mac::hmac_sha512_tag512_key_template();
    check_hmac_template(template, 64, 64, tink_proto::HashType::Sha512)
        .expect("incorrect HMACSHA512Tag512KeyTemplate");
    let template = tink_mac::aes_cmac_tag128_key_template();
    check_cmac_template(template, 32, 16).expect("incorrect AESCMACTag128KeyTemplate");
}

fn check_hmac_template(
    template: tink_proto::KeyTemplate,
    key_size: usize,
    tag_size: usize,
    hash_type: tink_proto::HashType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::HMAC_TYPE_URL {
        return Err("type_url is incorrect".into());
    }
    let format = tink_proto::HmacKeyFormat::decode(template.value.as_ref())
        .map_err(|e| wrap_err("unable to unmarshal serialized key format", e))?;
    if format.key_size as usize != key_size
        || format.params.as_ref().unwrap().hash != hash_type as i32
        || format.params.as_ref().unwrap().tag_size as usize != tag_size
    {
        return Err("KeyFormat is incorrect".into());
    }
    let keymanager = tink_core::registry::get_key_manager(tink_tests::HMAC_TYPE_URL)
        .expect("HMAC key manager not found");
    keymanager
        .new_key(&template.value)
        .expect("HMAC key manager cannot create key");
    Ok(())
}

fn check_cmac_template(
    template: tink_proto::KeyTemplate,
    key_size: usize,
    tag_size: usize,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_CMAC_TYPE_URL {
        return Err("TypeUrl is incorrect".into());
    }
    let format = tink_proto::AesCmacKeyFormat::decode(template.value.as_ref())
        .map_err(|e| wrap_err("unable to unmarshal serialized key format", e))?;
    if format.key_size as usize != key_size
        || format.params.as_ref().unwrap().tag_size as usize != tag_size
    {
        return Err("KeyFormat is incorrect".into());
    }
    let keymanager = tink_core::registry::get_key_manager(tink_tests::AES_CMAC_TYPE_URL)
        .expect("AES CMAC key manager not found");
    keymanager
        .new_key(&template.value)
        .expect("AES CMAC key manager cannot create key");
    Ok(())
}

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
use tink_proto::prost::Message;

#[test]
fn test_key_templates() {
    tink_prf::init();
    let test_cases = vec![
        ("HMAC_PRF_SHA256", tink_prf::hmac_sha256_prf_key_template()),
        ("HMAC_PRF_SHA512", tink_prf::hmac_sha512_prf_key_template()),
        ("HKDF_PRF_SHA256", tink_prf::hkdf_sha256_prf_key_template()),
        ("AES_CMAC_PRF", tink_prf::aes_cmac_prf_key_template()),
    ];
    for (name, template) in test_cases {
        let want = tink_tests::key_template_proto("prf", name).unwrap();
        assert_eq!(want, template);

        let handle = tink_core::keyset::Handle::new(&template).unwrap();
        let primitive = tink_prf::Set::new(&handle).unwrap();

        let nonempty_input = b"This is an ID that needs to be redacted";
        let empty_input = b"";
        let test_inputs = vec![&nonempty_input[..], &empty_input[..]];
        for ti in test_inputs {
            let output = primitive.compute_primary_prf(ti, 16).unwrap();
            assert_eq!(output.len(), 16);
            let output2 = primitive.compute_primary_prf(ti, 16).unwrap();
            assert_eq!(output2, output);
        }
    }
}

#[test]
fn test_templates() {
    tink_prf::init();
    let template = tink_prf::hmac_sha256_prf_key_template();
    assert!(
        check_hmac_template(&template, 32, tink_proto::HashType::Sha256).is_ok(),
        "incorrect HMAC_SHA256PRFKeyTemplate"
    );
    let template = tink_prf::hmac_sha512_prf_key_template();
    assert!(
        check_hmac_template(&template, 64, tink_proto::HashType::Sha512).is_ok(),
        "incorrect HMAC_SHA512PRFKeyTemplate"
    );
    let template = tink_prf::hkdf_sha256_prf_key_template();
    assert!(
        check_hkdf_template(&template, 32, &[], tink_proto::HashType::Sha256).is_ok(),
        "incorrect HKDFSHA256PRFKeyTemplate"
    );
    let template = tink_prf::aes_cmac_prf_key_template();
    assert!(
        check_cmac_template(&template, 32).is_ok(),
        "incorrect AESCMACSPRFKeyTemplate"
    );
}

fn check_hmac_template(
    template: &tink_proto::KeyTemplate,
    key_size: u32,
    hash_type: tink_proto::HashType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::HMAC_PRF_TYPE_URL {
        return Err("TypeUrl is incorrect".into());
    }
    if template.output_prefix_type != tink_proto::OutputPrefixType::Raw as i32 {
        return Err("Not RAW output prefix".into());
    }
    let format = tink_proto::HmacPrfKeyFormat::decode(template.value.as_ref())
        .map_err(|_| TinkError::new("unable to unmarshal serialized key format"))?;
    if format.key_size != key_size || format.params.unwrap().hash != hash_type as i32 {
        return Err("KeyFormat is incorrect".into());
    }
    let keymanager = tink_core::registry::get_key_manager(tink_tests::HMAC_PRF_TYPE_URL)
        .map_err(|e| wrap_err("Could not obtain HMAC key manager", e))?;
    assert!(
        keymanager.new_key(&template.value).is_ok(),
        "HMAC key manager cannot create key"
    );
    Ok(())
}

fn check_hkdf_template(
    template: &tink_proto::KeyTemplate,
    key_size: u32,
    salt: &[u8],
    hash_type: tink_proto::HashType,
) -> Result<(), TinkError> {
    if template.type_url != tink_tests::HKDF_PRF_TYPE_URL {
        return Err("TypeUrl is incorrect".into());
    }
    if template.output_prefix_type != tink_proto::OutputPrefixType::Raw as i32 {
        return Err("Not RAW output prefix".into());
    }

    let format = tink_proto::HkdfPrfKeyFormat::decode(template.value.as_ref())
        .map_err(|_| TinkError::new("unable to unmarshal serialized key format"))?;
    if format.key_size != key_size
        || format.params.as_ref().unwrap().hash != hash_type as i32
        || hex::encode(salt) != hex::encode(format.params.unwrap().salt)
    {
        return Err("KeyFormat is incorrect".into());
    }
    let keymanager = tink_core::registry::get_key_manager(tink_tests::HKDF_PRF_TYPE_URL)
        .map_err(|e| wrap_err("Could not obtain HKDF key manager", e))?;
    assert!(
        keymanager.new_key(&template.value).is_ok(),
        "HKDF key manager cannot create key"
    );
    Ok(())
}

fn check_cmac_template(template: &tink_proto::KeyTemplate, key_size: u32) -> Result<(), TinkError> {
    if template.type_url != tink_tests::AES_CMAC_PRF_TYPE_URL {
        return Err("TypeUrl is incorrect".into());
    }
    if template.output_prefix_type != tink_proto::OutputPrefixType::Raw as i32 {
        return Err("Not RAW output prefix".into());
    }

    let format = tink_proto::AesCmacPrfKeyFormat::decode(template.value.as_ref())
        .map_err(|_| TinkError::new("unable to unmarshal serialized key format"))?;
    if format.key_size != key_size {
        return Err("KeyFormat is incorrect".into());
    }
    let keymanager = tink_core::registry::get_key_manager(tink_tests::AES_CMAC_PRF_TYPE_URL)
        .map_err(|e| wrap_err("Could not obtain AES-CMAC key manager", e))?;
    assert!(
        keymanager.new_key(&template.value).is_ok(),
        "AES-CMAC key manager cannot create key"
    );
    Ok(())
}

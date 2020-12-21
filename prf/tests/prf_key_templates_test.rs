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
use tink::{utils::wrap_err, TinkError};

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
    if template.type_url != tink_testutil::HMAC_PRF_TYPE_URL {
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
    let keymanager = tink::registry::get_key_manager(tink_testutil::HMAC_PRF_TYPE_URL)
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
    if template.type_url != tink_testutil::HKDF_PRF_TYPE_URL {
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
    let keymanager = tink::registry::get_key_manager(tink_testutil::HKDF_PRF_TYPE_URL)
        .map_err(|e| wrap_err("Could not obtain HKDF key manager", e))?;
    assert!(
        keymanager.new_key(&template.value).is_ok(),
        "HKDF key manager cannot create key"
    );
    Ok(())
}

fn check_cmac_template(template: &tink_proto::KeyTemplate, key_size: u32) -> Result<(), TinkError> {
    if template.type_url != tink_testutil::AES_CMAC_PRF_TYPE_URL {
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
    let keymanager = tink::registry::get_key_manager(tink_testutil::AES_CMAC_PRF_TYPE_URL)
        .map_err(|e| wrap_err("Could not obtain AES-CMAC key manager", e))?;
    assert!(
        keymanager.new_key(&template.value).is_ok(),
        "AES-CMAC key manager cannot create key"
    );
    Ok(())
}

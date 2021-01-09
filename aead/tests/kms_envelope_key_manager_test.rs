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
use tink_testutil::proto_encode;

#[test]
fn test_kms_envelope_get_primitive() {
    tink_aead::init();

    let key_uri = "aws-kms://arn:aws:kms:us-east-2:1234:key/abcd-1234";
    let ini_file = std::path::PathBuf::from("../testdata/credentials_aws.ini");
    let g = tink_awskms::AwsClient::new_with_credentials(key_uri, &ini_file).unwrap();
    tink::registry::register_kms_client(g);

    let dek = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let kh = tink::keyset::Handle::new(&tink_aead::kms_envelope_aead_key_template(key_uri, dek))
        .expect("error getting a new keyset handle");
    let _a = tink_aead::new(&kh).expect("error getting the primitive");

    // No real KEK so can't exercise the AEAD.
}

#[test]
fn test_kms_envelope_get_primitive_no_client() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL)
        .expect("cannot obtain KMS envelope key manager");
    assert_eq!(
        key_manager.type_url(),
        tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL
    );
    assert_eq!(
        key_manager.key_material_type(),
        tink::proto::key_data::KeyMaterialType::Remote
    );
    let key = tink::proto::KmsEnvelopeAeadKey {
        version: tink_testutil::KMS_ENVELOPE_AEAD_KEY_VERSION,
        params: Some(tink::proto::KmsEnvelopeAeadKeyFormat {
            kek_uri: "some uri".to_string(),
            dek_template: Some(tink_aead::aes128_ctr_hmac_sha256_key_template()),
        }),
    };
    let serialized_key = proto_encode(&key);

    // No KMS client registered, so expect failure
    assert!(key_manager.primitive(&serialized_key).is_err());
}

#[test]
fn test_kms_envelope_get_primitive_invalid() {
    tink_aead::init();

    let key_uri = "aws-kms://arn:aws:kms:us-east-2:1234:key/abcd-1234";
    let ini_file = std::path::PathBuf::from("../testdata/credentials_aws.ini");
    let g = tink_awskms::AwsClient::new_with_credentials(key_uri, &ini_file).unwrap();
    tink::registry::register_kms_client(g);

    let km = tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL)
        .expect("cannot obtain KMS envelope key manager");

    let result = km.primitive(&[]);
    tink_testutil::expect_err(result, "empty key");

    let result = km.primitive(&[0; 5]);
    tink_testutil::expect_err(result, "invalid key");

    let key_without_params = tink::proto::KmsEnvelopeAeadKey {
        version: tink_testutil::KMS_ENVELOPE_AEAD_KEY_VERSION,
        params: None,
    };
    let serialized_key = proto_encode(&key_without_params);
    // This is actually a repeat of the empty-key test above, as `key_without_params`
    // happens to only contain default values for fields in the protobuf.
    let result = km.primitive(&serialized_key);
    assert!(result.is_err());

    let key_wrong_version = tink::proto::KmsEnvelopeAeadKey {
        version: 9999,
        params: Some(tink::proto::KmsEnvelopeAeadKeyFormat {
            kek_uri: key_uri.to_string(),
            dek_template: Some(tink_aead::aes128_ctr_hmac_sha256_key_template()),
        }),
    };
    let serialized_key = proto_encode(&key_wrong_version);
    let result = km.primitive(&serialized_key);
    tink_testutil::expect_err(result, "version in range");

    let key_no_dek_template = tink::proto::KmsEnvelopeAeadKey {
        version: tink_testutil::KMS_ENVELOPE_AEAD_KEY_VERSION,
        params: Some(tink::proto::KmsEnvelopeAeadKeyFormat {
            kek_uri: key_uri.to_string(),
            dek_template: None,
        }),
    };
    let serialized_key = proto_encode(&key_no_dek_template);
    let result = km.primitive(&serialized_key);
    tink_testutil::expect_err(result, "missing DEK template");
}

#[test]
fn test_kms_envelope_new_key_basic() {
    tink_aead::init();
    let key_manager = tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL)
        .expect("cannot obtain KMS envelope key manager");
    let format = tink::proto::KmsEnvelopeAeadKeyFormat {
        kek_uri: "some uri".to_string(),
        dek_template: None,
    };
    let serialized_format = proto_encode(&format);
    let m = key_manager.new_key(&serialized_format).unwrap();
    let key = tink::proto::KmsEnvelopeAeadKey::decode(m.as_ref()).unwrap();
    assert_eq!(key.version, tink_testutil::KMS_ENVELOPE_AEAD_KEY_VERSION);
}

#[test]
fn test_kms_envelope_new_key_invalid() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL)
        .expect("cannot obtain KMS envelope key manager");
    assert!(km.new_key(&[]).is_err());
    assert!(km.new_key(&[0; 5]).is_err());
}

#[test]
fn test_kms_envelope_template() {
    tink_aead::init();
    let dek_template = tink_aead::aes128_ctr_hmac_sha256_key_template();
    let key_template = tink_aead::kms_envelope_aead_key_template("some-uri", dek_template);
    assert_eq!(key_template.type_url, tink_aead::KMS_ENVELOPE_AEAD_TYPE_URL);
    let key_format =
        tink::proto::KmsEnvelopeAeadKeyFormat::decode(key_template.value.as_ref()).unwrap();
    assert_eq!(key_format.kek_uri, "some-uri");
}

#[test]
fn test_kms_envelope_key_manager_params() {
    tink_aead::init();
    let key_manager =
        tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL).unwrap();

    assert_eq!(
        key_manager.type_url(),
        tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL
    );
    assert_eq!(
        key_manager.key_material_type(),
        tink::proto::key_data::KeyMaterialType::Remote
    );
    assert!(!key_manager.supports_private_keys());
}

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
            dek_template: None,
        }),
    };
    let serialized_key = proto_encode(&key);

    // No KMS client registered, so expect failure
    assert!(key_manager.primitive(&serialized_key).is_err());
}

#[test]
fn test_kms_envelope_get_primitive_invalid() {
    tink_aead::init();
    let km = tink::registry::get_key_manager(tink_testutil::KMS_ENVELOPE_AEAD_TYPE_URL)
        .expect("cannot obtain KMS envelope key manager");

    assert!(km.primitive(&[]).is_err());
    assert!(km.primitive(&[0; 5]).is_err());
    let key_without_params = tink::proto::KmsEnvelopeAeadKey {
        version: tink_testutil::KMS_ENVELOPE_AEAD_KEY_VERSION,
        params: None,
    };
    let serialized_key = proto_encode(&key_without_params);
    assert!(km.primitive(&serialized_key).is_err());

    let key_wrong_version = tink::proto::KmsEnvelopeAeadKey {
        version: 9999,
        params: Some(tink::proto::KmsEnvelopeAeadKeyFormat {
            kek_uri: "some uri".to_string(),
            dek_template: None,
        }),
    };
    let serialized_key = proto_encode(&key_wrong_version);
    assert!(km.primitive(&serialized_key).is_err());
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

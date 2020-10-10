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

use super::SharedBuf;
use std::io::{Read, Write};
use tink::keyset::{Reader, Writer};

#[test]
fn test_json_io_unencrypted() {
    tink_mac::init();
    let buf = SharedBuf::new();
    let mut w = tink::keyset::JsonWriter::new(buf.clone());
    let mut r = tink::keyset::JsonReader::new(buf);

    let manager = tink_testutil::new_hmac_keyset_manager();
    let h = manager.handle().expect("cannot get keyset handle");

    let ks1 = tink::keyset::insecure::keyset_material(&h);
    w.write(&ks1).expect("cannot write keyset");

    let ks2 = r.read().expect("cannot read keyset");
    assert_eq!(
        ks1, ks2,
        "written keyset ({:?}) doesn't match read keyset ({:?})",
        ks1, ks2
    );
}

#[test]
fn test_json_reader() {
    tink_mac::init();
    let gcm_key = tink_testutil::proto_encode(&tink_testutil::new_aes_gcm_key(0, 16));
    let eax_key = tink_testutil::proto_encode(&tink_testutil::new_hmac_key(
        tink::proto::HashType::Sha512,
        32,
    ));
    let json_keyset = format!(
        r#"{{
         "primaryKeyId":42,
         "key":[
            {{
               "keyData":{{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "{}"
               }},
               "outputPrefixType":"TINK",
               "keyId":42,
               "status":"ENABLED"
            }},
            {{
               "keyData":{{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesEaxKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "{}"
               }},
               "outputPrefixType":"RAW",
               "keyId":711,
               "status":"ENABLED"
            }}
         ]
      }}"#,
        base64::encode(&gcm_key),
        base64::encode(&eax_key)
    );
    let mut buf = SharedBuf::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink::keyset::JsonReader::new(buf);

    let got = r.read().expect("cannot read keyset");

    let want = tink::proto::Keyset {
        primary_key_id: 42,
        key: vec![
            tink::proto::keyset::Key {
                key_data: Some(tink::proto::KeyData {
                    type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey".to_string(),
                    key_material_type: tink::proto::key_data::KeyMaterialType::Symmetric as i32,
                    value: gcm_key,
                }),
                output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
                key_id: 42,
                status: tink::proto::KeyStatusType::Enabled as i32,
            },
            tink::proto::keyset::Key {
                key_data: Some(tink::proto::KeyData {
                    type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey".to_string(),
                    key_material_type: tink::proto::key_data::KeyMaterialType::Symmetric as i32,
                    value: eax_key,
                }),
                output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
                key_id: 711,
                status: tink::proto::KeyStatusType::Enabled as i32,
            },
        ],
    };
    assert_eq!(got, want, "written keyset doesn't match expected keyset");
}

#[test]
fn test_json_reader_large_ids() {
    tink_mac::init();
    let gcm_key = tink_testutil::proto_encode(&tink_testutil::new_aes_gcm_key(0, 16));
    let json_keyset = format!(
        r#"{{
         "primaryKeyId":4294967275,
         "key":[
            {{
               "keyData":{{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "{}"
               }},
               "outputPrefixType":"TINK",
               "keyId":4294967275,
               "status":"ENABLED"
            }}
         ]
      }}"#,
        base64::encode(&gcm_key),
    );
    let mut buf = SharedBuf::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink::keyset::JsonReader::new(buf);

    let got = r.read().expect("cannot read keyset");

    let want = tink::proto::Keyset {
        primary_key_id: 4294967275,
        key: vec![tink::proto::keyset::Key {
            key_data: Some(tink::proto::KeyData {
                type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey".to_string(),
                key_material_type: tink::proto::key_data::KeyMaterialType::Symmetric as i32,
                value: gcm_key,
            }),
            output_prefix_type: tink::proto::OutputPrefixType::Tink as i32,
            key_id: 4294967275,
            status: tink::proto::KeyStatusType::Enabled as i32,
        }],
    };

    assert_eq!(got, want, "written keyset doesn't match expected keyset");
}

#[test]
fn test_json_reader_negative_ids() {
    tink_mac::init();
    let gcm_key = tink_testutil::proto_encode(&tink_testutil::new_aes_gcm_key(0, 16));
    let json_keyset = format!(
        r#"{{
         "primaryKeyId": -10,
         "key":[
            {{
               "keyData":{{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "{}"
               }},
               "outputPrefixType":"TINK",
               "keyId": -10,
               "status":"ENABLED"
            }}
         ]
      }}"#,
        base64::encode(&gcm_key),
    );
    let mut buf = SharedBuf::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink::keyset::JsonReader::new(buf);

    assert!(r.read().is_err(), "Expected failure due to negative key id");
}

// Tests that large IDs (>2^31) are written correctly.
#[test]
fn test_json_writer_large_id() {
    tink_mac::init();
    let eax_key = tink_testutil::proto_encode(&tink_testutil::new_hmac_key(
        tink::proto::HashType::Sha512,
        32,
    ));

    let ks = tink::proto::Keyset {
        primary_key_id: 4294967275,
        key: vec![tink::proto::keyset::Key {
            key_data: Some(tink::proto::KeyData {
                type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey".to_string(),
                key_material_type: tink::proto::key_data::KeyMaterialType::Symmetric as i32,
                value: eax_key,
            }),
            output_prefix_type: tink::proto::OutputPrefixType::Raw as i32,
            key_id: 4294967275,
            status: tink::proto::KeyStatusType::Enabled as i32,
        }],
    };

    let mut buf = SharedBuf::new();
    let mut w = tink::keyset::JsonWriter::new(buf.clone());
    w.write(&ks).expect("cannot write keyset");

    let mut contents = String::new();
    buf.read_to_string(&mut contents).unwrap();
    assert!(
        contents.contains("\"keyId\": 4294967275"),
        "written keyset does not contain a key with keyId 4294967275"
    );
    assert!(
        contents.contains("\"primaryKeyId\": 4294967275"),
        "written keyset does not contain have primaryKeyId 4294967275"
    );
}

#[test]
fn test_json_io_encrypted() {
    tink_mac::init();
    let buf = SharedBuf::new();
    let mut w = tink::keyset::JsonWriter::new(buf.clone());
    let mut r = tink::keyset::JsonReader::new(buf);

    let kse1 = tink::proto::EncryptedKeyset {
        encrypted_keyset: vec![b'A'; 32],
        keyset_info: None,
    };
    w.write_encrypted(&kse1)
        .expect("cannot write encrypted keyset");

    let kse2 = r.read_encrypted().expect("cannot read encrypted keyset");
    assert_eq!(
        kse1, kse2,
        "written encrypted keyset ({:?}) doesn't match read encrypted keyset ({:?})",
        kse1, kse2
    );
}

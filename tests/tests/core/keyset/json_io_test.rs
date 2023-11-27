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

use base64::Engine;
use std::io::Write;
use tink_core::keyset::{Reader, Writer};
use tink_proto::{key_data::KeyMaterialType, KeyStatusType, OutputPrefixType};

#[test]
fn test_json_io_unencrypted() {
    tink_mac::init();

    let manager = tink_tests::new_hmac_keyset_manager();
    let h = manager.handle().expect("cannot get keyset handle");
    let ks1 = tink_core::keyset::insecure::keyset_material(&h);

    let mut buf = Vec::new();
    {
        let mut w = tink_core::keyset::JsonWriter::new(&mut buf);
        w.write(&ks1).expect("cannot write keyset");
    }

    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
    let ks2 = r.read().expect("cannot read keyset");
    assert_eq!(
        ks1, ks2,
        "written keyset ({ks1:?}) doesn't match read keyset ({ks2:?})",
    );
}

#[test]
fn test_json_reader() {
    tink_mac::init();
    let gcm_key = tink_tests::proto_encode(&tink_tests::new_aes_gcm_key(0, 16));
    let eax_key =
        tink_tests::proto_encode(&tink_tests::new_hmac_key(tink_proto::HashType::Sha512, 32));

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
        base64::engine::general_purpose::STANDARD.encode(&gcm_key),
        base64::engine::general_purpose::STANDARD.encode(&eax_key)
    );

    let mut buf = Vec::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);

    let got = r.read().expect("cannot read keyset");

    let want = tink_proto::Keyset {
        primary_key_id: 42,
        key: vec![
            tink_proto::keyset::Key {
                key_data: Some(tink_proto::KeyData {
                    type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey".to_string(),
                    key_material_type: KeyMaterialType::Symmetric as i32,
                    value: gcm_key,
                }),
                output_prefix_type: OutputPrefixType::Tink as i32,
                key_id: 42,
                status: KeyStatusType::Enabled as i32,
            },
            tink_proto::keyset::Key {
                key_data: Some(tink_proto::KeyData {
                    type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey".to_string(),
                    key_material_type: KeyMaterialType::Symmetric as i32,
                    value: eax_key,
                }),
                output_prefix_type: OutputPrefixType::Raw as i32,
                key_id: 711,
                status: KeyStatusType::Enabled as i32,
            },
        ],
    };
    assert_eq!(got, want, "written keyset doesn't match expected keyset");
}

#[test]
fn test_json_reader_large_ids() {
    tink_mac::init();
    let gcm_key = tink_tests::proto_encode(&tink_tests::new_aes_gcm_key(0, 16));
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
        base64::engine::general_purpose::STANDARD.encode(&gcm_key),
    );
    let mut buf = Vec::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);

    let got = r.read().expect("cannot read keyset");

    let want = tink_proto::Keyset {
        primary_key_id: 4294967275,
        key: vec![tink_proto::keyset::Key {
            key_data: Some(tink_proto::KeyData {
                type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey".to_string(),
                key_material_type: KeyMaterialType::Symmetric as i32,
                value: gcm_key,
            }),
            output_prefix_type: OutputPrefixType::Tink as i32,
            key_id: 4294967275,
            status: KeyStatusType::Enabled as i32,
        }],
    };

    assert_eq!(got, want, "written keyset doesn't match expected keyset");
}

#[test]
fn test_json_reader_negative_ids() {
    tink_mac::init();
    let gcm_key = tink_tests::proto_encode(&tink_tests::new_aes_gcm_key(0, 16));
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
        base64::engine::general_purpose::STANDARD.encode(gcm_key),
    );
    let mut buf = Vec::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);

    assert!(r.read().is_err(), "Expected failure due to negative key id");
}

// Tests that large IDs (>2^31) are written correctly.
#[test]
fn test_json_writer_large_id() {
    tink_mac::init();
    let eax_key =
        tink_tests::proto_encode(&tink_tests::new_hmac_key(tink_proto::HashType::Sha512, 32));

    let ks = tink_proto::Keyset {
        primary_key_id: 4294967275,
        key: vec![tink_proto::keyset::Key {
            key_data: Some(tink_proto::KeyData {
                type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey".to_string(),
                key_material_type: KeyMaterialType::Symmetric as i32,
                value: eax_key,
            }),
            output_prefix_type: OutputPrefixType::Raw as i32,
            key_id: 4294967275,
            status: KeyStatusType::Enabled as i32,
        }],
    };

    let mut buf = Vec::new();
    {
        let mut w = tink_core::keyset::JsonWriter::new(&mut buf);
        w.write(&ks).expect("cannot write keyset");
    }

    let contents = String::from_utf8(buf).unwrap();
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
    let mut buf = Vec::new();

    let kse1 = tink_proto::EncryptedKeyset {
        encrypted_keyset: vec![b'A'; 32],
        keyset_info: None,
    };
    {
        let mut w = tink_core::keyset::JsonWriter::new(&mut buf);
        w.write_encrypted(&kse1)
            .expect("cannot write encrypted keyset");
    }

    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
    let kse2 = r.read_encrypted().expect("cannot read encrypted keyset");
    assert_eq!(
        kse1, kse2,
        "written encrypted keyset ({kse1:?}) doesn't match read encrypted keyset ({kse2:?})",
    );
}

#[test]
fn test_json_io_read_fail_decode() {
    tink_mac::init();
    let buf = [1, 2, 3];
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
    assert!(r.read().is_err());

    let buf = [1, 2, 3];
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
    assert!(r.read_encrypted().is_err());
}

#[test]
fn test_json_io_fail() {
    let eax_key =
        tink_tests::proto_encode(&tink_tests::new_hmac_key(tink_proto::HashType::Sha512, 32));
    let ks = tink_proto::Keyset {
        primary_key_id: 4294967275,
        key: vec![tink_proto::keyset::Key {
            key_data: Some(tink_proto::KeyData {
                type_url: "type.googleapis.com/google.crypto.tink.AesEaxKey".to_string(),
                key_material_type: KeyMaterialType::Symmetric as i32,
                value: eax_key,
            }),
            output_prefix_type: OutputPrefixType::Raw as i32,
            key_id: 4294967275,
            status: KeyStatusType::Enabled as i32,
        }],
    };
    let kse = tink_proto::EncryptedKeyset {
        encrypted_keyset: vec![b'A'; 32],
        keyset_info: None,
    };

    let mut sink = tink_tests::IoFailure {};
    let mut w = tink_core::keyset::JsonWriter::new(&mut sink);
    assert!(w.write(&ks).is_err());

    let mut sink = tink_tests::IoFailure {};
    let mut w = tink_core::keyset::JsonWriter::new(&mut sink);
    assert!(w.write_encrypted(&kse).is_err());

    let src = tink_tests::IoFailure {};
    let mut r = tink_core::keyset::JsonReader::new(src);
    assert!(r.read().is_err());

    let src = tink_tests::IoFailure {};
    let mut r = tink_core::keyset::JsonReader::new(src);
    assert!(r.read_encrypted().is_err());
}

#[test]
fn test_json_reader_all_enums() {
    tink_mac::init();
    let gcm_key = tink_tests::proto_encode(&tink_tests::new_aes_gcm_key(0, 16));

    let materials = vec![
        ("SYMMETRIC", KeyMaterialType::Symmetric),
        ("ASYMMETRIC_PRIVATE", KeyMaterialType::AsymmetricPrivate),
        ("ASYMMETRIC_PUBLIC", KeyMaterialType::AsymmetricPublic),
        ("REMOTE", KeyMaterialType::Remote),
        ("BURBLE", KeyMaterialType::UnknownKeymaterial),
    ];
    let key_statuses = vec![
        ("ENABLED", KeyStatusType::Enabled),
        ("DISABLED", KeyStatusType::Disabled),
        ("DESTROYED", KeyStatusType::Destroyed),
        ("BURBLE", KeyStatusType::UnknownStatus),
    ];
    let prefix_types = vec![
        ("TINK", OutputPrefixType::Tink),
        ("LEGACY", OutputPrefixType::Legacy),
        ("RAW", OutputPrefixType::Raw),
        ("CRUNCHY", OutputPrefixType::Crunchy),
        ("BURBLE", OutputPrefixType::UnknownPrefix),
    ];

    for (material_name, material_type) in &materials {
        for (status_name, status_type) in &key_statuses {
            for (prefix_name, prefix_type) in &prefix_types {
                let json_keyset = format!(
                    r#"{{
                          "primaryKeyId":42,
                          "key":[
                             {{
                                "keyData":{{
                                   "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                                   "keyMaterialType":"{}",
                                   "value": "{}"
                                }},
                                "outputPrefixType":"{}",
                                "keyId":42,
                                "status":"{}"
                             }}
                          ]
                       }}"#,
                    material_name,
                    base64::engine::general_purpose::STANDARD.encode(&gcm_key),
                    prefix_name,
                    status_name
                );
                let want = tink_proto::Keyset {
                    primary_key_id: 42,
                    key: vec![tink_proto::keyset::Key {
                        key_data: Some(tink_proto::KeyData {
                            type_url: "type.googleapis.com/google.crypto.tink.AesGcmKey"
                                .to_string(),
                            key_material_type: *material_type as i32,
                            value: gcm_key.clone(),
                        }),
                        output_prefix_type: *prefix_type as i32,
                        key_id: 42,
                        status: *status_type as i32,
                    }],
                };

                // Read from hand-crafted JSON
                let mut buf = Vec::new();
                buf.write_all(json_keyset.as_bytes()).unwrap();
                let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
                let got = r.read().expect("cannot read keyset");
                assert_eq!(got, want, "written keyset doesn't match expected keyset");

                // Write to JSON and read back.
                let mut buf = Vec::new();
                {
                    let mut w = tink_core::keyset::JsonWriter::new(&mut buf);
                    w.write(&want).expect("cannot write keyset");
                }

                let mut r = tink_core::keyset::JsonReader::new(&buf[..]);
                let got = r.read().expect("cannot read keyset");
                assert_eq!(got, want, "written keyset doesn't match expected keyset");
            }
        }
    }
}

#[test]
fn test_json_read_invalid_b64() {
    let json_keyset = r#"{
         "primaryKeyId":42,
         "key":[
            {
               "keyData":{
                  "typeUrl":"type.googleapis.com/google.crypto.tink.AesGcmKey",
                  "keyMaterialType":"SYMMETRIC",
                  "value": "non base64 data ^&*%"
               },
               "outputPrefixType":"TINK",
               "keyId":42,
               "status":"ENABLED"
            }
         ]
      }"#;

    let mut buf = Vec::new();
    buf.write_all(json_keyset.as_bytes()).unwrap();
    let mut r = tink_core::keyset::JsonReader::new(&buf[..]);

    let result = r.read();
    tink_tests::expect_err(result, "base64");
}

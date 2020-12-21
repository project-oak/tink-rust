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

use crate::cryptofmt;

#[test]
fn test_output_prefix() {
    struct Case {
        key_id: crate::KeyId,
        result: Vec<u8>,
    };
    let tests = vec![
        Case {
            key_id: 1000000,
            result: vec![0, 15, 66, 64],
        },
        Case {
            key_id: 4294967295,
            result: vec![255, 255, 255, 255],
        },
        Case {
            key_id: 0,
            result: vec![0, 0, 0, 0],
        },
    ];
    let mut key = tink_proto::keyset::Key::default();
    for test in tests {
        key.key_id = test.key_id;
        // legacy type
        key.output_prefix_type = tink_proto::OutputPrefixType::Legacy as i32;
        let prefix = cryptofmt::output_prefix(&key).unwrap();
        assert!(
            validate_prefix(&prefix, cryptofmt::LEGACY_START_BYTE, &test.result),
            "incorrect legacy prefix",
        );
        // crunchy type
        key.output_prefix_type = tink_proto::OutputPrefixType::Crunchy as i32;
        let prefix = cryptofmt::output_prefix(&key).unwrap();
        assert!(
            validate_prefix(&prefix, cryptofmt::LEGACY_START_BYTE, &test.result),
            "incorrect crunchy prefix",
        );
        // tink type
        key.output_prefix_type = tink_proto::OutputPrefixType::Tink as i32;
        let prefix = cryptofmt::output_prefix(&key).unwrap();
        assert!(
            validate_prefix(&prefix, cryptofmt::TINK_START_BYTE, &test.result),
            "incorrect tink prefix",
        );
        // raw type
        key.output_prefix_type = tink_proto::OutputPrefixType::Raw as i32;
        let prefix = cryptofmt::output_prefix(&key).unwrap();
        assert_eq!(prefix, cryptofmt::RAW_PREFIX, "incorrect raw prefix",);
    }
    // unknown prefix type
    key.output_prefix_type = tink_proto::OutputPrefixType::UnknownPrefix as i32;
    assert!(
        cryptofmt::output_prefix(&key).is_err(),
        "expect an error when prefix type is unknown"
    );
}

fn validate_prefix(prefix: &[u8], start_byte: u8, key: &[u8]) -> bool {
    if prefix[0] != start_byte {
        return false;
    }
    prefix[1..] == *key
}

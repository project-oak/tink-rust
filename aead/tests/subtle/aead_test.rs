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

#[test]
fn test_validate_aes_key_size() {
    for i in 0..65 {
        let result = tink_aead::subtle::validate_aes_key_size(i);
        match i {
            16 | 32 => {
                // Valid key sizes.
                result.unwrap();
            }
            _ => {
                // Invalid key sizes.
                let err =
                    result.expect_err(&format!("invalid key size ({}) should not be accepted", i));
                assert!(format!("{:?}", err).contains( "invalid AES key size; want 16 or 32") ,
                        "wrong error message; want a String starting with \"invalid AES key size; want 16 or 32\", got {}", err);
            }
        }
    }
}

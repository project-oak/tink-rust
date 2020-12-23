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

mod ecdsa_signer_verifier_test;
mod ecdsa_test;
mod ed25519_signer_verifier_test;

#[test]
fn test_element_from_padded_slice() {
    let testcases = vec![
        (
            "b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            true, // two bytes skipped at start
        ),
        (
            "00b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            true, // one byte skipped, one byte zeroed
        ),
        (
            "0000b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            true, // first two bytes zeroed
        ),
        (
            "2927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            true, // correct 32-byte field element
        ),
        (
            "00002927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            true, // extra leading zero bytes ('0000')
        ),
        (
            "00012927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838",
            false, // extra leading non-zero byte ('0001')
        ),
    ];
    for (value, valid) in testcases {
        let x = hex::decode(value).unwrap(); // safe: test
        let result = tink_signature::subtle::element_from_padded_slice::<p256::NistP256>(&x);
        if valid {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
    }
}

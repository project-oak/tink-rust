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

use tink::subtle;
use tink_proto::HashType;

mod cryptofmt_test;
mod hkdf_hmac_test;
mod random_test;

#[test]
fn test_compute_hash() {
    let data = b"Hello";
    struct Case {
        hf: tink_proto::HashType,
        want: &'static str,
    }
    let tests = vec![
        Case {
            hf: HashType::Sha1,
            want: "f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0",
        },
        Case {
            hf: HashType::Sha256,
            want: "185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969",
        },
        Case {
            hf: HashType::Sha384,
            want: "3519fe5ad2c596efe3e276a6f351b8fc0b03db861782490d45f7598ebd0ab5fd5520ed102f38c4a5ec834e98668035fc",
        },
        Case {
            hf: HashType::Sha512,
            want: "3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315",
        },
    ];

    for tt in tests {
        let mut hash_func = tink::subtle::get_hash_func(tt.hf).unwrap();
        let hashed = subtle::compute_hash(&mut hash_func, data).unwrap();
        let got_hash = hex::encode(hashed);
        assert_eq!(tt.want, got_hash);
    }

    // unknown
    assert!(
        subtle::get_hash_func(HashType::UnknownHash).is_none(),
        "unexpected result for invalid hash types"
    );
}

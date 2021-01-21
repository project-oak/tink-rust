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

//! Example program demonstrating `tink-signature`

fn main() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();

    let pt = b"this data needs to be signed";
    let a = s.sign(pt).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&a));

    let pubkh = kh.public().unwrap();
    let v = tink_signature::new_verifier(&pubkh).unwrap();
    assert!(v.verify(&a, b"this data needs to be signed").is_ok());
    println!("Signature verified.");
}

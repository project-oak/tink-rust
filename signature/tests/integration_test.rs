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

mod subtle;

#[test]
fn test_signature_init() {
    tink_signature::init();
    assert!(tink::registry::get_key_manager(tink_testutil::ECDSA_SIGNER_TYPE_URL).is_ok());
    assert!(tink::registry::get_key_manager(tink_testutil::ECDSA_VERIFIER_TYPE_URL).is_ok());

    assert!(tink::registry::get_key_manager(tink_testutil::ED25519_SIGNER_TYPE_URL).is_ok());
    assert!(tink::registry::get_key_manager(tink_testutil::ED25519_VERIFIER_TYPE_URL).is_ok());
}

#[test]
fn example_ecdsa() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();

    let a = s.sign(b"this data needs to be signed").unwrap();

    let pubkh = kh.public().unwrap();
    let v = tink_signature::new_verifier(&pubkh).unwrap();
    assert!(v.verify(&a, b"this data needs to be signed").is_ok());
}

#[test]
fn example_ed25519() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink::keyset::Handle::new(&tink_signature::ed25519_key_template()).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();

    let a = s.sign(b"this data needs to be signed").unwrap();

    let pubkh = kh.public().unwrap();

    let v = tink_signature::new_verifier(&pubkh).unwrap();
    assert!(v.verify(&a, b"this data needs to be signed").is_ok());
}

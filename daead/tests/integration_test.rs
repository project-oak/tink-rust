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

#[test]
fn example() {
    tink_daead::init();
    let kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();
    let d = tink_daead::new(&kh).unwrap();
    let pt = b"this data needs to be encrypted";
    let ad = b"this data needs to be authenticated, but not encrypted";
    let ct1 = d.encrypt_deterministically(pt, ad).unwrap();
    let ct2 = d.encrypt_deterministically(pt, ad).unwrap();

    assert_eq!(ct1, ct2, "cipher texts are not equal");
    println!("Cipher texts are equal.");

    let pt2 = d.decrypt_deterministically(&ct1, ad).unwrap();

    println!("Plain text: {}", String::from_utf8_lossy(pt));
    assert_eq!(pt, &pt2[..]);
}

#[test]
fn test_deterministic_aead_init() {
    // Check for AES-SIV key manager.
    tink_daead::init();
    assert!(tink::registry::get_key_manager(tink_testutil::AES_SIV_TYPE_URL).is_ok());
}

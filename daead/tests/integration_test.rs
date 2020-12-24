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

    // NOTE: save the keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let d = tink_daead::new(&kh).unwrap();
    let msg = b"this data needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct1 = d.encrypt_deterministically(msg, aad).unwrap();
    let pt = d.decrypt_deterministically(&ct1, aad).unwrap();
    let ct2 = d.encrypt_deterministically(msg, aad).unwrap();

    assert_eq!(ct1, ct2, "ct1 != ct2");

    println!("Ciphertext: {}", base64::encode(&ct1));
    println!("Original  plaintext: {}", std::str::from_utf8(msg).unwrap());
    println!("Decrypted Plaintext: {}", std::str::from_utf8(&pt).unwrap());
    assert_eq!(msg, &pt[..]);
}

#[test]
fn test_deterministic_aead_init() {
    // Check for AES-SIV key manager.
    tink_daead::init();
    assert!(tink::registry::get_key_manager(tink_tests::AES_SIV_TYPE_URL).is_ok());
}

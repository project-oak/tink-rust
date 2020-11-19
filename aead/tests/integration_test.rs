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
fn example() {
    tink_aead::init();
    let kh = tink::keyset::Handle::new(&tink_aead::aes256_gcm_key_template()).unwrap();

    // NOTE: save the keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let a = tink_aead::new(&kh).unwrap();
    let msg = b"this message needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct = a.encrypt(msg, aad).unwrap();
    let pt = a.decrypt(&ct, aad).unwrap();

    println!("Ciphertext: {}", base64::encode(&ct));
    println!("Original  plaintext: {}", std::str::from_utf8(msg).unwrap());
    println!("Decrypted Plaintext: {}", std::str::from_utf8(&pt).unwrap());

    assert_eq!(msg.to_vec(), pt);
}

#[test]
fn test_aead_init() {
    tink_aead::init();

    // Check for AES-GCM key manager.
    tink::registry::get_key_manager(tink_testutil::AES_GCM_TYPE_URL).unwrap();

    // Check for ChaCha20Poly1305 key manager.
    tink::registry::get_key_manager(tink_testutil::CHA_CHA20_POLY1305_TYPE_URL).unwrap();

    // Check for XChaCha20Poly1305 key manager.
    tink::registry::get_key_manager(tink_testutil::X_CHA_CHA20_POLY1305_TYPE_URL).unwrap();
}

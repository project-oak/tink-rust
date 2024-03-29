// Copyright 2020-2021 The Tink-Rust Authors
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
fn example() {
    tink_hybrid::init();
    let kh_priv = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )
    .unwrap();

    // NOTE: save the private keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let kh_pub = kh_priv.public().unwrap();

    // NOTE: share the public keyset with the sender.

    let enc = tink_hybrid::new_encrypt(&kh_pub).unwrap();

    let msg = b"this data needs to be encrypted";
    let encryption_context = b"encryption context";
    let ct = enc.encrypt(msg, encryption_context).unwrap();

    let dec = tink_hybrid::new_decrypt(&kh_priv).unwrap();

    let pt = dec.decrypt(&ct, encryption_context).unwrap();

    println!("Ciphertext: {}", hex::encode(&ct));
    println!("Original  plaintext: {}", std::str::from_utf8(msg).unwrap());
    println!("Decrypted Plaintext: {}", std::str::from_utf8(&pt).unwrap());
    assert_eq!(msg, &pt[..]);

    // Altering either the ciphertext or context results in failure to decrypt.
    let altered_context = b"encryptionXcontext";
    assert!(dec.decrypt(&ct, altered_context).is_err());
    let mut altered_ct = ct;
    altered_ct[0] ^= 0x01;
    assert!(dec.decrypt(&altered_ct, encryption_context).is_err());
}

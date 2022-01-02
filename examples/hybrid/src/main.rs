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

//! Example program demonstrating `tink-hybrid`

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tink_hybrid::init();
    let kh_priv = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )?;

    // NOTE: save the private keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.  See
    // https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let kh_pub = kh_priv.public()?;

    // NOTE: share the public keyset with the sender.

    let enc = tink_hybrid::new_encrypt(&kh_pub)?;

    let msg = b"this data needs to be encrypted";
    let encryption_context = b"encryption context";
    let ct = enc.encrypt(msg, encryption_context)?;

    let dec = tink_hybrid::new_decrypt(&kh_priv)?;

    let pt = dec.decrypt(&ct, encryption_context)?;
    assert_eq!(msg[..], pt);

    println!("Ciphertext: {}\n", hex::encode(&ct));
    println!("Original  plaintext: {}\n", String::from_utf8_lossy(msg));
    println!("Decrypted plaintext: {}\n", String::from_utf8_lossy(&pt));
    Ok(())
}

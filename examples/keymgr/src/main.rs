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

//! Example program demonstrating keyset management.

fn main() {
    tink_aead::init();

    // Create a keyset with a single key in it, and encrypt something.
    let kh = tink::keyset::Handle::new(&tink_aead::aes128_gcm_key_template()).unwrap();
    let cipher = tink_aead::new(&kh).unwrap();
    let ct = cipher.encrypt(b"data", b"aad").unwrap();

    // Move ownership of the `Handle` into a `keyset::Manager`.
    let mut km = tink::keyset::Manager::new_from_handle(kh);

    // Rotate in a new primary key, and add an additional secondary key.
    let key_id_a = km.rotate(&tink_aead::aes256_gcm_key_template()).unwrap();
    let key_id_b = km
        .add(
            &tink_aead::aes256_gcm_key_template(),
            /* primary = */ false,
        )
        .unwrap();

    // Create a new keyset handle for the current state of the managed keyset.
    let kh2 = km.handle().unwrap();
    println!("{:?}", kh2); // debug output does not include key material

    // The original key is still in the keyset, and so can decrypt.
    let cipher2 = tink_aead::new(&kh2).unwrap();
    let pt = cipher2.decrypt(&ct, b"aad").unwrap();
    assert_eq!(pt, b"data");

    // Set the third key to primary and disable the previous primary key.
    km.set_primary(key_id_b).unwrap();
    km.disable(key_id_a).unwrap();
    let kh3 = km.handle().unwrap();
    println!("{:?}", kh3);
}

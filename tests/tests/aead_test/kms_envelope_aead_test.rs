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

fn create_kms_envelope_aead() -> Box<dyn tink_core::Aead> {
    let kh = tink_core::keyset::Handle::new(&tink_aead::aes256_gcm_key_template())
        .expect("failed to create new handle");
    let parent_aead = tink_aead::new(&kh).expect("failed to create parent AEAD");
    Box::new(tink_aead::KmsEnvelopeAead::new(
        tink_aead::aes256_gcm_key_template(),
        parent_aead,
    ))
}

#[test]
fn test_kms_envelope_roundtrip() {
    tink_aead::init();
    let a = create_kms_envelope_aead();

    let original_plaintext = b"hello world";

    let ciphertext = a
        .encrypt(original_plaintext, &[])
        .expect("failed to encrypt");

    let plaintext = a.decrypt(&ciphertext, &[]).expect("failed to decrypt");

    assert_eq!(
        plaintext,
        original_plaintext,
        "Decrypt(Encrypt({})) = {}; want {}",
        hex::encode(&original_plaintext),
        hex::encode(&plaintext),
        hex::encode(&original_plaintext)
    );

    // Can clone the boxed AEAD.
    let a2 = a.box_clone();
    let plaintext = a2.decrypt(&ciphertext, &[]).expect("failed to decrypt");
    assert_eq!(plaintext, original_plaintext,);
}

#[test]
fn test_kms_envelope_short_ciphertext() {
    tink_aead::init();
    let a = create_kms_envelope_aead();

    let result = a.decrypt(&[1], &[]); // not enough data for a 4-byte length header
    tink_tests::expect_err(result, "invalid ciphertext");

    let result = a.decrypt(&[0, 0, 0, 3, 1], &[]); // length of 3, only 1 byte available
    tink_tests::expect_err(result, "invalid ciphertext");
}

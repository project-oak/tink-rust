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

use tink_core::TinkError;

#[test]
fn test_aes_siv_key_template() {
    tink_daead::init();
    let test_cases = vec![("AES256_SIV", tink_daead::aes_siv_key_template())];
    for (name, template) in test_cases {
        let want = tink_tests::key_template_proto("daead", name).unwrap();
        assert_eq!(want, template);
        assert!(test_encrypt_decrypt(&template).is_ok());
    }
}

fn test_encrypt_decrypt(template: &tink_proto::KeyTemplate) -> Result<(), TinkError> {
    let handle = tink_core::keyset::Handle::new(template).unwrap();
    let primitive = tink_daead::new(&handle).unwrap();

    let plaintext = b"some data to encrypt";
    let aad = b"extra data to authenticate";
    let ciphertext = primitive.encrypt_deterministically(plaintext, aad)?;
    let decrypted = primitive.decrypt_deterministically(&ciphertext, aad)?;

    assert_eq!(&plaintext[..], decrypted);
    Ok(())
}

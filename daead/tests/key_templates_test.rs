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

use tink::TinkError;

#[test]
fn test_aes_siv_key_template() {
    tink_daead::init();
    let template = tink_daead::aes_siv_key_template();
    assert_eq!(
        template.type_url,
        tink_testutil::AES_SIV_TYPE_URL,
        "incorrect type url"
    );
    assert!(test_encrypt_decrypt(&template).is_ok());
}

fn test_encrypt_decrypt(template: &tink::proto::KeyTemplate) -> Result<(), TinkError> {
    let sk = tink::registry::new_key(template)?;
    let p = tink::registry::primitive(&template.type_url, &sk)?;

    let primitive = match p {
        tink::Primitive::DeterministicAead(p) => p,
        _ => return Err("failed to find DeterministicAEAD primitive".into()),
    };

    let plaintext = b"some data to encrypt";
    let aad = b"extra data to authenticate";
    let ciphertext = primitive.encrypt_deterministically(plaintext, aad)?;
    let decrypted = primitive.decrypt_deterministically(&ciphertext, aad)?;

    assert_eq!(plaintext.to_vec(), decrypted);
    Ok(())
}

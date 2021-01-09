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

//! Example program demonstrating `tink-awskms`

use std::path::PathBuf;
use tink::{keyset::insecure, registry::KmsClient, AeadBoxClone};

const KEY_URI: &str =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f";
const CRED_INI_FILE: &str = "../../../testdata/credentials_aws.ini";

fn main() {
    tink_aead::init();

    // Generate a new key.
    let kh1 = tink::keyset::Handle::new(&tink_aead::aes256_gcm_key_template()).unwrap();

    // Set up the main key-encryption key at a KMS. This is an AEAD which will generate a new
    // data-encryption key (DEK) for each encryption operation; the DEK is included in the
    // ciphertext emitted from the encryption operation, in encrypted form (encrypted by the
    // KMS main key).
    let kms_client =
        tink_awskms::AwsClient::new_with_credentials(KEY_URI, &PathBuf::from(CRED_INI_FILE))
            .unwrap();
    let backend = kms_client.get_aead(KEY_URI).unwrap();
    let main_key = Box::new(tink_aead::KmsEnvelopeAead::new(
        tink_aead::aes256_gcm_key_template(),
        backend,
    ));

    // The `keyset::Reader` and `keyset::Writer` traits allow for reading/writing a keyset to
    // some kind of store; this particular implementation just holds the keyset in memory.
    let mut mem_keyset = tink::keyset::MemReaderWriter::default();

    // The `Handle::write` method encrypts the keyset that is associated with the handle, using the
    // given AEAD (`main_key`), and then writes the encrypted keyset to the `keyset::Writer`
    // implementation (`mem_keyset`).  We recommend you encrypt the keyset handle before
    // persisting it.
    kh1.write(&mut mem_keyset, main_key.box_clone()).unwrap();
    println!("Encrypted keyset: {:?}", mem_keyset.encrypted_keyset);

    // The `Handle::read` method reads the encrypted keyset back from the `keyset::Reader`
    // implementation and decrypts it using the AEAD used to encrypt it (`main_key`), giving a
    // handle to the recovered keyset.
    let kh2 = tink::keyset::Handle::read(&mut mem_keyset, main_key).unwrap();

    assert_eq!(
        insecure::keyset_material(&kh1),
        insecure::keyset_material(&kh2)
    );
    println!("Key handles are equal.");
}

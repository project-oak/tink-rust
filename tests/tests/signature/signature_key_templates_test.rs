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
fn test_key_templates() {
    tink_signature::init();
    let test_cases = vec![
        (
            "ECDSA_P256",
            tink_signature::ecdsa_p256_key_template(),
            true,
        ),
        (
            "ECDSA_P384",
            #[allow(deprecated)]
            tink_signature::ecdsa_p384_key_template(),
            false,
        ),
        (
            "ECDSA_P384_SHA384",
            tink_signature::ecdsa_p384_sha384_key_template(),
            false,
        ),
        (
            "ECDSA_P521",
            tink_signature::ecdsa_p521_key_template(),
            false,
        ),
        (
            "ECDSA_P256_IEEE_P1363",
            tink_signature::ecdsa_p256_key_p1363_template(),
            true,
        ),
        ("ED25519", tink_signature::ed25519_key_template(), true),
    ];
    for (name, template, supported) in test_cases {
        let want = tink_tests::key_template_proto("signature", name).unwrap();
        assert_eq!(want, template);

        // Check that the same template is registered under the same name.
        let generator = tink_core::registry::get_template_generator(name).unwrap();
        let registered = generator();
        assert_eq!(registered, template);

        // TODO(#16): more ECDSA curves
        if supported {
            assert!(test_sign_verify(&template).is_ok());
        }
    }
}

#[test]
fn test_no_prefix_key_templates() {
    tink_signature::init();
    let test_cases = vec![
        (
            "ECDSA_P256",
            tink_signature::ecdsa_p256_key_without_prefix_template(),
            true,
        ),
        (
            "ECDSA_P384",
            tink_signature::ecdsa_p384_key_without_prefix_template(),
            false,
        ),
        (
            "ECDSA_P521",
            tink_signature::ecdsa_p521_key_without_prefix_template(),
            false,
        ),
        (
            "ED25519",
            tink_signature::ed25519_key_without_prefix_template(),
            true,
        ),
    ];
    for (name, template, supported) in test_cases {
        let mut want = tink_tests::key_template_proto("signature", name).unwrap();
        want.output_prefix_type = tink_proto::OutputPrefixType::Raw as i32;
        assert_eq!(want, template);
        // TODO(#16): more ECDSA curves
        if supported {
            assert!(test_sign_verify(&template).is_ok());
        }
    }
}

fn test_sign_verify(template: &tink_proto::KeyTemplate) -> Result<(), TinkError> {
    let private_handle = tink_core::keyset::Handle::new(template).unwrap();
    let signer = tink_signature::new_signer(&private_handle).unwrap();

    let msg = b"this data needs to be signed";
    let sig = signer.sign(&msg[..]).unwrap();

    let public_handle = private_handle.public().unwrap();
    let verifier = tink_signature::new_verifier(&public_handle).unwrap();
    verifier.verify(&sig, &msg[..])
}

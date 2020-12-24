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

#[test]
fn test_mac_init() {
    tink_mac::init();
    assert!(tink::registry::get_key_manager(tink_tests::HMAC_TYPE_URL).is_ok());
    assert!(tink::registry::get_key_manager(tink_tests::AES_CMAC_TYPE_URL).is_ok());
}

#[test]
fn example() {
    tink_mac::init();
    let kh = tink::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template()).unwrap();

    // NOTE: save the keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let m = tink_mac::new(&kh).unwrap();

    let msg = b"this data needs to be authenticated";
    let tag = m.compute_mac(msg).unwrap();

    assert!(m.verify_mac(&tag, msg).is_ok());
    println!("Message: {}", std::str::from_utf8(msg).unwrap());
    println!("Authentication tag: {}", base64::encode(&tag));
}

#[test]
fn test_legacy_prefix_type() {
    tink_mac::init();
    let mut template = tink_mac::hmac_sha256_tag256_key_template();
    template.output_prefix_type = tink_proto::OutputPrefixType::Legacy as i32;
    let kh = tink::keyset::Handle::new(&template).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let msg = b"this data needs to be authenticated";
    let tag = m.compute_mac(msg).unwrap();

    assert!(m.verify_mac(&tag, msg).is_ok());
    println!("Message: {}", std::str::from_utf8(msg).unwrap());
    println!("Authentication tag: {}", base64::encode(&tag));
}

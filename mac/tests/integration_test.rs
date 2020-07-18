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
fn test_mac_init() {
    tink_mac::init();
    assert!(tink::registry::get_key_manager(tink_testutil::HMAC_TYPE_URL).is_ok());
    assert!(tink::registry::get_key_manager(tink_testutil::AES_CMAC_TYPE_URL).is_ok());
}

#[test]
fn example() {
    tink_mac::init();
    let kh = tink::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template()).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let mac = m.compute_mac(b"this data needs to be MACed").unwrap();

    assert!(m.verify_mac(&mac, b"this data needs to be MACed").is_ok());
}

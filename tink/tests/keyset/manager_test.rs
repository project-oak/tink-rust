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

use tink::keyset::insecure;

#[test]
fn test_keyset_manager_basic() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm = tink::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm.rotate(&kt)
        .expect("cannot rotate when key template is available");
    let h = ksm.handle().expect("cannot get keyset handle");
    let ks = insecure::keyset_material(&h);
    assert_eq!(
        1,
        ks.key.len(),
        "expect the number of keys in the keyset is 1"
    );
    assert_eq!(ks.key[0].key_id, ks.primary_key_id);
    assert_eq!(
        ks.key[0].key_data.as_ref().unwrap().type_url,
        tink_testutil::HMAC_TYPE_URL
    );
    assert_eq!(ks.key[0].status, tink::proto::KeyStatusType::Enabled as i32);
    assert_eq!(
        ks.key[0].output_prefix_type,
        tink::proto::OutputPrefixType::Tink as i32
    );
}

#[test]
fn test_existing_keyset() {
    tink_mac::init();
    // Create a keyset that contains a single `HmacKey`.
    let mut ksm1 = tink::keyset::Manager::new();
    let kt = tink_mac::hmac_sha256_tag128_key_template();
    ksm1.rotate(&kt)
        .expect("cannot rotate when key template is available");

    let h1 = ksm1.handle().expect("cannot get keyset handle");
    let ks1 = insecure::keyset_material(&h1);

    let mut ksm2 = tink::keyset::Manager::new_from_handle(h1);
    ksm2.rotate(&kt).expect("failed to rotate");
    let h2 = ksm2.handle().expect("cannot get keyset handle");
    let ks2 = insecure::keyset_material(&h2);

    assert_eq!(ks2.key.len(), 2, "expect the number of keys to be 2");
    assert_eq!(
        format!("{:?}", ks1.key[0]),
        format!("{:?}", ks2.key[0]),
        "expect the first key in two keysets to be the same"
    );
    assert_eq!(
        ks2.key[1].key_id, ks2.primary_key_id,
        "expect the second key to be primary"
    );
}

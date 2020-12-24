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
fn example() {
    tink_prf::init();
    let kh = tink::keyset::Handle::new(&tink_prf::hmac_sha256_prf_key_template()).unwrap();

    // NOTE: save the keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let ps = tink_prf::Set::new(&kh).unwrap();

    let msg = b"This is an ID needs to be redacted";
    let output = ps.compute_primary_prf(msg, 16).unwrap();

    println!("Message: {}", std::str::from_utf8(msg).unwrap());
    println!("Redacted: {}", base64::encode(&output));
}

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

//! Example program demonstrating `tink-aead`

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tink_aead::init();
    let kh = tink_core::keyset::Handle::new(&tink_aead::aes256_gcm_key_template())?;
    let a = tink_aead::new(&kh)?;

    let pt = b"this data needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct = a.encrypt(pt, aad)?;
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&ct));

    let pt2 = a.decrypt(&ct, aad)?;
    assert_eq!(&pt[..], pt2);
    Ok(())
}

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

//! Example program demonstrating `tink-mac`

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tink_mac::init();
    let kh = tink_core::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template())?;
    let m = tink_mac::new(&kh)?;

    let pt = b"this data needs to be MACed";
    let mac = m.compute_mac(pt)?;
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&mac));

    assert!(m.verify_mac(&mac, b"this data needs to be MACed").is_ok());
    println!("MAC verification succeeded.");
    Ok(())
}

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

//! Example program demonstrating `tink-prf`

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    tink_prf::init();
    let kh = tink_core::keyset::Handle::new(&tink_prf::hmac_sha256_prf_key_template())?;
    let m = tink_prf::Set::new(&kh)?;

    let pt = b"need pseudo-random data deterministically produced from this input";
    let out = m.compute_primary_prf(pt, 16)?;
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&out));
    assert_eq!(out.len(), 16);
    Ok(())
}

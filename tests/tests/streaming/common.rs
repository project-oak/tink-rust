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

use tink_core::{subtle::random::get_random_bytes, utils::wrap_err, TinkError};
use tink_tests::SharedBuf;

pub fn encrypt_decrypt(
    encrypt_cipher: Box<dyn tink_core::StreamingAead>,
    decrypt_cipher: Box<dyn tink_core::StreamingAead>,
    pt_size: usize,
    aad_size: usize,
) -> Result<(), TinkError> {
    let pt = get_random_bytes(pt_size);
    let aad = get_random_bytes(aad_size);

    let buf = SharedBuf::new();
    let mut w = encrypt_cipher
        .new_encrypting_writer(Box::new(buf.clone()), &aad)
        .map_err(|e| wrap_err("cannot create encrypting writer", e))?;
    w.write(&pt)
        .map_err(|e| wrap_err("error writing data", e))?;
    w.close().map_err(|e| wrap_err("error closing writer", e))?;

    let mut r = decrypt_cipher
        .new_decrypting_reader(Box::new(buf), &aad)
        .map_err(|e| wrap_err("cannot create decrypt reader", e))?;
    let mut pt_got = vec![];
    let _n = r
        .read_to_end(&mut pt_got)
        .map_err(|e| wrap_err("decryption failed", e))?;
    if pt != pt_got {
        return Err("decryption failed".into());
    }
    Ok(())
}

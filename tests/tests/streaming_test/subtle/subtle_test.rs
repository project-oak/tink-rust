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

use tink_core::{utils::wrap_err, TinkError};
use tink_tests::SharedBuf;

pub const IKM: &[u8] = &[
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
pub const AAD: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

/// Generate a plaintext of size `plaintext_size` and encrypt it using the `cipher`. Upon success
/// this function returns the actual plaintext and ciphertext bytes.
pub fn encrypt<T: tink_core::StreamingAead>(
    cipher: &T,
    aad: &[u8],
    plaintext_size: usize,
) -> Result<(Vec<u8>, Vec<u8>), TinkError> {
    let mut pt = Vec::with_capacity(plaintext_size);
    for i in 0..plaintext_size {
        pt.push((i % 253) as u8);
    }

    let ct_buf = SharedBuf::new();
    let mut w = cipher
        .new_encrypting_writer(Box::new(ct_buf.clone()), aad)
        .map_err(|e| wrap_err("cannot create an encrypt writer", e))?;
    let n = w
        .write(&pt)
        .map_err(|e| wrap_err("error writing to an encrypt writer", e))?;
    if n != pt.len() {
        return Err(format!(
            "unexpected number of bytes written. got={};want={}",
            n,
            pt.len()
        )
        .into());
    }
    w.close().map_err(|e| wrap_err("error closing writer", e))?;
    Ok((pt, ct_buf.contents()))
}

/// Decrypt ciphertext `ct` using the `cipher` and validate that it's the
/// same as the original plaintext `pt`.
pub fn decrypt<T: tink_core::StreamingAead>(
    cipher: &T,
    aad: &[u8],
    pt: &[u8],
    ct: &[u8],
    chunk_size: usize,
) -> Result<(), TinkError> {
    let mut r = cipher
        .new_decrypting_reader(Box::new(std::io::Cursor::new(ct.to_vec())), aad)
        .map_err(|e| wrap_err("cannot create an encrypt reader", e))?;
    let mut chunk = vec![0; chunk_size];
    let mut decrypted = 0;
    loop {
        let n = r
            .read(&mut chunk)
            .map_err(|e| wrap_err("error reading chunk", e))?;
        if n == 0 {
            // EOF
            break;
        }
        let got = &chunk[..n];
        let want = &pt[decrypted..decrypted + n];
        if got != want {
            return Err(format!(
                "decrypted data doesn't match. got={};want={}",
                hex::encode(&got),
                hex::encode(&want)
            )
            .into());
        }
        decrypted += n;
    }
    if decrypted != pt.len() {
        return Err(format!(
            "number of decrypted bytes doesn't match. Got={};want={}",
            decrypted,
            pt.len()
        )
        .into());
    }
    Ok(())
}

pub fn segment_pos(
    segment_size: usize,
    first_segment_offset: usize,
    header_len: usize,
    segment_nr: usize,
) -> (usize, usize) {
    let mut start = segment_size * segment_nr;
    let mut end = start + segment_size;

    let first_segment_diff = first_segment_offset + header_len;
    if start > 0 {
        start -= first_segment_diff
    }
    end -= first_segment_diff;
    (start + header_len, end + header_len)
}

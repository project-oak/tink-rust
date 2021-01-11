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

//! Example program demonstrating `tink-streaming-aead`

const CHUNK_SIZE: usize = 20;
const PT: &[u8] = b"This is a long string that will be written in chunks to the encrypting writer. It needs to be longer than several of the CHUNK_SIZE chunks, so that there are multiple write operations demonstrated";

fn main() {
    let dir = tempfile::tempdir().unwrap().into_path();
    let ct_filename = dir.join("ciphertext.bin");

    tink_streaming_aead::init();

    // Generate fresh key material.
    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
            .unwrap();

    // Get the primitive that uses the key material.
    let a = tink_streaming_aead::new(&kh).unwrap();

    // Use the primitive to create a [`std::io::Write`] object that writes ciphertext
    // to a file.
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct_file = std::fs::File::create(ct_filename.clone()).unwrap();
    let mut w = a
        .new_encrypting_writer(Box::new(ct_file), &aad[..])
        .unwrap();

    // Write data to the encrypting-writer, in chunks to simulate streaming.
    let mut offset = 0;
    while offset < PT.len() {
        let end = std::cmp::min(PT.len(), offset + CHUNK_SIZE);
        let written = w.write(&PT[offset..end]).unwrap();
        offset += written;
        // Can flush but it does nothing.
        w.flush().unwrap();
    }
    // Complete the encryption (process any remaining buffered plaintext).
    w.close().unwrap();

    // For the other direction, given a [`std::io::Read`] object that reads ciphertext,
    // use the primitive to create a [`std::io::Read`] object that emits the corresponding
    // plaintext.
    let ct_file = std::fs::File::open(ct_filename).unwrap();
    let mut r = a
        .new_decrypting_reader(Box::new(ct_file), &aad[..])
        .unwrap();

    // Read data from the decrypting-reader, in chunks to simulate streaming.
    let mut recovered = vec![];
    loop {
        let mut chunk = vec![0; CHUNK_SIZE];
        let len = r.read(&mut chunk).unwrap();
        if len == 0 {
            break;
        }
        recovered.extend_from_slice(&chunk[..len]);
    }

    assert_eq!(recovered, PT);
}

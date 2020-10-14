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

use std::fs;
use tink::subtle::random::get_random_bytes;
use tink_testutil::SharedBuf;

mod subtle;

#[test]
fn example() {
    tink_streaming_aead::init();
    let dir = tempfile::tempdir().unwrap().into_path();
    let src_filename = dir.join("plaintext.src");
    let ct_filename = dir.join("ciphertext.bin");
    let dst_filename = dir.join("plaintext.dst");
    fs::write(src_filename.clone(), b"this data needs to be encrypted").unwrap();

    let kh = tink::keyset::Handle::new(&tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template())
        .unwrap();

    // NOTE: save the keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.
    // See https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let a = tink_streaming_aead::new(&kh).unwrap();
    let aad = b"this data needs to be authenticated, but not encrypted";
    // Encrypt file.
    let mut src_file = fs::File::open(src_filename).unwrap();
    let ct_file = fs::File::create(ct_filename.clone()).unwrap();
    let mut w = a.new_encrypting_writer(Box::new(ct_file), aad).unwrap();
    std::io::copy(&mut src_file, &mut w).unwrap();
    w.close().unwrap();

    // Decrypt file.
    let ct_file = fs::File::open(ct_filename).unwrap();
    let mut dst_file = fs::File::create(dst_filename.clone()).unwrap();
    let mut r = a.new_decrypting_reader(Box::new(ct_file), aad).unwrap();
    std::io::copy(&mut r, &mut dst_file).unwrap();
    let b = fs::read(dst_filename).unwrap();
    println!("{}", std::str::from_utf8(&b).unwrap());
    // Output: this data needs to be encrypted
}

#[test]
fn streaming_roundtrip_chunks() {
    tink_streaming_aead::init();
    let pt = get_random_bytes(20_000);
    let aad = get_random_bytes(100);

    // Ciphertext segment size is 4096, so try writing in chunks smaller than, bigger than, and
    // equal to that.
    for ct_chunk_size in &[20, 4095, 4096, 4097, 6000] {
        // Plaintext chunk size is 4080 (=4096-16), so try writing in chunks smaller than, bigger
        // than, and equal to that.
        for pt_chunk_size in &[20, 4079, 4080, 4081, 6000] {
            let kh =
                tink::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
                    .unwrap();
            let a = tink_streaming_aead::new(&kh).unwrap();
            let buf = SharedBuf::new();

            // Write data to an encrypting-writer, in chunks to simulate streaming.
            let mut w = a
                .new_encrypting_writer(Box::new(buf.clone()), &aad[..])
                .unwrap();
            let mut offset = 0;
            while offset < pt.len() {
                let end = std::cmp::min(pt.len(), offset + *ct_chunk_size);
                let written = w.write(&pt[offset..end]).unwrap();
                w.flush().unwrap();
                offset += written;
            }
            w.close().unwrap();

            // Read data from a decrypting-reader, in chunks to simulate streaming.
            let mut r = a.new_decrypting_reader(Box::new(buf), &aad[..]).unwrap();
            let mut recovered = vec![];
            loop {
                let mut chunk = vec![0; *pt_chunk_size];
                let len = r.read(&mut chunk).unwrap();
                if len == 0 {
                    break;
                }
                recovered.extend_from_slice(&chunk[..len]);
            }

            assert_eq!(recovered, pt);
        }
    }
}

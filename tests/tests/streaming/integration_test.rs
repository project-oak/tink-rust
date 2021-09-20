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

use rand::Rng;
use std::fs;
use tink_core::subtle::random::get_random_bytes;
use tink_tests::SharedBuf;

#[test]
fn example() {
    tink_streaming_aead::init();
    let dir = tempfile::tempdir().unwrap().into_path();
    let src_filename = dir.join("plaintext.src");
    let ct_filename = dir.join("ciphertext.bin");
    let dst_filename = dir.join("plaintext.dst");
    fs::write(src_filename.clone(), b"this data needs to be encrypted").unwrap();

    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template())
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
fn test_streaming_roundtrip_chunks() {
    tink_streaming_aead::init();
    let pt = get_random_bytes(20_000);
    let aad = get_random_bytes(100);

    // Ciphertext segment size is 4096, so try writing in chunks smaller than, bigger than, and
    // equal to that.
    for ct_chunk_size in &[20, 4095, 4096, 4097, 6000] {
        // Plaintext chunk size is 4080 (=4096-16), so try writing in chunks smaller than, bigger
        // than, and equal to that.
        for pt_chunk_size in &[20, 4079, 4080, 4081, 6000] {
            let kh = tink_core::keyset::Handle::new(
                &tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template(),
            )
            .unwrap();
            let a = tink_streaming_aead::new(&kh).unwrap();
            let buf = SharedBuf::new();

            // Write data to an encrypting-writer, in chunks to simulate streaming.
            let mut w = a
                .new_encrypting_writer(Box::new(buf.clone()), &aad)
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
            let mut r = a.new_decrypting_reader(Box::new(buf), &aad).unwrap();
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

#[test]
fn test_closed_write() {
    tink_streaming_aead::init();
    let pt = get_random_bytes(2000);
    let aad = get_random_bytes(100);

    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
            .unwrap();
    let a = tink_streaming_aead::new(&kh).unwrap();
    let buf = vec![];

    let mut w = a.new_encrypting_writer(Box::new(buf), &aad).unwrap();
    w.write_all(&pt).unwrap();
    w.close().unwrap();

    let result = w.write_all(&pt);
    tink_tests::expect_err(result, "write on closed writer");
}

#[test]
fn test_multiple_failed_read() {
    tink_streaming_aead::init();
    let pt = get_random_bytes(2000);
    let aad = get_random_bytes(100);

    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
            .unwrap();
    let a = tink_streaming_aead::new(&kh).unwrap();
    let buf = SharedBuf::new();

    {
        let mut w = a
            .new_encrypting_writer(Box::new(buf.clone()), &aad)
            .unwrap();
        w.write_all(&pt).unwrap();
        w.close().unwrap();
    }

    // Fail to decrypt-read with a different key.
    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
            .unwrap();
    let a = tink_streaming_aead::new(&kh).unwrap();
    let mut r = a.new_decrypting_reader(Box::new(buf), &aad).unwrap();
    let mut recovered = vec![];
    let result = r.read_to_end(&mut recovered);
    tink_tests::expect_err(result, "no matching key found");
    let result = r.read_to_end(&mut recovered);
    tink_tests::expect_err(result, "read previously failed");
}

const PARTIAL_CHUNK: usize = 17;
struct PartialReader {
    data: Vec<u8>,
    offset: usize,
}

impl PartialReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }
}

impl std::io::Read for PartialReader {
    // Implementation of `read()` that will return less data than requested, even
    // when more data is available. This is valid for Rust's `std::io::Read`, but
    // would not be valid for an `io::Writer` in Go.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if rand::rngs::OsRng.gen_range(0..3) == 0 {
            // Randomly pretend to have been interrupted.
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "fake interrupted",
            ));
        }
        let size = std::cmp::min(
            PARTIAL_CHUNK,
            std::cmp::min(buf.len(), self.data.len() - self.offset),
        );
        buf[..size].copy_from_slice(&self.data[self.offset..self.offset + size]);
        self.offset += size;
        Ok(size)
    }
}

#[test]
fn streaming_partial_reads() {
    tink_streaming_aead::init();
    let pt = get_random_bytes(20_000);
    let aad = get_random_bytes(100);

    let dir = tempfile::tempdir().unwrap().into_path();
    let src_filename = dir.join("plaintext.src");
    let ct_filename = dir.join("ciphertext.bin");
    let dst_filename = dir.join("plaintext.dst");
    fs::write(src_filename.clone(), &pt).unwrap();

    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template())
            .unwrap();

    // Encrypt file.
    let a = tink_streaming_aead::new(&kh).unwrap();
    let mut src_file = fs::File::open(src_filename).unwrap();
    let ct_file = fs::File::create(ct_filename.clone()).unwrap();
    let mut w = a.new_encrypting_writer(Box::new(ct_file), &aad).unwrap();
    std::io::copy(&mut src_file, &mut w).unwrap();
    w.close().unwrap();

    // Decrypt file using a reader that does incomplete read()s.
    let ct = fs::read(ct_filename).unwrap();
    let partial_reader = PartialReader::new(ct);

    let mut dst_file = fs::File::create(dst_filename.clone()).unwrap();
    let mut r = a
        .new_decrypting_reader(Box::new(partial_reader), &aad)
        .unwrap();
    std::io::copy(&mut r, &mut dst_file).unwrap();
    let recovered = fs::read(dst_filename).unwrap();

    assert_eq!(recovered, pt);
}

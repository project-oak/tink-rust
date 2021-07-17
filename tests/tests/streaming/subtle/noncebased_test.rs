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

use std::io::{Read, Write};
use tink_core::{subtle::random::get_random_bytes, utils::wrap_err, EncryptingWrite, TinkError};
use tink_streaming_aead::subtle::noncebased;
use tink_tests::SharedBuf;

#[test]
fn test_nonce_based() {
    struct TestCase {
        name: &'static str,
        plaintext_size: usize,
        nonce_size: usize,
        nonce_prefix_size: usize,
        plaintext_segment_size: usize,
        first_ciphertext_segment_offset: usize,
        chunk_size: usize,
    }
    let test_cases = vec![
        TestCase {
            name: "plaintext_sizeAlignedWithSegment_size",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 20,
            first_ciphertext_segment_offset: 10,
            chunk_size: 5,
        },
        TestCase {
            name: "plaintext_sizeNotAlignedWithSegment_size",
            plaintext_size: 110,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 20,
            first_ciphertext_segment_offset: 10,
            chunk_size: 5,
        },
        TestCase {
            name: "singleSegment",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 100,
            first_ciphertext_segment_offset: 10,
            chunk_size: 5,
        },
        TestCase {
            name: "shortPlaintext",
            plaintext_size: 1,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 100,
            first_ciphertext_segment_offset: 10,
            chunk_size: 5,
        },
        // The next two cases deviate from the upstream Go versions by using a first segment offset
        // of 8 rather than 10. This is because Rust's `std::io::Read` trait has no way to
        // signal a read of zero bytes that is *not* EOF. The upstream parameters have a
        // ciphertext segment of 20 (=10+10) bytes, but on the first segment only 10 bytes
        // are available (=20-10 there, is =20-8 here) which allows exactly the nonce to be read,
        // and zero bytes of plaintext.
        TestCase {
            name: "shortSegment_size",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 10,
            first_ciphertext_segment_offset: 8,
            chunk_size: 5,
        },
        TestCase {
            name: "largeChunk_size",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 10,
            first_ciphertext_segment_offset: 8,
            chunk_size: 500,
        },
    ];
    for tc in test_cases {
        let test_params = TestParams {
            nonce_size: tc.nonce_size,
            plaintext_segment_size: tc.plaintext_segment_size,
            first_ciphertext_segment_offset: tc.first_ciphertext_segment_offset,
        };
        let result = test_encrypt(tc.plaintext_size, tc.nonce_prefix_size, &test_params)
            .unwrap_or_else(|e| panic!("encrypting failed: {}\n", e));

        test_decrypt(
            &result.plaintext,
            &result.ciphertext,
            tc.chunk_size,
            &test_params,
            &result.nonce_prefix,
        )
        .unwrap_or_else(|e| panic!("{}: decrypting failed: {}\n", tc.name, e));
    }
}

struct TestParams {
    nonce_size: usize,
    plaintext_segment_size: usize,
    first_ciphertext_segment_offset: usize,
}

#[test]
fn test_nonce_based_invalid_parameters() {
    struct TestCase {
        name: &'static str,
        plaintext_size: usize,
        nonce_size: usize,
        nonce_prefix_size: usize,
        plaintext_segment_size: usize,
        first_ciphertext_segment_offset: usize,
        chunk_size: usize,
        expected_error: &'static str,
    }
    let test_cases = vec![
        TestCase {
            name: "nonceTooSmall",
            plaintext_size: 100,
            nonce_size: 5,
            nonce_prefix_size: 5,
            plaintext_segment_size: 20,
            first_ciphertext_segment_offset: 10,
            chunk_size: 5,
            expected_error: "nonce size too short",
        },
        TestCase {
            name: "firstSegmentOffsetWayTooLarge",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 20,
            first_ciphertext_segment_offset: 200,
            chunk_size: 5,
            expected_error: "first ciphertext segment offset bigger than ciphertext segment size",
        },
        TestCase {
            name: "firstSegmentIncompleteNonce",
            plaintext_size: 100,
            nonce_size: 10,
            nonce_prefix_size: 5,
            plaintext_segment_size: 10,
            first_ciphertext_segment_offset: 11,
            chunk_size: 5,
            expected_error: "not large enough for full nonce",
        },
    ];
    for tc in test_cases {
        let test_params = TestParams {
            nonce_size: tc.nonce_size,
            plaintext_segment_size: tc.plaintext_segment_size,
            first_ciphertext_segment_offset: tc.first_ciphertext_segment_offset,
        };
        let result = test_encrypt(tc.plaintext_size, tc.nonce_prefix_size, &test_params);
        tink_tests::expect_err_for_case(result, tc.expected_error, tc.name);

        // Prepare empty input for test_decrypt().
        let ciphertext_segment_size = tc.plaintext_segment_size + tc.nonce_size;

        let mut ciphertext_size = tc.first_ciphertext_segment_offset;
        ciphertext_size +=
            (tc.plaintext_size / tc.plaintext_segment_size) * ciphertext_segment_size;
        let plaintext_remainder = tc.plaintext_size % tc.plaintext_segment_size;
        if plaintext_remainder > 0 {
            ciphertext_size += plaintext_remainder + tc.nonce_size
        }

        let nonce_prefix = vec![0; tc.nonce_prefix_size];
        let result = test_decrypt(
            &vec![0; tc.plaintext_size],
            &vec![0; ciphertext_size],
            tc.chunk_size,
            &test_params,
            &nonce_prefix,
        );
        tink_tests::expect_err_for_case(result, tc.expected_error, tc.name);
    }
}

/// `TestEncrypter` is essentially a no-op cipher.
///
/// It produces ciphertexts which contain the plaintext broken into segments,
/// with the unmodified per-segment nonce placed at the end of each segment.
struct TestEncrypter {}

impl noncebased::SegmentEncrypter for TestEncrypter {
    fn encrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError> {
        let mut ciphertext = segment.to_vec();
        ciphertext.extend_from_slice(nonce);
        Ok(ciphertext)
    }
}

struct TestDecrypter {}

impl noncebased::SegmentDecrypter for TestDecrypter {
    fn decrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError> {
        if segment.len() < nonce.len() {
            return Err("segment too short".into());
        }
        let tag_start = segment.len() - nonce.len();
        let tag = &segment[tag_start..];
        if nonce != tag {
            return Err(format!(
                "tag mismatch:\nsegment: {}\nnonce: {}\ntag: {}",
                hex::encode(&segment),
                hex::encode(&nonce),
                hex::encode(&tag)
            )
            .into());
        }
        let result = segment[..tag_start].to_vec();
        Ok(result)
    }
}

#[derive(Debug)]
struct EncryptResult {
    plaintext: Vec<u8>,
    ciphertext: Vec<u8>,
    nonce_prefix: Vec<u8>,
}

/// Generate a random plaintext and random `nonce_prefix`, then use
/// them to instantiate a [`noncebased::Writer`] and uses it to produce a ciphertext.
///
/// The plaintext, ciphertext and nonce prefix are returned.
fn test_encrypt(
    plaintext_size: usize,
    nonce_prefix_size: usize,
    params: &TestParams,
) -> Result<EncryptResult, TinkError> {
    let dst = SharedBuf::new();

    let nonce_prefix = get_random_bytes(nonce_prefix_size);

    let wp = noncebased::WriterParams {
        w: Box::new(dst.clone()),
        segment_encrypter: Box::new(TestEncrypter {}),
        nonce_size: params.nonce_size,
        nonce_prefix: nonce_prefix.clone(),
        plaintext_segment_size: params.plaintext_segment_size,
        first_ciphertext_segment_offset: params.first_ciphertext_segment_offset,
    };
    let mut w = noncebased::Writer::new(wp)?;

    let plaintext = get_random_bytes(plaintext_size);

    w.write(&plaintext)
        .map_err(|e| wrap_err("write failed", e))?;
    w.close().map_err(|e| wrap_err("close failed", e))?;
    let ciphertext = dst.contents();

    Ok(EncryptResult {
        plaintext,
        ciphertext,
        nonce_prefix,
    })
}

/// Instantiate a [`noncebased::Reader`], uses it to decrypt `ciphertext`
/// and verifies it matches `plaintext`. While decrypting, it reads in `chunk_size`
/// increments.
fn test_decrypt(
    plaintext: &[u8],
    ciphertext: &[u8],
    chunk_size: usize,
    params: &TestParams,
    nonce_prefix: &[u8],
) -> Result<(), TinkError> {
    let rp = noncebased::ReaderParams {
        r: Box::new(std::io::Cursor::new(ciphertext.to_vec())),
        segment_decrypter: Box::new(TestDecrypter {}),
        nonce_size: params.nonce_size,
        nonce_prefix: nonce_prefix.to_vec(),
        ciphertext_segment_size: params.plaintext_segment_size + params.nonce_size,
        first_ciphertext_segment_offset: params.first_ciphertext_segment_offset,
    };
    let mut r = noncebased::Reader::new(rp)?;

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
        let want = &plaintext[decrypted..decrypted + n];
        if got != want {
            return Err(format!(
                "decrypted data does not match. Got={};want={}",
                hex::encode(&got),
                hex::encode(&want)
            )
            .into());
        }
        decrypted += n;
    }
    if decrypted != plaintext.len() {
        return Err(format!(
            "number of decrypted bytes does not match. Got={},want={}",
            decrypted,
            plaintext.len()
        )
        .into());
    }
    Ok(())
}

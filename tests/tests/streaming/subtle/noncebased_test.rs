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
                hex::encode(segment),
                hex::encode(nonce),
                hex::encode(tag)
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
                hex::encode(got),
                hex::encode(want)
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

/// Initial size of the lazily-allocated segment buffers in `noncebased`. The tests below probe
/// plaintext and ciphertext sizes around this boundary; if the constant changes, they still
/// pass but no longer pin the boundary itself.
const INITIAL_BUFFER_SIZE: usize = 4096;

/// A reader that returns at most one byte per `read` call.
struct OneByteReader<R: Read>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0.read(&mut buf[..1])
    }
}

/// A reader that fails every other `read` call with [`std::io::ErrorKind::Interrupted`].
struct InterruptedReader<R: Read> {
    inner: R,
    interrupt_next: bool,
}

impl<R: Read> Read for InterruptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.interrupt_next = !self.interrupt_next;
        if self.interrupt_next {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "interrupted",
            ));
        }
        self.inner.read(buf)
    }
}

/// Exercise the lazily-grown ciphertext buffer in [`noncebased::Reader`] at ciphertext and
/// segment sizes around the initial buffer size and its growth steps.
#[test]
fn test_read_with_small_initial_buffer() {
    const NONCE_SIZE: usize = 10;
    const NONCE_PREFIX_SIZE: usize = 5;
    // With `TestEncrypter` a ciphertext segment is its plaintext segment plus `NONCE_SIZE`
    // trailing bytes, so a single-segment ciphertext of size S corresponds to a plaintext of
    // size S - NONCE_SIZE.
    struct TestCase {
        name: &'static str,
        plaintext_size: usize,
        plaintext_segment_size: usize,
        first_ciphertext_segment_offset: usize,
        chunk_size: usize,
        one_byte_reads: bool,
        interrupted_reads: bool,
    }
    let test_cases = vec![
        TestCase {
            name: "singleSegmentCiphertextJustBelowInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE - 1, // ciphertext: 4095 bytes
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "singleSegmentCiphertextExactlyInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE, // ciphertext: 4096 bytes
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "singleSegmentCiphertextJustAboveInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE + 1, // ciphertext: 4097 bytes
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "singleSegmentCiphertextWellAboveInitialBuffer",
            plaintext_size: 100_000,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        // A ciphertext that ends exactly at a grown buffer size.
        TestCase {
            name: "singleSegmentCiphertextExactlySecondBufferSize",
            plaintext_size: 32768 - NONCE_SIZE,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "emptyPlaintextLargeSegmentSize",
            plaintext_size: 0,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        // Ciphertext segments of exactly INITIAL_BUFFER_SIZE - 1: the buffer limit equals the
        // initial size, so the buffer never grows and every non-final segment fills it
        // completely.
        TestCase {
            name: "multiSegmentCiphertextSegmentJustBelowInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE - 1) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE - 1,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        // Ciphertext segments of exactly INITIAL_BUFFER_SIZE: the buffer limit is
        // INITIAL_BUFFER_SIZE + 1, so the very first segment grows the buffer by a single byte.
        TestCase {
            name: "multiSegmentCiphertextSegmentExactlyInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "multiSegmentCiphertextSegmentJustAboveInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE + 1) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE + 1,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        // A segment large enough that the buffer walks the whole growth sequence, ending with
        // the jump to the full buffer size, and then completes segments in the fully-grown
        // buffer.
        TestCase {
            name: "multiSegmentRequiringMultipleGrowthSteps",
            plaintext_size: (1 << 20) + 100,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        // A plaintext that ends exactly at a segment boundary, so the last ciphertext segment
        // is a full-sized segment.
        TestCase {
            name: "multiSegmentPlaintextAlignedWithSegmentSize",
            plaintext_size: 2 * (INITIAL_BUFFER_SIZE - NONCE_SIZE),
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "firstSegmentOffsetWithCiphertextAtInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 10,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "firstSegmentOffsetWithMultipleSegmentsAtInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            first_ciphertext_segment_offset: 10,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: false,
        },
        TestCase {
            name: "oneByteReadsAcrossGrowBoundary",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE + 1,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: true,
            interrupted_reads: false,
        },
        TestCase {
            name: "oneByteReadsMultiSegment",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            first_ciphertext_segment_offset: 0,
            chunk_size: 7,
            one_byte_reads: true,
            interrupted_reads: false,
        },
        TestCase {
            name: "interruptedReadsAcrossGrowBoundary",
            plaintext_size: INITIAL_BUFFER_SIZE - NONCE_SIZE + 1,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: true,
            interrupted_reads: true,
        },
        TestCase {
            name: "interruptedReadsMultiSegment",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - NONCE_SIZE) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - NONCE_SIZE,
            first_ciphertext_segment_offset: 0,
            chunk_size: 1000,
            one_byte_reads: false,
            interrupted_reads: true,
        },
    ];
    for tc in test_cases {
        let test_params = TestParams {
            nonce_size: NONCE_SIZE,
            plaintext_segment_size: tc.plaintext_segment_size,
            first_ciphertext_segment_offset: tc.first_ciphertext_segment_offset,
        };
        let result = test_encrypt(tc.plaintext_size, NONCE_PREFIX_SIZE, &test_params)
            .unwrap_or_else(|e| panic!("{}: encrypting failed: {}", tc.name, e));

        let mut r: Box<dyn Read> = Box::new(std::io::Cursor::new(result.ciphertext));
        if tc.one_byte_reads {
            r = Box::new(OneByteReader(r));
        }
        if tc.interrupted_reads {
            r = Box::new(InterruptedReader {
                inner: r,
                interrupt_next: false,
            });
        }
        let mut reader = noncebased::Reader::new(noncebased::ReaderParams {
            r,
            segment_decrypter: Box::new(TestDecrypter {}),
            nonce_size: NONCE_SIZE,
            nonce_prefix: result.nonce_prefix,
            ciphertext_segment_size: tc.plaintext_segment_size + NONCE_SIZE,
            first_ciphertext_segment_offset: tc.first_ciphertext_segment_offset,
        })
        .unwrap_or_else(|e| panic!("{}: Reader::new failed: {}", tc.name, e));

        let mut decrypted = Vec::new();
        let mut chunk = vec![0; tc.chunk_size];
        loop {
            let n = reader
                .read(&mut chunk)
                .unwrap_or_else(|e| panic!("{}: read failed: {}", tc.name, e));
            if n == 0 {
                break;
            }
            decrypted.extend_from_slice(&chunk[..n]);
        }
        assert_eq!(
            decrypted, result.plaintext,
            "{}: decrypted data does not match plaintext",
            tc.name
        );
    }
}

/// Truncated ciphertexts at boundaries around the initial buffer size must fail regardless of
/// where the truncation falls relative to a buffer growth step.
#[test]
fn test_read_truncated_ciphertext() {
    const NONCE_SIZE: usize = 10;
    const NONCE_PREFIX_SIZE: usize = 5;
    let plaintext_segment_size = INITIAL_BUFFER_SIZE - NONCE_SIZE;
    let test_params = TestParams {
        nonce_size: NONCE_SIZE,
        plaintext_segment_size,
        first_ciphertext_segment_offset: 0,
    };
    let result = test_encrypt(
        3 * plaintext_segment_size + 100,
        NONCE_PREFIX_SIZE,
        &test_params,
    )
    .unwrap_or_else(|e| panic!("encrypting failed: {}", e));

    struct TestCase {
        truncate: usize,
        want_err: bool,
    }
    let test_cases = vec![
        TestCase {
            truncate: 1,
            want_err: true,
        },
        TestCase {
            truncate: 4095,
            want_err: true,
        },
        TestCase {
            truncate: 4096,
            want_err: true,
        },
        TestCase {
            truncate: result.ciphertext.len() - 1,
            want_err: true,
        },
    ];
    for tc in test_cases {
        let mut reader = noncebased::Reader::new(noncebased::ReaderParams {
            r: Box::new(std::io::Cursor::new(
                result.ciphertext[..tc.truncate].to_vec(),
            )),
            segment_decrypter: Box::new(TestDecrypter {}),
            nonce_size: NONCE_SIZE,
            nonce_prefix: result.nonce_prefix.clone(),
            ciphertext_segment_size: plaintext_segment_size + NONCE_SIZE,
            first_ciphertext_segment_offset: 0,
        })
        .unwrap_or_else(|e| panic!("truncatedAt{}: Reader::new failed: {}", tc.truncate, e));
        let mut decrypted = Vec::new();
        let got_err = reader.read_to_end(&mut decrypted).is_err();
        assert_eq!(
            got_err, tc.want_err,
            "truncatedAt{}: read_to_end error mismatch",
            tc.truncate
        );
    }
}

/// Exercise the lazily-grown plaintext buffer in [`noncebased::Writer`] at plaintext and
/// segment sizes around the initial buffer size and its growth steps. Each case also checks
/// that chunked writes produce ciphertext byte-identical to a single write of the whole
/// plaintext.
#[test]
fn test_write_with_small_initial_buffer() {
    const NONCE_SIZE: usize = 10;
    const NONCE_PREFIX_SIZE: usize = 5;
    struct TestCase {
        name: &'static str,
        plaintext_size: usize,
        plaintext_segment_size: usize,
        first_ciphertext_segment_offset: usize,
        write_chunk_size: usize,
    }
    let test_cases = vec![
        TestCase {
            name: "singleSegmentPlaintextJustBelowInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE - 1,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "singleSegmentPlaintextExactlyInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "singleSegmentPlaintextJustAboveInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE + 1,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "singleSegmentPlaintextWellAboveInitialBuffer",
            plaintext_size: 100_000,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "emptyPlaintextLargeSegmentSize",
            plaintext_size: 0,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        // Plaintext segments of exactly INITIAL_BUFFER_SIZE - 1: the buffer never grows and
        // every non-final segment fills it completely.
        TestCase {
            name: "multiSegmentSegmentJustBelowInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE - 1) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE - 1,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "multiSegmentSegmentExactlyInitialBuffer",
            plaintext_size: 3 * INITIAL_BUFFER_SIZE + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        // Plaintext segments of INITIAL_BUFFER_SIZE + 1: the very first segment grows the
        // buffer by a single byte.
        TestCase {
            name: "multiSegmentSegmentJustAboveInitialBuffer",
            plaintext_size: 3 * (INITIAL_BUFFER_SIZE + 1) + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE + 1,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        // A segment large enough that the buffer walks the whole growth sequence, ending with
        // the jump to the full segment size, and then completes segments in the fully-grown
        // buffer.
        TestCase {
            name: "multiSegmentRequiringMultipleGrowthSteps",
            plaintext_size: (1 << 20) + 100,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        // A first write large enough that the buffer is sized to the pending data exactly,
        // followed by writes that grow it from that intermediate size and complete segments.
        TestCase {
            name: "largeFirstWriteThenGrowthFromOddSize",
            plaintext_size: (1 << 20) + 100,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 500_000,
        },
        TestCase {
            name: "mediumWritesGrowingFromOddSizes",
            plaintext_size: (1 << 20) + 100,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 65536,
        },
        // A plaintext that ends exactly at a segment boundary: `write` defers the
        // exactly-filled segment, and `close` emits it as the last segment.
        TestCase {
            name: "multiSegmentPlaintextAlignedWithSegmentSize",
            plaintext_size: 2 * INITIAL_BUFFER_SIZE,
            plaintext_segment_size: INITIAL_BUFFER_SIZE,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1000,
        },
        // A single write that fills the initial buffer exactly without completing a segment,
        // followed directly by `close`.
        TestCase {
            name: "singleWriteFillingInitialBufferThenClose",
            plaintext_size: INITIAL_BUFFER_SIZE,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: INITIAL_BUFFER_SIZE,
        },
        TestCase {
            name: "firstSegmentOffsetWithPlaintextAtInitialBuffer",
            plaintext_size: INITIAL_BUFFER_SIZE,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 10,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "firstSegmentOffsetWithMultipleSegmentsAtInitialBuffer",
            plaintext_size: 3 * INITIAL_BUFFER_SIZE + 100,
            plaintext_segment_size: INITIAL_BUFFER_SIZE,
            first_ciphertext_segment_offset: 10,
            write_chunk_size: 1000,
        },
        TestCase {
            name: "oneByteWritesAcrossGrowBoundary",
            plaintext_size: INITIAL_BUFFER_SIZE + 1,
            plaintext_segment_size: 1 << 20,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1,
        },
        TestCase {
            name: "oneByteWritesMultiSegment",
            plaintext_size: 2 * INITIAL_BUFFER_SIZE + 50,
            plaintext_segment_size: INITIAL_BUFFER_SIZE,
            first_ciphertext_segment_offset: 0,
            write_chunk_size: 1,
        },
    ];

    let encrypt_chunked = |plaintext: &[u8],
                           nonce_prefix: &[u8],
                           segment_size: usize,
                           offset: usize,
                           chunk_size: usize|
     -> Vec<u8> {
        let dst = SharedBuf::new();
        let mut w = noncebased::Writer::new(noncebased::WriterParams {
            w: Box::new(dst.clone()),
            segment_encrypter: Box::new(TestEncrypter {}),
            nonce_size: NONCE_SIZE,
            nonce_prefix: nonce_prefix.to_vec(),
            plaintext_segment_size: segment_size,
            first_ciphertext_segment_offset: offset,
        })
        .expect("Writer::new failed");
        for chunk in plaintext.chunks(chunk_size) {
            w.write_all(chunk).expect("write failed");
        }
        w.close().expect("close failed");
        dst.contents()
    };

    for tc in test_cases {
        let plaintext = get_random_bytes(tc.plaintext_size);
        let nonce_prefix = get_random_bytes(NONCE_PREFIX_SIZE);

        let ciphertext = encrypt_chunked(
            &plaintext,
            &nonce_prefix,
            tc.plaintext_segment_size,
            tc.first_ciphertext_segment_offset,
            tc.write_chunk_size,
        );
        let single_write = encrypt_chunked(
            &plaintext,
            &nonce_prefix,
            tc.plaintext_segment_size,
            tc.first_ciphertext_segment_offset,
            tc.plaintext_size + 1,
        );
        assert_eq!(
            ciphertext, single_write,
            "{}: chunked writes produced different ciphertext from a single write",
            tc.name
        );

        let test_params = TestParams {
            nonce_size: NONCE_SIZE,
            plaintext_segment_size: tc.plaintext_segment_size,
            first_ciphertext_segment_offset: tc.first_ciphertext_segment_offset,
        };
        test_decrypt(&plaintext, &ciphertext, 1000, &test_params, &nonce_prefix)
            .unwrap_or_else(|e| panic!("{}: decrypting failed: {}", tc.name, e));
    }
}

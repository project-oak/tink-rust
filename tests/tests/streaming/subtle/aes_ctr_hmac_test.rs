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

use tink_streaming_aead::subtle;

#[test]
fn test_aes_ctr_hmac_encrypt_decrypt() {
    struct TestCase {
        name: &'static str,
        key_size_in_bytes: usize,
        tag_size_in_bytes: usize,
        segment_size: usize,
        first_segment_offset: usize,
        plaintext_size: usize,
        chunk_size: usize,
    }
    let test_cases = vec![
        TestCase {
            name: "small-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 20,
            chunk_size: 64,
        },
        TestCase {
            name: "small-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 0,
            plaintext_size: 400,
            chunk_size: 64,
        },
        TestCase {
            name: "small-offset-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 8,
            plaintext_size: 20,
            chunk_size: 64,
        },
        TestCase {
            name: "small-offset-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 8,
            plaintext_size: 400,
            chunk_size: 64,
        },
        TestCase {
            name: "empty-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 0,
            chunk_size: 128,
        },
        TestCase {
            name: "empty-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 8,
            plaintext_size: 0,
            chunk_size: 128,
        },
        TestCase {
            name: "medium-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 1024,
            chunk_size: 128,
        },
        TestCase {
            name: "medium-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 0,
            plaintext_size: 3086,
            chunk_size: 128,
        },
        TestCase {
            name: "medium-3",
            key_size_in_bytes: 32,
            tag_size_in_bytes: 12,
            segment_size: 1024,
            first_segment_offset: 0,
            plaintext_size: 12345,
            chunk_size: 128,
        },
        TestCase {
            name: "large-chunks-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 1024,
            chunk_size: 4096,
        },
        TestCase {
            name: "large-chunks-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 0,
            plaintext_size: 5086,
            chunk_size: 4096,
        },
        TestCase {
            name: "large-chunks-3",
            key_size_in_bytes: 32,
            tag_size_in_bytes: 12,
            segment_size: 1024,
            first_segment_offset: 0,
            plaintext_size: 12345,
            chunk_size: 5000,
        },
        TestCase {
            name: "medium-offset-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 8,
            plaintext_size: 1024,
            chunk_size: 64,
        },
        TestCase {
            name: "medium-offset-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 20,
            plaintext_size: 3086,
            chunk_size: 256,
        },
        TestCase {
            name: "medium-offset-3",
            key_size_in_bytes: 32,
            tag_size_in_bytes: 12,
            segment_size: 1024,
            first_segment_offset: 10,
            plaintext_size: 12345,
            chunk_size: 5000,
        },
        TestCase {
            name: "last-segment-full-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 216,
            chunk_size: 64,
        },
        TestCase {
            name: "last-segment-full-2",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 16,
            plaintext_size: 200,
            chunk_size: 256,
        },
        TestCase {
            name: "last-segment-full-3",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 16,
            plaintext_size: 440,
            chunk_size: 1024,
        },
        TestCase {
            name: "single-byte-1",
            key_size_in_bytes: 16,
            tag_size_in_bytes: 12,
            segment_size: 256,
            first_segment_offset: 0,
            plaintext_size: 1024,
            chunk_size: 1,
        },
        TestCase {
            name: "single-byte-2",
            key_size_in_bytes: 32,
            tag_size_in_bytes: 12,
            segment_size: 512,
            first_segment_offset: 0,
            plaintext_size: 5086,
            chunk_size: 1,
        },
    ];

    for tc in test_cases {
        let cipher = subtle::AesCtrHmac::new(
            super::IKM,
            tink_proto::HashType::Sha256,
            tc.key_size_in_bytes,
            tink_proto::HashType::Sha256,
            tc.tag_size_in_bytes,
            tc.segment_size,
            tc.first_segment_offset,
        )
        .unwrap_or_else(|e| panic!("{}: cannot create cipher: {:?}", tc.name, e));
        let (pt, ct) = super::encrypt(&cipher, super::AAD, tc.plaintext_size)
            .unwrap_or_else(|e| panic!("{}: failure during encryption: {:?}", tc.name, e));
        assert!(
            super::decrypt(&cipher, super::AAD, &pt, &ct, tc.chunk_size).is_ok(),
            "{}: failure during decryption",
            tc.name
        );
    }
}

#[test]
fn test_aes_ctr_hmac_modified_ciphertext() {
    let ikm =
        hex::decode("000102030405060708090a0b0c0d0e0f00112233445566778899aabbccddeeff").unwrap();
    let aad = hex::decode("aabbccddeeff").unwrap();

    let key_size_in_bytes = 16;
    let tag_size_in_bytes = 12;
    let segment_size = 256;
    let first_segment_offset = 8;
    let plaintext_size = 1024;
    let chunk_size = 128;

    let cipher = subtle::AesCtrHmac::new(
        &ikm,
        tink_proto::HashType::Sha256,
        key_size_in_bytes,
        tink_proto::HashType::Sha256,
        tag_size_in_bytes,
        segment_size,
        first_segment_offset,
    )
    .expect("Cannot create a cipher");

    let (pt, ct) = super::encrypt(&cipher, &aad, plaintext_size).unwrap();

    // truncate ciphertext
    for i in (0..ct.len()).step_by(8) {
        assert!(
            super::decrypt(&cipher, &aad, &pt, &ct[..i], chunk_size).is_err(),
            "expected error"
        );
    }
    // append to ciphertext
    let sizes = vec![1, segment_size - ct.len() % segment_size, segment_size];
    for size in sizes {
        let mut ct2 = ct.clone();
        ct2.extend_from_slice(&vec![0; size]);
        assert!(
            super::decrypt(&cipher, &aad, &pt, &ct2, chunk_size).is_err(),
            "expected error"
        );
    }
    // flip bits
    for i in 0..ct.len() {
        let mut ct2 = ct.clone();
        ct2[i] ^= 0x01;
        assert!(
            super::decrypt(&cipher, &aad, &pt, &ct2, chunk_size).is_err(),
            "expected error"
        );
    }
    // delete segments
    for i in 0..ct.len() / segment_size + 1 {
        let (start, mut end) = super::segment_pos(
            segment_size,
            first_segment_offset,
            cipher.header_length(),
            i,
        );
        if start > ct.len() {
            break;
        }
        if end > ct.len() {
            end = ct.len()
        }
        let mut ct2 = ct[..start].to_vec();
        ct2.extend_from_slice(&ct[end..]);
        assert!(
            super::decrypt(&cipher, &aad, &pt, &ct2, chunk_size).is_err(),
            "expected error"
        );
    }
    // duplicate segments
    for i in 0..ct.len() / segment_size + 1 {
        let (start, mut end) = super::segment_pos(
            segment_size,
            first_segment_offset,
            cipher.header_length(),
            i,
        );
        if start > ct.len() {
            break;
        }
        if end > ct.len() {
            end = ct.len()
        }
        let mut ct2 = (&ct[..end]).to_vec();
        ct2.extend_from_slice(&ct[start..]);
        assert!(
            super::decrypt(&cipher, &aad, &pt, &ct2, chunk_size).is_err(),
            "expected error"
        );
    }
    // modify aad
    for i in 0..aad.len() {
        let mut aad2 = aad.clone();
        aad2[i] ^= 0x01;
        assert!(
            super::decrypt(&cipher, &aad2, &pt, &ct, chunk_size).is_err(),
            "expected error"
        );
    }
}

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

//! Provide a reusable streaming AEAD framework.
//!
//! It tackles the segment handling portions of the nonce based online
//! encryption scheme proposed in "Online Authenticated-Encryption and its
//! Nonce-Reuse Misuse-Resistance" by Hoang, Reyhanitabar, Rogaway and Vizár
//! (<https://eprint.iacr.org/2015/189.pdf>).
//!
//! In this scheme, the format of a ciphertext is:
//!
//!   header || segment_0 || segment_1 || ... || segment_k.
//!
//! The format of header is:
//!
//!   header_length || salt || nonce_prefix
//!
//! header_length is 1 byte which documents the size of the header and can be
//! obtained via header_length(). In principle, header_length is redundant
//! information, since the length of the header can be determined from the key
//! size.
//!
//! salt is a salt used in the key derivation.
//!
//! nonce_prefix is a prefix for all per-segment nonces.
//!
//! segment_i is the i-th segment of the ciphertext. The size of segment_1 ..
//! segment_{k-1} is ciphertextSegmentSize. segment_0 is shorter, so that
//! segment_0 plus additional data of size firstCiphertextSegmentOffset (e.g.
//! the header) aligns with ciphertextSegmentSize.
//!
//! The first segment size will be:
//!
//!   ciphertext_segment_size - header_length() - first_ciphertext_segment_offset.

use std::{convert::TryFrom, io};
use tink_core::{utils::wrap_err, EncryptingWrite, TinkError};

/// `SegmentEncrypter` facilitates implementing various streaming AEAD encryption modes.
pub trait SegmentEncrypter {
    fn encrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError>;
}

/// `Writer` provides a framework for ingesting plaintext data and
/// writing encrypted data to the wrapped [`io::Write`]. The scheme used for
/// encrypting segments is specified by providing a `SegmentEncrypter`
/// implementation.
pub struct Writer {
    w: Box<dyn io::Write>,
    segment_encrypter: Box<dyn SegmentEncrypter>,
    encrypted_segment_cnt: u64,
    first_ciphertext_segment_offset: usize,
    nonce_size: usize,
    nonce_prefix: Vec<u8>,
    /// Buffer to hold incomplete segments of plaintext, until they are complete and
    /// ready for encryption.
    plaintext: Vec<u8>,
    /// Next free position in `plaintext`.
    plaintext_pos: usize,
    /// A final smaller segment can be written by calling `close()`, but after that
    /// no more data can be written.
    closed: bool,
}

/// `WriterParams` contains the options for instantiating a `Writer` via `Writer::new()`.
pub struct WriterParams {
    /// `w` is the underlying writer being wrapped.
    pub w: Box<dyn io::Write>,

    /// `segment_encrypter` provides a method for encrypting segments.
    pub segment_encrypter: Box<dyn SegmentEncrypter>,

    /// `nonce_size` is the length of generated nonces. It must be at least 5 +
    /// `nonce_prefix.len()`. It can be longer, but longer nonces introduce more
    /// overhead in the resultant ciphertext.
    pub nonce_size: usize,

    /// `nonce_prefix` is a constant that all nonces throughout the ciphertext will
    /// start with. Its length must be at least 5 bytes shorter than `nonce_size`.
    pub nonce_prefix: Vec<u8>,

    /// The size of the segments which the plaintext will be split into.
    pub plaintext_segment_size: usize,

    /// `first_ciphertex_segment_offset` indicates where the ciphertext should begin in
    /// `w`. This allows for the existence of overhead in the stream unrelated to
    /// this encryption scheme.
    pub first_ciphertext_segment_offset: usize,
}

impl Writer {
    /// Create a new Writer instance.
    pub fn new(params: WriterParams) -> Result<Writer, TinkError> {
        if params.nonce_size - params.nonce_prefix.len() < 5 {
            return Err("nonce size too short".into());
        }
        let ct_size = params.plaintext_segment_size + params.nonce_size;
        match ct_size.checked_sub(params.first_ciphertext_segment_offset) {
            None => {
                return Err(
                    "first ciphertext segment offset bigger than ciphertext segment size".into(),
                )
            }
            Some(sz) if sz <= params.nonce_size => {
                return Err("first ciphertext segment not large enough for full nonce".into())
            }
            _ => {}
        }
        Ok(Writer {
            w: params.w,
            segment_encrypter: params.segment_encrypter,
            encrypted_segment_cnt: 0,
            first_ciphertext_segment_offset: params.first_ciphertext_segment_offset,
            nonce_size: params.nonce_size,
            nonce_prefix: params.nonce_prefix,
            plaintext: vec![0; params.plaintext_segment_size],
            plaintext_pos: 0,
            closed: false,
        })
    }
}

impl io::Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write on closed writer",
            ));
        }

        let mut pos = 0; // read position in input plaintext (`buf`)
        loop {
            // Move a chunk of the input plaintext into the internal buffer.
            let mut pt_lim = self.plaintext.len();
            if self.encrypted_segment_cnt == 0 {
                pt_lim -= self.first_ciphertext_segment_offset
            }

            let n = std::cmp::min(pt_lim - self.plaintext_pos, buf.len() - pos);
            self.plaintext[self.plaintext_pos..self.plaintext_pos + n]
                .copy_from_slice(&buf[pos..pos + n]);

            self.plaintext_pos += n;
            pos += n;
            if pos == buf.len() {
                // All of the input plaintext has been consumed, but some (less than a segment's
                // worth) may be still be pending-encryption, held in
                // `self.plaintext`. It will be emitted on another `write()` (or by
                // `close()`).
                break;
            }

            // At this point there is a full segment's worth of plaintext in
            // `self.plaintext[..pt_lim]`, ready to encrypt and write out.
            if self.plaintext_pos != pt_lim {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "internal error: pos={} != pt_lim={}",
                        self.plaintext_pos, pt_lim
                    ),
                ));
            }
            let nonce = generate_segment_nonce(
                self.nonce_size,
                &self.nonce_prefix,
                self.encrypted_segment_cnt,
                /* last= */ false,
            )?;

            let ciphertext = self
                .segment_encrypter
                .encrypt_segment(&self.plaintext[..pt_lim], &nonce)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;
            self.w.write_all(&ciphertext)?;

            // Ready to accumulate next segment.
            self.plaintext_pos = 0;
            self.encrypted_segment_cnt += 1;
        }
        Ok(pos)
    }

    /// Flushing an encrypting writer does nothing even when there is buffered plaintext,
    /// because only complete segments can be written.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl EncryptingWrite for Writer {
    fn close(&mut self) -> Result<(), TinkError> {
        if self.closed {
            return Ok(());
        }

        let nonce = generate_segment_nonce(
            self.nonce_size,
            &self.nonce_prefix,
            self.encrypted_segment_cnt,
            /* last= */ true,
        )
        .map_err(|e| wrap_err("internal error", e))?;
        let ciphertext = self
            .segment_encrypter
            .encrypt_segment(&self.plaintext[..self.plaintext_pos], &nonce)?;
        self.w
            .write_all(&ciphertext)
            .map_err(|e| wrap_err("write failure", e))?;

        self.plaintext_pos = 0;
        self.encrypted_segment_cnt += 1;
        self.closed = true;
        Ok(())
    }
}

/// Manual [`Drop`] implementation which ensures the stream is closed.
impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// `SegmentDecrypter` facilitates implementing various streaming AEAD encryption modes.
pub trait SegmentDecrypter {
    fn decrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError>;
}

/// `Reader` facilitates the decryption of ciphertexts created using a [`Writer`].
///
/// The scheme used for decrypting segments is specified by providing a
/// [`SegmentDecrypter`] implementation. The implementation must align
/// with the [`SegmentEncrypter`] used in the [`Writer`].
pub struct Reader {
    r: Box<dyn io::Read>,
    segment_decrypter: Box<dyn SegmentDecrypter>,
    decrypted_segment_cnt: u64,
    first_ciphertext_segment_offset: usize,
    nonce_size: usize,
    nonce_prefix: Vec<u8>,
    /// `plaintext` holds data that has already been decrypted, and `plaintext_pos`
    /// indicates the part of it that has not yet been returns from a `read` operation.
    plaintext: Vec<u8>,
    plaintext_pos: usize,
    /// `ciphertext` is a fixed-size buffer that holds encrypted data that has already been read
    /// from `r`.
    ciphertext: Vec<u8>,

    ciphertext_pos: usize,
}

/// `ReaderParams` contains the options for instantiating a [`Reader`] via `Reader::new()`.
pub struct ReaderParams {
    /// `r` is the underlying reader being wrapped.
    pub r: Box<dyn io::Read>,

    /// `segment_decrypter` provides a method for decrypting segments.
    pub segment_decrypter: Box<dyn SegmentDecrypter>,

    /// `nonce_size` is the length of generated nonces. It must match the `nonce_size`
    /// of the [`Writer`] used to create the ciphertext, and must be somewhat larger
    /// than the size of the common `nonce_prefix`
    pub nonce_size: usize,

    /// `nonce_prefix` is a constant that all nonces throughout the ciphertext start
    /// with. It's extracted from the header of the ciphertext.
    pub nonce_prefix: Vec<u8>,

    /// The size of the ciphertext segments, equal to `nonce_size` plus the
    /// size of the plaintext segment.
    pub ciphertext_segment_size: usize,

    /// `first_ciphertext_segment_offset` indicates where the ciphertext actually begins
    /// in `r`. This allows for the existence of overhead in the stream unrelated to
    /// this encryption scheme.
    pub first_ciphertext_segment_offset: usize,
}

impl Reader {
    /// Create a new `Reader` instance.
    pub fn new(params: ReaderParams) -> Result<Reader, TinkError> {
        if params.nonce_size - params.nonce_prefix.len() < 5 {
            return Err("nonce size too short".into());
        }
        match params
            .ciphertext_segment_size
            .checked_sub(params.first_ciphertext_segment_offset)
        {
            None => {
                return Err(
                    "first ciphertext segment offset bigger than ciphertext segment size".into(),
                )
            }
            Some(sz) if sz <= params.nonce_size => {
                return Err("first ciphertext segment not large enough for full nonce".into())
            }
            _ => {}
        }
        Ok(Reader {
            r: params.r,
            segment_decrypter: params.segment_decrypter,
            decrypted_segment_cnt: 0,
            first_ciphertext_segment_offset: params.first_ciphertext_segment_offset,
            nonce_size: params.nonce_size,
            nonce_prefix: params.nonce_prefix,
            plaintext: vec![],
            plaintext_pos: 0,
            // Allocate an extra byte to detect the last segment.
            ciphertext: vec![0; params.ciphertext_segment_size + 1],
            // Offset of data in `ciphertext`. Only ever set to:
            //  - 0 (for first segment), or
            //  - 1 (for all subsequent segments).
            ciphertext_pos: 0,
        })
    }
}

/// Extension trait for [`std::io::Read`] to support `read_full()` method.
trait ReadFullExt {
    /// Read the exact number of bytes required to fill `buf`, if possible.
    ///
    /// This function reads as many bytes as necessary to completely fill the
    /// specified buffer `buf`.
    ///
    /// If this function encounters an error of the kind
    /// [`std::io::ErrorKind::Interrupted`] then the error is ignored and the
    /// operation will continue.
    ///
    /// If this function encounters an "end of file" before completely filling
    /// the buffer, it returns an `Ok(n)` value holding the number of bytes read
    /// into `buf`.
    ///
    /// If any other read error is encountered then this function immediately
    /// returns. The contents of `buf` are unspecified in this case.
    ///
    /// (This is similar to `Read::read_exact` except for partial read behaviour,
    /// and also behaves like Go's `io::ReadFull`, as used in the upstream Go code.)
    fn read_full(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

impl ReadFullExt for dyn std::io::Read {
    fn read_full(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        let mut count = 0;
        while !buf.is_empty() {
            match self.read(buf) {
                Ok(0) => break,
                Ok(n) => {
                    count += n;
                    let tmp = buf;
                    buf = &mut tmp[n..];
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(count)
    }
}

impl io::Read for Reader {
    /// Read decrypts data from underlying reader and passes it to `buf`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.plaintext_pos < self.plaintext.len() {
            // There is already-decrypted plaintext available -- return it first before attempting
            // any more decryption.
            let n = std::cmp::min(buf.len(), self.plaintext.len() - self.plaintext_pos);
            buf[..n].copy_from_slice(&self.plaintext[self.plaintext_pos..(self.plaintext_pos + n)]);
            self.plaintext_pos += n;
            return Ok(n);
        }
        // No available plaintext.
        self.plaintext_pos = 0;

        // Read up to a segment's worth of ciphertext.
        let mut ct_lim = self.ciphertext.len();
        if self.decrypted_segment_cnt == 0 {
            // The first segment of ciphertext might be offset in the stream.
            ct_lim -= self.first_ciphertext_segment_offset;
        }
        let n = self
            .r
            .read_full(&mut self.ciphertext[self.ciphertext_pos..ct_lim])?;
        if n == 0 {
            // No ciphertext available, so therefore no plaintext available for now.
            return Ok(0);
        }

        let last_segment;
        let segment;
        if n != (ct_lim - self.ciphertext_pos) {
            // Read less than a full segment, so this should be the last segment.
            last_segment = true;
            segment = self.ciphertext_pos + n;
        } else {
            last_segment = false;
            if (self.ciphertext_pos + n) < 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "ciphertext segment too short",
                ));
            }
            segment = self.ciphertext_pos + n - 1;
        }

        // Calculate the expected segment nonce and decrypt a segment.
        let nonce = generate_segment_nonce(
            self.nonce_size,
            &self.nonce_prefix,
            self.decrypted_segment_cnt,
            last_segment,
        )?;
        self.plaintext = self
            .segment_decrypter
            .decrypt_segment(&self.ciphertext[..segment], &nonce)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{:?}", e)))?;

        // Copy 1 byte remainder to the beginning of `self.ciphertext`.
        if !last_segment {
            let remainder_offset = segment;
            self.ciphertext[0] = self.ciphertext[remainder_offset];
            self.ciphertext_pos = 1;
        }
        self.decrypted_segment_cnt += 1;

        // A segment's worth of plaintext is now available in `self.plaintext`;
        // copy from this to the caller's buffer.
        let n = std::cmp::min(buf.len(), self.plaintext.len());
        buf[..n].copy_from_slice(&self.plaintext[..n]);
        self.plaintext_pos = n;
        Ok(n)
    }
}

/// Return a nonce for a segment.
///
/// The format of the nonce is:
///
///   nonce_prefix || ctr || last_block.
///
/// nonce_prefix is a constant prefix used throughout the whole ciphertext.
///
/// The ctr is a 32 bit counter.
///
/// last_block is 1 byte which is set to 1 for the last segment and 0
/// otherwise.
fn generate_segment_nonce(
    size: usize,
    prefix: &[u8],
    segment_num: u64,
    last: bool,
) -> io::Result<Vec<u8>> {
    let segment_num = match u32::try_from(segment_num) {
        Ok(v) => v,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many segments",
            ))
        }
    };
    let mut nonce = vec![0; size];
    nonce[..prefix.len()].copy_from_slice(prefix);
    let mut offset = prefix.len();
    nonce[offset..offset + 4].copy_from_slice(&segment_num.to_be_bytes()[..]);
    offset += 4;
    if last {
        nonce[offset] = 1;
    }
    Ok(nonce)
}

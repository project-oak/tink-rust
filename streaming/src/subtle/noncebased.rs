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

/// `Writer` provides a framework for ingesting plaintext data and writing encrypted data to the
/// wrapped [`io::Write`].
///
/// The scheme used for encrypting segments is specified by providing a `SegmentEncrypter`
/// implementation.
pub struct Writer {
    w: Box<dyn io::Write>,
    segment_encrypter: Box<dyn SegmentEncrypter>,
    encrypted_segment_cnt: u64,
    first_ciphertext_segment_offset: usize,
    nonce_size: usize,
    nonce_prefix: Vec<u8>,
    /// Buffer to hold incomplete segments of plaintext, until they are complete and
    /// ready for encryption. Its length is the amount of plaintext buffered so far;
    /// its capacity starts small and grows toward `plaintext_segment_size` only as
    /// data actually arrives.
    plaintext: Vec<u8>,
    /// The full plaintext segment size, which bounds the growth of `plaintext`.
    plaintext_segment_size: usize,
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
            // Grown lazily toward `plaintext_segment_size`; see `initial_segment_buffer_size`.
            plaintext: Vec::with_capacity(initial_segment_buffer_size(
                params.plaintext_segment_size,
            )),
            plaintext_segment_size: params.plaintext_segment_size,
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
            let mut pt_lim = self.plaintext_segment_size;
            if self.encrypted_segment_cnt == 0 {
                pt_lim -= self.first_ciphertext_segment_offset
            }
            let copy_lim = std::cmp::min(pt_lim, self.plaintext.capacity());

            let n = std::cmp::min(copy_lim - self.plaintext.len(), buf.len() - pos);
            self.plaintext.extend_from_slice(&buf[pos..pos + n]);
            pos += n;
            if pos == buf.len() {
                // All of the input plaintext has been consumed, but some (less than a segment's
                // worth) may be still be pending-encryption, held in
                // `self.plaintext`. It will be emitted on another `write()` (or by
                // `close()`).
                break;
            }

            if self.plaintext.len() < pt_lim {
                // The buffer is full but the segment is not complete: grow toward the full
                // segment size, no less than the buffered data plus the data still pending in
                // `buf`, so that a single large write skips the intermediate growth steps.
                let needed = self.plaintext.len() + buf.len() - pos;
                let grown = grown_segment_buffer_size(
                    self.plaintext.capacity(),
                    needed,
                    self.plaintext_segment_size,
                );
                self.plaintext.reserve_exact(grown - self.plaintext.len());
                continue;
            }

            // At this point there is a full segment's worth of plaintext in
            // `self.plaintext`, ready to encrypt and write out.
            if self.plaintext.len() != pt_lim {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "internal error: pos={} != pt_lim={}",
                        self.plaintext.len(),
                        pt_lim
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
                .encrypt_segment(&self.plaintext, &nonce)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
            self.w.write_all(&ciphertext)?;

            // Ready to accumulate next segment.
            self.plaintext.clear();
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
            .encrypt_segment(&self.plaintext, &nonce)?;
        self.w
            .write_all(&ciphertext)
            .map_err(|e| wrap_err("write failure", e))?;

        self.plaintext.clear();
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
    /// `ciphertext` holds encrypted data that has already been read from `r`. It starts small
    /// and grows toward `ciphertext_buffer_limit` only as bytes actually arrive.
    ciphertext: Vec<u8>,
    /// The full segment buffer size (ciphertext segment size plus one lookahead byte),
    /// which bounds the growth of `ciphertext`.
    ciphertext_buffer_limit: usize,

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
            // Grown lazily toward `ciphertext_buffer_limit`; see `initial_segment_buffer_size`.
            ciphertext: vec![0; initial_segment_buffer_size(params.ciphertext_segment_size + 1)],
            ciphertext_buffer_limit: params.ciphertext_segment_size + 1,
            // Offset of data in `ciphertext`. Only ever set to:
            //  - 0 (for first segment), or
            //  - 1 (for all subsequent segments).
            ciphertext_pos: 0,
        })
    }

    /// Read into `self.ciphertext[self.ciphertext_pos..ct_lim]`, growing `self.ciphertext`
    /// toward the full segment buffer size as the stream proves to have more data than the
    /// current buffer. `ct_lim` must not exceed `self.ciphertext_buffer_limit`.
    ///
    /// This behaves like Go's `io.ReadFull` (as used in the upstream Go code) into
    /// `self.ciphertext[self.ciphertext_pos..ct_lim]`: it reads as many bytes as necessary to reach
    /// `ct_lim`, ignores [`io::ErrorKind::Interrupted`], and on end-of-file returns `Ok(n)`
    /// holding the number of bytes read so far. Any other error is returned immediately, in
    /// which case the contents of the buffer are unspecified. It issues one `read` call per
    /// buffer growth step more than a fully pre-sized read would, which only a reader sensitive
    /// to request sizes or call counts can observe.
    fn read_segment_growing(&mut self, ct_lim: usize) -> io::Result<usize> {
        debug_assert!(ct_lim <= self.ciphertext_buffer_limit);
        let start = self.ciphertext_pos;
        let mut end = start;
        while end < ct_lim {
            if end == self.ciphertext.len() {
                // The buffer is full but the segment is not complete. Before growing, probe for
                // a single further byte so that a stream that ends exactly at the buffer size
                // does not pay for a larger buffer it will never fill.
                let mut probe = [0u8; 1];
                match self.r.read(&mut probe) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                // Grow toward the full segment buffer size. Unlike the `Writer`, the `Reader`
                // never knows how much data is still pending.
                let grown = grown_segment_buffer_size(
                    self.ciphertext.len(),
                    0,
                    self.ciphertext_buffer_limit,
                );
                // `reserve_exact` rather than `resize` alone: amortized growth could allocate
                // up to twice the segment size.
                self.ciphertext.reserve_exact(grown - self.ciphertext.len());
                self.ciphertext.resize(grown, 0);
                self.ciphertext[end] = probe[0];
                end += 1;
                continue;
            }
            let read_lim = std::cmp::min(self.ciphertext.len(), ct_lim);
            match self.r.read(&mut self.ciphertext[end..read_lim]) {
                Ok(0) => break,
                Ok(n) => end += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(end - start)
    }
}

/// Initial allocation size for a segment buffer. Segment buffers start small and grow (see
/// `grown_segment_buffer_size`) so that streams much smaller than the segment size do not pay
/// for a segment-sized allocation.
const INITIAL_SEGMENT_BUFFER_SIZE: usize = 4096;

/// Return the initial allocation size for a segment buffer: `INITIAL_SEGMENT_BUFFER_SIZE`,
/// unless the full segment buffer is not much larger (or is smaller), in which case the full
/// size is allocated at once.
fn initial_segment_buffer_size(limit: usize) -> usize {
    if INITIAL_SEGMENT_BUFFER_SIZE >= jump_threshold(limit) {
        limit
    } else {
        INITIAL_SEGMENT_BUFFER_SIZE
    }
}

/// The size from which a growing segment buffer jumps straight to `limit`: three quarters of
/// it. The jump avoids a nearly-full-sized step, such as one covering all but the `Reader`'s
/// one-byte lookahead.
fn jump_threshold(limit: usize) -> usize {
    limit - limit / 4
}

/// Return the next size for a segment buffer of size `cur` that must grow toward `limit`:
/// the next step of the sequence `INITIAL_SEGMENT_BUFFER_SIZE * GROWTH_FACTOR^k` above `cur`,
/// but no smaller than `needed`, and `limit` itself once the chosen size would reach
/// `jump_threshold(limit)`.
///
/// `needed` is the number of buffered and pending bytes already known to the caller, or zero
/// when unknown, so that a caller holding more data than a growth step covers allocates for
/// it in one step. Stepping along a fixed sequence rather than multiplying `cur` keeps the
/// total allocated over a segment's growth independent of the sizes such callers ask for.
fn grown_segment_buffer_size(cur: usize, needed: usize, limit: usize) -> usize {
    const GROWTH_FACTOR: usize = 8;
    let jump_threshold = jump_threshold(limit);
    let mut stepped = INITIAL_SEGMENT_BUFFER_SIZE;
    while stepped <= cur {
        // The multiplication is only taken when its result is below `jump_threshold`, so it
        // cannot overflow.
        if stepped >= jump_threshold / GROWTH_FACTOR {
            stepped = limit;
            break;
        }
        stepped *= GROWTH_FACTOR;
    }
    let new_size = std::cmp::max(stepped, needed);
    if new_size >= jump_threshold {
        limit
    } else {
        new_size
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
        let mut ct_lim = self.ciphertext_buffer_limit;
        if self.decrypted_segment_cnt == 0 {
            // The first segment of ciphertext might be offset in the stream.
            ct_lim -= self.first_ciphertext_segment_offset;
        }
        let n = self.read_segment_growing(ct_lim)?;
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
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;

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

#[cfg(test)]
mod tests {
    use super::{grown_segment_buffer_size, initial_segment_buffer_size};

    #[test]
    fn initial_size_is_capped_by_limit_and_skips_near_misses() {
        assert_eq!(initial_segment_buffer_size(1), 1);
        assert_eq!(initial_segment_buffer_size(4095), 4095);
        assert_eq!(initial_segment_buffer_size(4096), 4096);
        // A limit only slightly above the initial size (such as a 4 KiB ciphertext segment
        // plus the lookahead byte) is allocated in full rather than grown by a single step.
        assert_eq!(initial_segment_buffer_size(4097), 4097);
        assert_eq!(initial_segment_buffer_size(5461), 5461);
        assert_eq!(initial_segment_buffer_size(5462), 4096);
        assert_eq!(initial_segment_buffer_size(1 << 20), 4096);
    }

    #[test]
    fn growth_sequence_for_one_mib_segment() {
        let limit = (1 << 20) + 1;
        let mut sizes = vec![initial_segment_buffer_size(limit)];
        while *sizes.last().unwrap() < limit {
            let cur = *sizes.last().unwrap();
            sizes.push(grown_segment_buffer_size(cur, 0, limit));
        }
        assert_eq!(sizes, vec![4096, 32768, 262144, limit]);
    }

    #[test]
    fn growth_never_overshoots_and_always_progresses() {
        for limit in 1..6000usize {
            let mut cur = initial_segment_buffer_size(limit);
            let mut steps = 0;
            while cur < limit {
                let next = grown_segment_buffer_size(cur, 0, limit);
                assert!(next > cur, "limit={} cur={} next={}", limit, cur, next);
                assert!(next <= limit, "limit={} cur={} next={}", limit, cur, next);
                cur = next;
                steps += 1;
                assert!(steps <= 4, "limit={}: too many growth steps", limit);
            }
        }
    }

    #[test]
    fn growth_honours_needed_and_jumps_near_limit() {
        let limit = 1 << 20;
        // A caller with more pending data than the next step covers is sized to that data.
        assert_eq!(grown_segment_buffer_size(4096, 100_000, limit), 100_000);
        // ... unless that would land within a quarter of the limit, in which case the buffer
        // jumps straight to the limit.
        assert_eq!(grown_segment_buffer_size(4096, 800_000, limit), limit);
        // Growth from such an off-sequence size continues along the fixed sequence.
        assert_eq!(grown_segment_buffer_size(100_000, 0, limit), 262_144);
        assert_eq!(grown_segment_buffer_size(262_143, 0, limit), 262_144);
        // A step that would land within a quarter of the limit jumps to the limit.
        assert_eq!(grown_segment_buffer_size(262_144, 0, limit), limit);
        assert_eq!(grown_segment_buffer_size(300_000, 0, limit), limit);
        // The `Writer` passes the bytes pending in the current write as `needed`, which can
        // exceed the limit; the result is clamped to the limit.
        assert_eq!(grown_segment_buffer_size(4096, limit, limit), limit);
        assert_eq!(grown_segment_buffer_size(4096, 10 * limit, limit), limit);
    }
}

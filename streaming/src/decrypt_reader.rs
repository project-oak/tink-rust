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

use std::{
    cell::{RefCell, RefMut},
    io,
    rc::Rc,
};

/// Possible states for a [`DecryptReader`].
enum State {
    // Matching primitive not yet determined, raw ciphertext reader available.
    Pending(Box<dyn io::Read>),
    // Matching primitive that correctly decrypts has been found.
    Found(Box<dyn io::Read>),
    // No matching primitive available.
    Failed,
}

/// `DecryptReader` is a reader that tries to find the right key to decrypt ciphertext from the
/// given primitive set.
pub(crate) struct DecryptReader {
    wrapped: crate::WrappedStreamingAead,
    aad: Vec<u8>,
    state: State,
}

impl DecryptReader {
    pub fn new(
        wrapped: crate::WrappedStreamingAead,
        reader: Box<dyn io::Read>,
        aad: &[u8],
    ) -> Self {
        Self {
            wrapped,
            aad: aad.to_vec(),
            state: State::Pending(reader),
        }
    }
}

impl io::Read for DecryptReader {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        match &mut self.state {
            State::Found(reader) => return reader.read(p),
            State::Failed => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no matching key found for the ciphertext in the stream",
                ))
            }
            State::Pending(_) => {}
        };
        // Move the underlying raw reader out of self and into a `SharedCopyReader`
        let state = std::mem::replace(&mut self.state, State::Failed);
        let raw_reader = match state {
            State::Pending(reader) => reader,
            _ => unreachable!(),
        };
        let mut copy_reader = SharedCopyReader::new(raw_reader);

        // find proper key to decrypt ciphertext
        let entries = self.wrapped.ps.raw_entries();
        for e in &entries {
            let sa = match &e.primitive {
                tink::Primitive::StreamingAead(p) => p,
                _ => continue,
            };

            // Attempt a decrypting-read from the ciphertext reader `cr`, but also keep a copy of
            // the read data into a buffer so that it can be re-scanned with a different key if
            // decryption fails.
            let mut r = match sa.new_decrypting_reader(Box::new(copy_reader.clone()), &self.aad) {
                Ok(r) => r,
                Err(_) => {
                    copy_reader.rewind();
                    continue;
                }
            };
            let n = match r.read(p) {
                Ok(n) => n,
                Err(_) => {
                    // The read attempt will have consumed some of the underlying reader, but
                    // there is a copy of the data that has been read. Ensure that this already-read
                    // data is re-used next time around.
                    copy_reader.rewind();
                    continue;
                }
            };

            // Reading has succeeded, so use this particular key from now on and no longer need
            // to store copies of read data.
            copy_reader.stop_copying();
            self.state = State::Found(r);
            return Ok(n);
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no matching key found for the ciphertext in the stream",
        ))
    }
}

/// Wrapper around an [`io::Read`] trait object that stores a copy of all of the data
/// read from the underlying object.
struct CopyReader {
    reader: Box<dyn io::Read>,
    copying: bool,
    read_pos: usize,
    copied_data: Vec<u8>,
}

impl std::fmt::Debug for CopyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CopyReader {{copying={}, read_pos={}, copied_data.len()={}}}",
            self.copying,
            self.read_pos,
            self.copied_data.len(),
        )
    }
}

impl CopyReader {
    fn new(reader: Box<dyn io::Read>) -> Self {
        Self {
            reader,
            copying: true,
            read_pos: 0,
            copied_data: vec![],
        }
    }
    fn rewind(&mut self) {
        self.read_pos = 0;
    }
    fn stop_copying(&mut self) {
        self.copying = false;
        // Buffered data has been consumed, so drop it.
        self.copied_data = vec![];
        self.read_pos = 0;
    }
}

impl io::Read for CopyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read_pos < self.copied_data.len() {
            // Read from the buffered copy of the data.
            let available_data = self.copied_data.len() - self.read_pos;
            let n = std::cmp::min(buf.len(), available_data);
            buf[..n].copy_from_slice(&self.copied_data[self.read_pos..self.read_pos + n]);
            self.read_pos += n;
            Ok(n)
        } else {
            // Read from the underlying object
            let n = self.reader.read(buf)?;
            if self.copying {
                // Store a copy of the data read.
                self.copied_data.extend_from_slice(&buf[..n]);
                self.read_pos += n;
            }
            Ok(n)
        }
    }
}

#[derive(Clone, Debug)]
struct SharedCopyReader(Rc<RefCell<CopyReader>>);

impl SharedCopyReader {
    fn new(reader: Box<dyn io::Read>) -> Self {
        Self(Rc::new(RefCell::new(CopyReader::new(reader))))
    }
    fn rewind(&mut self) {
        let mut cr: RefMut<_> = self.0.borrow_mut();
        cr.rewind();
    }
    fn stop_copying(&mut self) {
        let mut cr: RefMut<_> = self.0.borrow_mut();
        cr.stop_copying();
    }
}

impl io::Read for SharedCopyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut cr: RefMut<_> = self.0.borrow_mut();
        cr.read(buf)
    }
}

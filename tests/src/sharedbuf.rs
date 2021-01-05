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

//! Shared buffer for testing [`std::io::Read`] and [`std::io::Write`].

use std::sync::{Arc, Mutex};

/// Shared buffer, which allows [`Read`](std::io::Read) and [`Write`](std::io::Write) operations to
/// happen in parallel. This also means that a `clone`d copy can be enclosed as a `Box<dyn Read>`
/// (which is implicitly `Box<dyn Read + 'static>`) without lifetime concerns.
#[derive(Clone, Default)]
pub struct SharedBuf {
    contents: Arc<Mutex<Vec<u8>>>,
}

impl SharedBuf {
    pub fn new() -> Self {
        SharedBuf {
            contents: Arc::new(Mutex::new(vec![])),
        }
    }

    /// Return a copy of the contents of the buffer.
    pub fn contents(&self) -> Vec<u8> {
        self.contents.lock().unwrap().clone()
    }
}

impl std::io::Read for SharedBuf {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut v = self.contents.lock().unwrap();
        let count = std::cmp::min(buf.len(), v.len());
        for (i, b) in v.drain(0..count).enumerate() {
            buf[i] = b;
        }
        Ok(count)
    }
}

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut v = self.contents.lock().unwrap();
        v.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::result::Result<(), std::io::Error> {
        Ok(())
    }
}

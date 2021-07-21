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

//! Utilities for random data.

/// Re-export the particular version of the `rand` crate whose types appear in the API.
pub use rand;

use rand::Rng;

/// Trait that encapsulates the required traits that a random number generator instance must
/// implement.
pub trait Generator: rand::RngCore + rand::CryptoRng {}

/// Blanket implementation: any type that is a [`rand::CryptoRng`] is automatically
/// suitable as a Tink [`Generator`].
impl<T> Generator for T where T: rand::RngCore + rand::CryptoRng {}

/// Return a random number generator suitable for cryptographic operation.
pub fn rng() -> Box<dyn Generator> {
    Box::new(rand::thread_rng())
}

/// Return a vector of the given `size` filled with random bytes.
pub fn get_random_bytes(size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    rng().fill(&mut data[..]);
    data
}

/// Randomly generate an unsigned 32-bit integer.
pub fn get_random_uint32() -> u32 {
    rng().gen()
}

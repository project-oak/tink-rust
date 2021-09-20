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

//! Message Authentication Codes.

use alloc::{boxed::Box, vec::Vec};

/// `Mac` is the interface for MACs (Message Authentication Codes).
/// This interface should be used for authentication only, and not for other purposes
/// (for example, it should not be used to generate pseudorandom bytes).
pub trait Mac: MacBoxClone {
    /// Compute message authentication code (MAC) for code data.
    fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>, crate::TinkError>;

    /// Returns `()` if `mac` is a correct authentication code (MAC) for `data`,
    /// otherwise it returns an error.
    fn verify_mac(&self, mac: &[u8], data: &[u8]) -> Result<(), crate::TinkError> {
        let computed = self.compute_mac(data)?;
        if crate::subtle::constant_time_compare(mac, &computed) {
            Ok(())
        } else {
            Err("Invalid MAC".into())
        }
    }
}

/// Trait bound to indicate that primitive trait objects should support cloning
/// themselves as trait objects.
pub trait MacBoxClone {
    fn box_clone(&self) -> Box<dyn Mac>;
}

/// Default implementation of the box-clone trait bound for any underlying
/// concrete type that implements [`Clone`].
impl<T> MacBoxClone for T
where
    T: 'static + Mac + Clone,
{
    fn box_clone(&self) -> Box<dyn Mac> {
        Box::new(self.clone())
    }
}

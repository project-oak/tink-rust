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

//! Provide methods to generate, read, write or validate keysets.

mod binary_io;
pub use binary_io::*;
mod handle;
pub use handle::*;
#[cfg(feature = "json")]
#[cfg_attr(docsrs, doc(cfg(feature = "json")))]
mod json_io;
#[cfg(feature = "json")]
pub use json_io::*;
mod manager;
pub use manager::*;
mod mem_io;
pub use mem_io::*;
mod reader;
pub use reader::*;
mod validation;
pub use validation::*;
mod writer;
pub use writer::*;

#[cfg(feature = "insecure")]
#[cfg_attr(docsrs, doc(cfg(feature = "insecure")))]
pub mod insecure;

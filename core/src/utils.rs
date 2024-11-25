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

//! Utilities for Tink Rust code.
//!
//! Some of these utilities are not idiomatic Rust, but are included to make the process of
//! translating code from other languages (e.g. Go) easier.

use std::error::Error;

/// `Error` type for errors emitted by Tink. Note that errors from cryptographic
/// operations are necessarily uninformative, to avoid information leakage.
#[derive(Debug)]
pub struct TinkError {
    msg: String,
    src: Option<Box<dyn Error + Send + Sync>>,
}

impl TinkError {
    pub fn new(msg: &str) -> Self {
        msg.into()
    }
}

impl std::fmt::Display for TinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(src) = &self.src {
            write!(f, "{}: {}", self.msg, src)
        } else {
            write!(f, "{}", self.msg)
        }
    }
}

impl Error for TinkError {}

impl std::convert::From<&str> for TinkError {
    fn from(msg: &str) -> Self {
        TinkError {
            msg: msg.to_string(),
            src: None,
        }
    }
}

impl std::convert::From<String> for TinkError {
    fn from(msg: String) -> Self {
        TinkError { msg, src: None }
    }
}

/// Wrap an error with an additional message.  This utility is intended to help
/// with porting Go code to Rust, to cover patterns like:
///
/// ```Go
///   thing, err := FunctionCall()
///   if err != nil {
///     return nil, fmt.Errorf("FunctionCall failed: %s", err)
///   }
/// ```
pub fn wrap_err<T>(msg: &str, src: T) -> TinkError
where
    T: Error + Send + Sync + 'static,
{
    TinkError {
        msg: msg.to_string(),
        src: Some(Box::new(src)),
    }
}

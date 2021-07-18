// Copyright 2021 The Tink-Rust Authors
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

//! This binary crate is `no_std`, and used to check that no `std` depedencies
//! have crept into `tink-*` crates and their dependencies.
#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(start)]
#![allow(unused_imports)]

use tink_aead;
use tink_core;
use tink_daead;
use tink_mac;
use tink_prf;
use tink_proto;
use tink_signature;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[lang = "eh_personality"]
extern "C" fn my_eh_personality() {}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {}
}

#[start]
pub extern "C" fn _main(_argc: isize, _argv: *const *const u8) -> isize {
    0
}

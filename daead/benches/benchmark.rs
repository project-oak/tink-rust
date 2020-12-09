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

#![feature(test)]
extern crate test;
use test::Bencher;

const MSG: &[u8] = b"this data needs to be encrypted";
const AAD: &[u8] = b"this data needs to be authenticated, but not encrypted";

fn setup(kt: tink::proto::KeyTemplate) -> (Box<dyn tink::DeterministicAead>, Vec<u8>) {
    tink_daead::init();
    let kh = tink::keyset::Handle::new(&kt).unwrap();
    let a = tink_daead::new(&kh).unwrap();
    let ct = a.encrypt_deterministically(MSG, AAD).unwrap();
    (a, ct)
}

#[bench]
fn bench_aes_siv_encrypt(b: &mut Bencher) {
    let (d, _ct) = setup(tink_daead::aes_siv_key_template());
    b.iter(|| d.encrypt_deterministically(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes_siv_decrypt(b: &mut Bencher) {
    let (d, ct) = setup(tink_daead::aes_siv_key_template());
    b.iter(|| d.decrypt_deterministically(&ct, AAD).unwrap());
}

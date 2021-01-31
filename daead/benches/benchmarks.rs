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

fn setup(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::DeterministicAead>, Vec<u8>) {
    tink_daead::init();
    let kh = tink_core::keyset::Handle::new(&kt).unwrap();
    let a = tink_daead::new(&kh).unwrap();
    let ct = a.encrypt_deterministically(MSG, AAD).unwrap();
    (a, ct)
}

/// Size of the prefix information in the ciphertext. If this is corrupted, the tag will be
/// rejected immediately without performing any cryptographic operations.
const PREFIX_SIZE: usize = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;

fn setup_failure(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::DeterministicAead>, Vec<u8>) {
    let (a, ct) = setup(kt);
    (
        a,
        ct.iter()
            .enumerate()
            .map(|(i, b)| if i < PREFIX_SIZE { *b } else { b ^ 0b10101010 })
            .collect(),
    )
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

#[bench]
fn bench_aes_siv_decrypt_fail(b: &mut Bencher) {
    let (d, ct) = setup_failure(tink_daead::aes_siv_key_template());
    b.iter(|| d.decrypt_deterministically(&ct, AAD).unwrap_err());
}

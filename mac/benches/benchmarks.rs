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

const MSG: &[u8] = b"this data needs to be authenticated";

fn setup(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::Mac>, Vec<u8>) {
    tink_mac::init();
    let kh = tink_core::keyset::Handle::new(&kt).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let tag = m.compute_mac(MSG).unwrap();
    (m, tag)
}

/// Size of the prefix information in the tag. If this is corrupted, the tag will be
/// rejected immediately without performing any cryptographic operations.
const PREFIX_SIZE: usize = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;

fn setup_failure(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::Mac>, Vec<u8>) {
    let (m, tag) = setup(kt);
    (
        m,
        tag.iter()
            .enumerate()
            .map(|(i, b)| if i < PREFIX_SIZE { *b } else { b ^ 0b10101010 })
            .collect(),
    )
}

#[bench]
fn bench_hmac_sha256_tag128_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::hmac_sha256_tag128_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_hmac_sha256_tag128_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::hmac_sha256_tag128_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

#[bench]
fn bench_hmac_sha256_tag128_mac_verify_fail(b: &mut Bencher) {
    let (m, tag) = setup_failure(tink_mac::hmac_sha256_tag128_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap_err());
}

#[bench]
fn bench_hmac_sha256_tag256_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::hmac_sha256_tag256_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_hmac_sha256_tag256_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::hmac_sha256_tag256_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

#[bench]
fn bench_hmac_sha256_tag256_mac_verify_fail(b: &mut Bencher) {
    let (m, tag) = setup_failure(tink_mac::hmac_sha256_tag256_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap_err());
}

#[bench]
fn bench_hmac_sha512_tag256_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::hmac_sha512_tag256_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_hmac_sha512_tag256_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::hmac_sha512_tag256_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

#[bench]
fn bench_hmac_sha512_tag256_mac_verify_fail(b: &mut Bencher) {
    let (m, tag) = setup_failure(tink_mac::hmac_sha512_tag256_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap_err());
}

#[bench]
fn bench_hmac_sha512_tag512_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::hmac_sha512_tag512_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_hmac_sha512_tag512_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::hmac_sha512_tag512_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

#[bench]
fn bench_hmac_sha512_tag512_mac_verify_fail(b: &mut Bencher) {
    let (m, tag) = setup_failure(tink_mac::hmac_sha512_tag512_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap_err());
}

#[bench]
fn bench_aes_cmac_tag128_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::aes_cmac_tag128_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_aes_cmac_tag128_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::aes_cmac_tag128_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

#[bench]
fn bench_aes_cmac_tag128_mac_verify_fail(b: &mut Bencher) {
    let (m, tag) = setup_failure(tink_mac::aes_cmac_tag128_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap_err());
}

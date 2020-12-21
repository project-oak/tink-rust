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

fn setup(kt: tink_proto::KeyTemplate) -> (Box<dyn tink::Mac>, Vec<u8>) {
    tink_mac::init();
    let kh = tink::keyset::Handle::new(&kt).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let tag = m.compute_mac(MSG).unwrap();
    (m, tag)
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
fn bench_aes_cmac_tag128_mac_compute(b: &mut Bencher) {
    let (m, _tag) = setup(tink_mac::aes_cmac_tag128_key_template());
    b.iter(|| m.compute_mac(MSG).unwrap());
}

#[bench]
fn bench_aes_cmac_tag128_mac_verify(b: &mut Bencher) {
    let (m, tag) = setup(tink_mac::aes_cmac_tag128_key_template());
    b.iter(|| m.verify_mac(&tag, MSG).unwrap());
}

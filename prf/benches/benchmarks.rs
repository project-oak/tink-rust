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

const MSG: &[u8] = b"this is an ID that needs to be redacted";

fn setup(kt: tink_proto::KeyTemplate) -> tink_prf::Set {
    tink_prf::init();
    let kh = tink::keyset::Handle::new(&kt).unwrap();
    tink_prf::Set::new(&kh).unwrap()
}

#[bench]
fn bench_hmac_sha256_prf_compute(b: &mut Bencher) {
    let p = setup(tink_prf::hmac_sha256_prf_key_template());
    b.iter(|| p.compute_primary_prf(MSG, 30).unwrap());
}

#[bench]
fn bench_hmac_sha512_prf_compute(b: &mut Bencher) {
    let p = setup(tink_prf::hmac_sha512_prf_key_template());
    b.iter(|| p.compute_primary_prf(MSG, 30).unwrap());
}

#[bench]
fn bench_hkdf_sha256_prf_compute(b: &mut Bencher) {
    let p = setup(tink_prf::hkdf_sha256_prf_key_template());
    b.iter(|| p.compute_primary_prf(MSG, 30).unwrap());
}

#[bench]
fn bench_aes_cmac_prf_compute(b: &mut Bencher) {
    let p = setup(tink_prf::aes_cmac_prf_key_template());
    b.iter(|| p.compute_primary_prf(MSG, 14).unwrap());
}

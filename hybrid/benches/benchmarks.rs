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

#![feature(test)]
extern crate test;
use test::Bencher;

const MSG: &[u8] = b"this data needs to be encrypted";
const CONTEXT: &[u8] = b"context";

fn setup(
    kt: tink_proto::KeyTemplate,
) -> (
    Box<dyn tink_core::HybridEncrypt>,
    Box<dyn tink_core::HybridDecrypt>,
    Vec<u8>,
) {
    tink_hybrid::init();
    let kh = tink_core::keyset::Handle::new(&kt).unwrap();
    let d = tink_hybrid::new_decrypt(&kh).unwrap();
    let pubkh = kh.public().unwrap();
    let e = tink_hybrid::new_encrypt(&pubkh).unwrap();
    let ct = e.encrypt(MSG, CONTEXT).unwrap();
    (e, d, ct)
}

/// Size of the prefix information in the ciphertext. If this is corrupted, the tag will be
/// rejected immediately without performing any cryptographic operations.
const PREFIX_SIZE: usize = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;

fn setup_failure(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::HybridDecrypt>, Vec<u8>) {
    let (_e, d, ct) = setup(kt);
    (
        d,
        ct.iter()
            .enumerate()
            .map(|(i, b)| if i < PREFIX_SIZE { *b } else { b ^ 0b10101010 })
            .collect(),
    )
}

#[bench]
fn bench_ecies_hkdf_aes128_gcm_encrypt(b: &mut Bencher) {
    let (e, _d, _ct) = setup(tink_hybrid::ecies_hkdf_aes128_gcm_key_template());
    b.iter(|| e.encrypt(MSG, CONTEXT).unwrap())
}

#[bench]
fn bench_ecies_hkdf_aes128_gcm_decrypt(b: &mut Bencher) {
    let (_e, d, ct) = setup(tink_hybrid::ecies_hkdf_aes128_gcm_key_template());
    b.iter(|| d.decrypt(&ct, CONTEXT).unwrap())
}

#[bench]
fn bench_ecies_hkdf_aes128_ctr_hmac_encrypt(b: &mut Bencher) {
    let (e, _d, _ct) = setup(tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template());
    b.iter(|| e.encrypt(MSG, CONTEXT).unwrap())
}

#[bench]
fn bench_ecies_hkdf_aes128_ctr_hmac_decrypt(b: &mut Bencher) {
    let (_e, d, ct) = setup(tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template());
    b.iter(|| d.decrypt(&ct, CONTEXT).unwrap())
}

#[bench]
fn bench_ecies_hkdf_aes128_gcm_decrypt_fail(b: &mut Bencher) {
    let (d, ct) = setup_failure(tink_hybrid::ecies_hkdf_aes128_gcm_key_template());
    b.iter(|| d.decrypt(&ct, CONTEXT).unwrap_err())
}

#[bench]
fn bench_ecies_hkdf_aes128_ctr_hmac_decrypt_fail(b: &mut Bencher) {
    let (d, ct) = setup_failure(tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template());
    b.iter(|| d.decrypt(&ct, CONTEXT).unwrap_err())
}

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

fn setup(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::Aead>, Vec<u8>) {
    tink_aead::init();
    let kh = tink_core::keyset::Handle::new(&kt).unwrap();
    let a = tink_aead::new(&kh).unwrap();
    let ct = a.encrypt(MSG, AAD).unwrap();
    (a, ct)
}

#[bench]
fn bench_aes128_gcm_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes128_gcm_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes128_gcm_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes128_gcm_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_aes256_gcm_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes256_gcm_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes256_gcm_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes256_gcm_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_aes128_gcm_siv_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes128_gcm_siv_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes128_gcm_siv_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes128_gcm_siv_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_aes256_gcm_siv_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes256_gcm_siv_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes256_gcm_siv_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes256_gcm_siv_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_aes128_ctr_hmac_sha256_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes128_ctr_hmac_sha256_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes128_ctr_hmac_sha256_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes128_ctr_hmac_sha256_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_aes256_ctr_hmac_sha256_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::aes256_ctr_hmac_sha256_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_aes256_ctr_hmac_sha256_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::aes256_ctr_hmac_sha256_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_cha_cha20_poly1305_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::cha_cha20_poly1305_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_cha_cha20_poly1305_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::cha_cha20_poly1305_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

#[bench]
fn bench_x_cha_cha20_poly1305_encrypt(b: &mut Bencher) {
    let (a, _ct) = setup(tink_aead::x_cha_cha20_poly1305_key_template());
    b.iter(|| a.encrypt(MSG, AAD).unwrap());
}

#[bench]
fn bench_x_cha_cha20_poly1305_decrypt(b: &mut Bencher) {
    let (a, ct) = setup(tink_aead::x_cha_cha20_poly1305_key_template());
    b.iter(|| a.decrypt(&ct, AAD).unwrap());
}

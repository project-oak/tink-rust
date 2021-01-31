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

const MSG: &[u8] = b"this data needs to be signed";

fn setup(
    kt: tink_proto::KeyTemplate,
) -> (
    Box<dyn tink_core::Signer>,
    Box<dyn tink_core::Verifier>,
    Vec<u8>,
) {
    tink_signature::init();
    let kh = tink_core::keyset::Handle::new(&kt).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();
    let pubkh = kh.public().unwrap();
    let v = tink_signature::new_verifier(&pubkh).unwrap();
    let sig = s.sign(MSG).unwrap();
    (s, v, sig)
}

/// Size of the prefix information in the signature. If this is corrupted, the tag will be
/// rejected immediately without performing any cryptographic operations.
const PREFIX_SIZE: usize = tink_core::cryptofmt::NON_RAW_PREFIX_SIZE;

fn setup_failure(kt: tink_proto::KeyTemplate) -> (Box<dyn tink_core::Verifier>, Vec<u8>) {
    let (_s, v, sig) = setup(kt);
    (
        v,
        sig.iter()
            .enumerate()
            .map(|(i, b)| if i < PREFIX_SIZE { *b } else { b ^ 0b10101010 })
            .collect(),
    )
}

#[bench]
fn bench_ecdsa_p256_sign(b: &mut Bencher) {
    let (s, _v, _sig) = setup(tink_signature::ecdsa_p256_key_template());
    b.iter(|| s.sign(MSG).unwrap());
}

#[bench]
fn bench_ecdsa_p256_verify(b: &mut Bencher) {
    let (_s, v, sig) = setup(tink_signature::ecdsa_p256_key_template());
    b.iter(|| v.verify(&sig, MSG).unwrap());
}

#[bench]
fn bench_ecdsa_p256_verify_fail(b: &mut Bencher) {
    let (v, sig) = setup_failure(tink_signature::ecdsa_p256_key_template());
    b.iter(|| v.verify(&sig, MSG).unwrap_err());
}

#[bench]
fn bench_ed25519_sign(b: &mut Bencher) {
    let (s, _v, _sig) = setup(tink_signature::ed25519_key_template());
    b.iter(|| s.sign(MSG).unwrap());
}

#[bench]
fn bench_ed25519_verify(b: &mut Bencher) {
    let (_s, v, sig) = setup(tink_signature::ed25519_key_template());
    b.iter(|| v.verify(&sig, MSG).unwrap());
}

#[bench]
fn bench_ed25519_verify_fail(b: &mut Bencher) {
    let (v, sig) = setup_failure(tink_signature::ed25519_key_template());
    b.iter(|| v.verify(&sig, MSG).unwrap_err());
}

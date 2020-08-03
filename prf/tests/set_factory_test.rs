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

use tink::{utils::wrap_err, TinkError};

const MAX_AUTOCORRELATION: usize = 100;

fn add_key_and_return_id(
    m: &mut tink::keyset::Manager,
    template: &tink::proto::KeyTemplate,
) -> Result<u32, TinkError> {
    m.rotate(template)
        .map_err(|e| wrap_err("Could not add template", e))?;
    let h = m
        .handle()
        .map_err(|e| wrap_err("Could not obtain handle", e))?;
    let p = h
        .primitives()
        .map_err(|e| wrap_err("Could not obtain primitives", e))?;
    Ok(p.primary.unwrap().key_id)
}

#[test]
fn test_factory_basic() {
    tink_prf::init();
    let mut manager = tink::keyset::Manager::new();
    let aes_cmac_id = add_key_and_return_id(&mut manager, &tink_prf::aes_cmac_prf_key_template())
        .expect("Could not add AES CMAC PRF key");
    let hmac_sha256_id =
        add_key_and_return_id(&mut manager, &tink_prf::hmac_sha256_prf_key_template())
            .expect("Could not add HMAC SHA256 PRF key");
    let hkdf_sha256_id =
        add_key_and_return_id(&mut manager, &tink_prf::hkdf_sha256_prf_key_template())
            .expect("Could not add HKDF SHA256 PRF key");
    let hmac_sha512_id =
        add_key_and_return_id(&mut manager, &tink_prf::hmac_sha512_prf_key_template())
            .expect("Could not add HMAC SHA512 PRF key");

    let handle = manager.handle().expect("Could not obtain handle");
    let prf_set = tink_prf::Set::new(&handle)
        .expect("Could not create tink_prf::Set with standard key templates");
    let primary_id = prf_set.primary_id;
    assert_eq!(
        primary_id, hmac_sha512_id,
        "Primary ID should be the ID which was added last",
    );
    let lengths = [1, 10, 16, 17, 32, 33, 64, 65, 100, 8160, 8161];
    for &length in lengths.iter() {
        let mut results = Vec::new();
        for (id, prf) in &prf_set.prfs {
            let mut ok = true;
            if length > 16 && *id == aes_cmac_id
                || length > 32 && *id == hmac_sha256_id
                || length > 64 && *id == hmac_sha512_id
                || length > 8160 && *id == hkdf_sha256_id
            {
                ok = false;
            }

            let result1 = prf.compute_prf(b"The input", length);
            if result1.is_err() && !ok {
                // expected failure
                continue;
            }
            let result1 = result1.unwrap_or_else(|_| {
                panic!(
                    "Expected to be able to compute {} bytes of PRF output",
                    length
                )
            });
            assert!(
                ok,
                "Expected to be unable to compute {} bytes PRF output",
                length
            );
            let result2 = prf
                .compute_prf(b"The different input", length)
                .unwrap_or_else(|_| {
                    panic!(
                        "Expected to be able to compute {} bytes of PRF output",
                        length,
                    )
                });
            let result3 = prf.compute_prf(b"The input", length).unwrap_or_else(|_| {
                panic!(
                    "Expected to be able to compute {} bytes of PRF output",
                    length
                )
            });
            if *id == primary_id {
                let primary_result = prf_set
                    .compute_primary_prf(b"The input", length)
                    .unwrap_or_else(|_| {
                        panic!(
                            "Expected to be able to compute {} bytes of PRF output",
                            length
                        )
                    });
                assert_eq!(hex::encode(&result1), hex::encode(&primary_result),
                            "Expected manual call of ComputePRF of primary PRF and ComputePrimaryPRF with the same input to produce the same output");
            }
            assert_eq!(
                hex::encode(&result1),
                hex::encode(&result3),
                "Expected different calls with the same input to produce the same output"
            );
            results.push(result1);
            results.push(result2);
        }
        run_z_tests(results)
    }
}

#[test]
fn test_non_raw_keys() {
    tink_prf::init();
    let mut template = tink_prf::aes_cmac_prf_key_template();
    template.output_prefix_type = tink::proto::OutputPrefixType::Tink as i32;
    let h = tink::keyset::Handle::new(&template).expect("Couldn't create keyset");
    assert!(
        tink_prf::Set::new(&h).is_err(),
        "Expected non RAW prefix to fail to create prf.Set"
    );
    let mut m = tink::keyset::Manager::new_from_handle(h);
    assert!(
        m.rotate(&tink_prf::hmac_sha256_prf_key_template()).is_ok(),
        "Expected to be able to add keys to the keyset"
    );
    let h = m
        .handle()
        .expect("Expected to be able to create keyset handle");
    assert!(
        tink_prf::Set::new(&h).is_err(),
        "Expected mixed prefix keyset to fail to create tink_prf::Set"
    );
}

/*
// TODO: reinstate when tink_mac available
#[test]
fn test_non_prf_primitives() {
    tink_mac::init();
    tink_prf::init();
    let mut template = tink_mac::aes_cmac_tag128_key_template();
    template.output_prefix_type = tink::proto::OutputPrefixType::Raw as i32;
    let h = tink::keyset::Handle::new(&template).expect("Couldn't create keyset");
    assert!(
        tink_prf::Set::new(&h).is_err(),
        "Expected non PRF primitive to fail to create tink_prf::Set"
    );

    let mut m = tink::keyset::Manager::new_from_handle(h);
    assert!(
        m.rotate(&tink_prf::hmac_sha256_prf_key_template()).is_ok(),
        "Expected to be able to add keys to the keyset"
    );
    let h = m
        .handle()
        .expect("Expected to be able to create keyset handle");
    assert!(
        tink_prf::Set::new(&h).is_err(),
        "Expected mixed primitive keyset to fail to create prf.Set"
    );
}
*/

fn run_z_tests(results: Vec<Vec<u8>>) {
    for (i, result1) in results.iter().enumerate() {
        tink_testutil::z_test_uniform_string(result1)
            .expect("Expected PRF output to pass uniformity z test");
        if result1.len() <= MAX_AUTOCORRELATION {
            tink_testutil::z_test_autocorrelation_uniform_string(result1)
                .expect("Expected PRF output to pass autocorrelation test");
        }
        for result2 in results.iter().skip(i + 1) {
            tink_testutil::z_test_crosscorrelation_uniform_strings(result1, result2)
                .expect("Expected different PRF outputs to be uncorrelated");
        }
    }
}

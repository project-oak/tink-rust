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

use tink::Mac;
use tink_testutil::get_random_bytes;

mod wycheproofutil_test;

#[test]
fn test_dummy_mac() {
    // Check that DummyMAC verifies.
    // try to compute mac
    let mut data = vec![1, 2, 3, 4, 5];
    let dummy_mac = tink_testutil::DummyMac {
        name: "Mac12347".to_string(),
    };
    let digest = dummy_mac.compute_mac(&data).unwrap();
    data.extend_from_slice(dummy_mac.name.as_bytes());
    assert_eq!(data, digest, "incorrect digest");
    dummy_mac
        .verify_mac(&digest, &data)
        .expect("unexpected result of verify_mac");
}

#[test]
fn test_uniform_string() {
    tink_testutil::z_test_uniform_string(&[0xaau8; 32])
        .expect("Expected repeated 0xaa string to pass");
    assert!(
        tink_testutil::z_test_uniform_string(&[0x00u8; 32]).is_err(),
        "Expected to fail uniform distribution test for 32 zero bytes"
    );
    let r1 = get_random_bytes(32);
    tink_testutil::z_test_uniform_string(&r1)
        .expect("Expected random string to pass randomness test");
}

#[test]
fn test_cross_correlation_uniform_string() {
    tink_testutil::z_test_crosscorrelation_uniform_strings(&[0xaau8; 32], &[0x99u8; 32])
        .expect("Expected 0xaa and 0x99 repeated 32 times each to have no cross correlation");
    assert!(
        tink_testutil::z_test_crosscorrelation_uniform_strings(&[0xaau8; 32], &[0xaau8; 32])
            .is_err(),
        "Expected 0xaa repeated 32 times to be cross correlated with itself"
    );
    let r1 = get_random_bytes(32);
    let r2 = get_random_bytes(32);
    tink_testutil::z_test_crosscorrelation_uniform_strings(&r1, &r2)
        .expect("Expected random 32 byte strings to not be crosscorrelated");
}

#[test]
fn test_autocorrelation_uniform_string() {
    assert!(
        tink_testutil::z_test_autocorrelation_uniform_string(&[0xaau8; 32]).is_err(),
        "Expected repeated string to show autocorrelation"
    );
    assert!(
        tink_testutil::z_test_autocorrelation_uniform_string(
            "This is a text that is only ascii characters and therefore \
not random. It needs quite a few characters before it has \
enough to find a pattern, though, as it is text."
                .as_bytes(),
        )
        .is_err(),
        "Expected longish English ASCII test to be autocorrelated"
    );
    let r1 = get_random_bytes(32);
    tink_testutil::z_test_autocorrelation_uniform_string(&r1)
        .expect("Expected random 32 byte string to show not autocorrelation");
}

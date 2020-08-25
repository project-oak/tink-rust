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

use tink::subtle::random::get_random_bytes;

// TODO: more ECDSA curves
#[test]
#[ignore]
fn test_signer_verify_factory() {
    let (tink_priv, tink_pub) = new_ecdsa_keyset_keypair(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP521,
        tink::proto::OutputPrefixType::Tink,
        1,
    );
    let (legacy_priv, legacy_pub) = new_ecdsa_keyset_keypair(
        tink::proto::HashType::Sha256,
        tink::proto::EllipticCurveType::NistP256,
        tink::proto::OutputPrefixType::Legacy,
        2,
    );
    let (raw_priv, raw_pub) = new_ecdsa_keyset_keypair(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP384,
        tink::proto::OutputPrefixType::Raw,
        3,
    );
    let (crunchy_priv, crunchy_pub) = new_ecdsa_keyset_keypair(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP384,
        tink::proto::OutputPrefixType::Crunchy,
        4,
    );
    let priv_keys = vec![tink_priv, legacy_priv, raw_priv, crunchy_priv];
    let priv_keyset = tink_testutil::new_keyset(priv_keys[0].key_id, priv_keys);
    let priv_keyset_handle = tink::keyset::insecure::new_handle(priv_keyset).unwrap();
    let pub_keys = vec![tink_pub, legacy_pub, raw_pub, crunchy_pub];
    let pub_keyset = tink_testutil::new_keyset(pub_keys[0].key_id, pub_keys);
    let pub_keyset_handle = tink::keyset::insecure::new_handle(pub_keyset).unwrap();

    // sign some random data
    let signer =
        tink_signature::new_signer(&priv_keyset_handle).expect("getting sign primitive failed");
    let data = get_random_bytes(1211);
    let sig = signer.sign(&data).expect("signing failed");

    // verify with the same set of public keys should work
    let verifier =
        tink_signature::new_verifier(&pub_keyset_handle).expect("getting verify primitive failed");
    assert!(verifier.verify(&sig, &data).is_ok(), "verification failed");

    // verify with random key should fail
    let (_, random_pub) = new_ecdsa_keyset_keypair(
        tink::proto::HashType::Sha512,
        tink::proto::EllipticCurveType::NistP521,
        tink::proto::OutputPrefixType::Tink,
        1,
    );
    let pub_keys = vec![random_pub];
    let pub_keyset = tink_testutil::new_keyset(pub_keys[0].key_id, pub_keys);
    let pub_keyset_handle = tink::keyset::insecure::new_handle(pub_keyset).unwrap();
    let verifier =
        tink_signature::new_verifier(&pub_keyset_handle).expect("getting verify primitive failed");
    assert!(
        verifier.verify(&sig, &data).is_err(),
        "verification with random key should fail"
    );
}

fn new_ecdsa_keyset_keypair(
    hash_type: tink::proto::HashType,
    curve: tink::proto::EllipticCurveType,
    output_prefix_type: tink::proto::OutputPrefixType,
    key_id: u32,
) -> (tink::proto::keyset::Key, tink::proto::keyset::Key) {
    let key = tink_testutil::new_random_ecdsa_private_key(hash_type, curve);
    let serialized_key = tink_testutil::proto_encode(&key);
    let key_data = tink_testutil::new_key_data(
        tink_testutil::ECDSA_SIGNER_TYPE_URL,
        &serialized_key,
        tink::proto::key_data::KeyMaterialType::AsymmetricPrivate,
    );
    let priv_key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        key_id,
        output_prefix_type,
    );

    let serialized_key = tink_testutil::proto_encode(&key.public_key.unwrap());
    let key_data = tink_testutil::new_key_data(
        tink_testutil::ECDSA_VERIFIER_TYPE_URL,
        &serialized_key,
        tink::proto::key_data::KeyMaterialType::AsymmetricPublic,
    );
    let pub_key = tink_testutil::new_key(
        &key_data,
        tink::proto::KeyStatusType::Enabled,
        key_id,
        output_prefix_type,
    );
    (priv_key, pub_key)
}

#[test]
fn test_factory_with_invalid_primitive_set_type() {
    tink_signature::init();
    tink_mac::init();
    let wrong_kh = tink::keyset::Handle::new(&tink_mac::hmac_sha256_tag128_key_template())
        .expect("failed to build keyset::Handle");

    assert!(
        tink_signature::new_signer(&wrong_kh).is_err(),
        "calling new_signer() with wrong keyset::Handle should fail"
    );

    assert!(
        tink_signature::new_verifier(&wrong_kh).is_err(),
        "calling new_verifier() with wrong keyset::Handle should fail"
    );
}

#[test]
fn test_factory_with_valid_primitive_set_type() {
    tink_signature::init();
    let good_kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template())
        .expect("failed to build keyset::Handle");

    assert!(
        tink_signature::new_signer(&good_kh).is_ok(),
        "calling new_signer() with good keyset::Handle failed"
    );

    let good_public_kh = good_kh.public().expect("failed to get public key");

    assert!(
        tink_signature::new_verifier(&good_public_kh).is_ok(),
        "calling new_verifier() with good keyset::handle failed"
    );
}

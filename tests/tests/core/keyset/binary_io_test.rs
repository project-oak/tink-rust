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

use tink_core::keyset::{Reader, Writer};

#[test]
fn test_binary_io_unencrypted() {
    tink_mac::init();

    let manager = tink_tests::new_hmac_keyset_manager();
    let h = manager.handle().expect("cannot get keyset handle");
    let ks1 = tink_core::keyset::insecure::keyset_material(&h);

    let mut buf = Vec::new();
    {
        let mut w = tink_core::keyset::BinaryWriter::new(&mut buf);
        w.write(&ks1).expect("cannot write keyset");
    }

    let mut r = tink_core::keyset::BinaryReader::new(&buf[..]);
    let ks2 = r.read().expect("cannot read keyset");
    assert_eq!(
        ks1, ks2,
        "written keyset ({ks1:?}) doesn't match read keyset ({ks2:?})",
    );
}

#[test]
fn test_binary_io_encrypted() {
    let kse1 = tink_proto::EncryptedKeyset {
        encrypted_keyset: vec![b'A'; 32],
        keyset_info: None,
    };

    let mut buf = Vec::new();
    {
        let mut w = tink_core::keyset::BinaryWriter::new(&mut buf);
        w.write_encrypted(&kse1)
            .expect("cannot write encrypted keyset");
    }

    let mut r = tink_core::keyset::BinaryReader::new(&buf[..]);
    let kse2 = r.read_encrypted().expect("cannot read encrypted keyset");
    assert_eq!(
        kse1, kse2,
        "written encrypted keyset ({kse1:?}) doesn't match read encrypted keyset ({kse2:?})",
    );
}

#[test]
fn test_binary_io_read_fail() {
    let mut r = tink_core::keyset::BinaryReader::new(tink_tests::IoFailure {});
    let result = r.read();
    tink_tests::expect_err(result, "read failed");

    let buf = vec![1, 2, 3];
    let mut r = tink_core::keyset::BinaryReader::new(&buf[..]);
    let result = r.read();
    tink_tests::expect_err(result, "decode failed");
}

#[test]
fn test_binary_io_write_fail() {
    tink_mac::init();
    let manager = tink_tests::new_hmac_keyset_manager();
    let h = manager.handle().expect("cannot get keyset handle");
    let ks = tink_core::keyset::insecure::keyset_material(&h);

    let mut failing_writer = tink_tests::IoFailure {};
    let mut w = tink_core::keyset::BinaryWriter::new(&mut failing_writer);
    let result = w.write(&ks);
    tink_tests::expect_err(result, "write failed");
}

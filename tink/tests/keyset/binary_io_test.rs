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

use super::SharedBuf;
use tink::keyset::{Reader, Writer};

#[test]
fn test_binary_io_unencrypted() {
    tink_mac::init();
    let buf = SharedBuf::new();
    let mut w = tink::keyset::BinaryWriter::new(buf.clone());
    let mut r = tink::keyset::BinaryReader::new(buf);

    let manager = tink_testutil::new_hmac_keyset_manager();
    let h = manager.handle().expect("cannot get keyset handle");

    let ks1 = tink::keyset::insecure::keyset_material(&h);
    w.write(&ks1).expect("cannot write keyset");

    let ks2 = r.read().expect("cannot read keyset");
    assert_eq!(
        ks1, ks2,
        "written keyset ({:?}) doesn't match read keyset ({:?})",
        ks1, ks2
    );
}

#[test]
fn test_binary_io_encrypted() {
    let buf = SharedBuf::new();
    let mut w = tink::keyset::BinaryWriter::new(buf.clone());
    let mut r = tink::keyset::BinaryReader::new(buf);

    let kse1 = tink::proto::EncryptedKeyset {
        encrypted_keyset: vec![b'A'; 32],
        keyset_info: None,
    };
    w.write_encrypted(&kse1)
        .expect("cannot write encrypted keyset");

    let kse2 = r.read_encrypted().expect("cannot read encrypted keyset");
    assert_eq!(
        kse1, kse2,
        "written encrypted keyset ({:?}) doesn't match read encrypted keyset ({:?})",
        kse1, kse2
    );
}

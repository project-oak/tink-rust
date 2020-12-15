// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

//! Testing server for AEAD.

use crate::proto;

#[derive(Debug, Default)]
pub struct AeadServerImpl;

#[tonic::async_trait]
impl proto::aead_server::Aead for AeadServerImpl {
    async fn encrypt(
        &self,
        request: tonic::Request<proto::AeadEncryptRequest>,
    ) -> Result<tonic::Response<proto::AeadEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let cipher = tink_aead::new(&handle)?;
            cipher.encrypt(&req.plaintext, &req.associated_data)
        };
        Ok(tonic::Response::new(proto::AeadEncryptResponse {
            result: Some(match closure() {
                Ok(ct) => proto::aead_encrypt_response::Result::Ciphertext(ct),
                Err(e) => proto::aead_encrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<proto::AeadDecryptRequest>,
    ) -> Result<tonic::Response<proto::AeadDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let cipher = tink_aead::new(&handle)?;
            cipher.decrypt(&req.ciphertext, &req.associated_data)
        };
        Ok(tonic::Response::new(proto::AeadDecryptResponse {
            result: Some(match closure() {
                Ok(pt) => proto::aead_decrypt_response::Result::Plaintext(pt),
                Err(e) => proto::aead_decrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
}

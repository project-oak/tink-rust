// Copyright 2021 The Tink-Rust Authors
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

//! Testing server for hybrid encryption

use crate::proto;

#[derive(Debug, Default)]
pub struct HybridServerImpl;

#[tonic::async_trait]
impl proto::hybrid_server::Hybrid for HybridServerImpl {
    async fn encrypt(
        &self,
        request: tonic::Request<proto::HybridEncryptRequest>,
    ) -> Result<tonic::Response<proto::HybridEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.public_keyset);
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)?;
            let cipher = tink_hybrid::new_encrypt(&handle)?;
            cipher.encrypt(&req.plaintext, &req.context_info)
        };
        Ok(tonic::Response::new(proto::HybridEncryptResponse {
            result: Some(match closure() {
                Ok(ct) => proto::hybrid_encrypt_response::Result::Ciphertext(ct),
                Err(e) => proto::hybrid_encrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<proto::HybridDecryptRequest>,
    ) -> Result<tonic::Response<proto::HybridDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.private_keyset);
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)?;
            let cipher = tink_hybrid::new_decrypt(&handle)?;
            cipher.decrypt(&req.ciphertext, &req.context_info)
        };

        Ok(tonic::Response::new(proto::HybridDecryptResponse {
            result: Some(match closure() {
                Ok(pt) => proto::hybrid_decrypt_response::Result::Plaintext(pt),
                Err(e) => proto::hybrid_decrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
}

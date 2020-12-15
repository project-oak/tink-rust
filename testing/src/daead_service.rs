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

//! Testing server for DAEAD.

use crate::proto;

#[derive(Debug, Default)]
pub struct DaeadServerImpl;

#[tonic::async_trait]
impl proto::deterministic_aead_server::DeterministicAead for DaeadServerImpl {
    async fn encrypt_deterministically(
        &self,
        request: tonic::Request<proto::DeterministicAeadEncryptRequest>,
    ) -> Result<tonic::Response<proto::DeterministicAeadEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let cipher = tink_daead::new(&handle)?;
            cipher.encrypt_deterministically(&req.plaintext, &req.associated_data)
        };
        Ok(tonic::Response::new(
            proto::DeterministicAeadEncryptResponse {
                result: Some(match closure() {
                    Ok(ct) => proto::deterministic_aead_encrypt_response::Result::Ciphertext(ct),
                    Err(e) => {
                        proto::deterministic_aead_encrypt_response::Result::Err(format!("{:?}", e))
                    }
                }),
            },
        ))
    }

    async fn decrypt_deterministically(
        &self,
        request: tonic::Request<proto::DeterministicAeadDecryptRequest>,
    ) -> Result<tonic::Response<proto::DeterministicAeadDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let cipher = tink_daead::new(&handle)?;
            cipher.decrypt_deterministically(&req.ciphertext, &req.associated_data)
        };

        Ok(tonic::Response::new(
            proto::DeterministicAeadDecryptResponse {
                result: Some(match closure() {
                    Ok(pt) => proto::deterministic_aead_decrypt_response::Result::Plaintext(pt),
                    Err(e) => {
                        proto::deterministic_aead_decrypt_response::Result::Err(format!("{:?}", e))
                    }
                }),
            },
        ))
    }
}

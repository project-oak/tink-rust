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
pub struct DaeadServerImpl {}

#[tonic::async_trait]
impl proto::deterministic_aead_server::DeterministicAead for DaeadServerImpl {
    async fn encrypt_deterministically(
        &self,
        request: tonic::Request<proto::DeterministicAeadEncryptRequest>,
    ) -> Result<tonic::Response<proto::DeterministicAeadEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return encrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let cipher = match tink_daead::new(&handle) {
            Err(e) => return encrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let ciphertext =
            match cipher.encrypt_deterministically(&req.plaintext, &req.associated_data) {
                Err(e) => return encrypt_rsp_from_err(e),
                Ok(v) => v,
            };
        Ok(tonic::Response::new(
            proto::DeterministicAeadEncryptResponse {
                result: Some(
                    proto::deterministic_aead_encrypt_response::Result::Ciphertext(ciphertext),
                ),
            },
        ))
    }

    async fn decrypt_deterministically(
        &self,
        request: tonic::Request<proto::DeterministicAeadDecryptRequest>,
    ) -> Result<tonic::Response<proto::DeterministicAeadDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return decrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let cipher = match tink_daead::new(&handle) {
            Err(e) => return decrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let plaintext =
            match cipher.decrypt_deterministically(&req.ciphertext, &req.associated_data) {
                Err(e) => return decrypt_rsp_from_err(e),
                Ok(v) => v,
            };
        Ok(tonic::Response::new(
            proto::DeterministicAeadDecryptResponse {
                result: Some(
                    proto::deterministic_aead_decrypt_response::Result::Plaintext(plaintext),
                ),
            },
        ))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn encrypt_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::DeterministicAeadEncryptResponse>, tonic::Status> {
    Ok(tonic::Response::new(
        proto::DeterministicAeadEncryptResponse {
            result: Some(proto::deterministic_aead_encrypt_response::Result::Err(
                format!("{:?}", e),
            )),
        },
    ))
}
fn decrypt_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::DeterministicAeadDecryptResponse>, tonic::Status> {
    Ok(tonic::Response::new(
        proto::DeterministicAeadDecryptResponse {
            result: Some(proto::deterministic_aead_decrypt_response::Result::Err(
                format!("{:?}", e),
            )),
        },
    ))
}

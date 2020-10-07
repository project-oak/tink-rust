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
pub struct AeadServerImpl {}

#[tonic::async_trait]
impl proto::aead_server::Aead for AeadServerImpl {
    async fn encrypt(
        &self,
        request: tonic::Request<proto::AeadEncryptRequest>,
    ) -> Result<tonic::Response<proto::AeadEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return encrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let cipher = match tink_aead::new(&handle) {
            Err(e) => return encrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let ciphertext = match cipher.encrypt(&req.plaintext, &req.associated_data) {
            Err(e) => return encrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::AeadEncryptResponse {
            result: Some(proto::aead_encrypt_response::Result::Ciphertext(ciphertext)),
        }))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<proto::AeadDecryptRequest>,
    ) -> Result<tonic::Response<proto::AeadDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return decrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let cipher = match tink_aead::new(&handle) {
            Err(e) => return decrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        let plaintext = match cipher.decrypt(&req.ciphertext, &req.associated_data) {
            Err(e) => return decrypt_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::AeadDecryptResponse {
            result: Some(proto::aead_decrypt_response::Result::Plaintext(plaintext)),
        }))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn encrypt_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::AeadEncryptResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::AeadEncryptResponse {
        result: Some(proto::aead_encrypt_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}
fn decrypt_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::AeadDecryptResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::AeadDecryptResponse {
        result: Some(proto::aead_decrypt_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

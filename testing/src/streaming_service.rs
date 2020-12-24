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

//! Testing server for streaming AEAD.

use crate::proto;
use tink::{utils::wrap_err, TinkError};
use tink_tests::SharedBuf;

#[derive(Debug, Default)]
pub struct StreamingAeadServerImpl;

#[tonic::async_trait]
impl proto::streaming_aead_server::StreamingAead for StreamingAeadServerImpl {
    async fn encrypt(
        &self,
        request: tonic::Request<proto::StreamingAeadEncryptRequest>,
    ) -> Result<tonic::Response<proto::StreamingAeadEncryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)
                .map_err(|e| wrap_err("read failed", e))?;
            let primitive = tink_streaming_aead::new(&handle)?;
            let buf = SharedBuf::new();
            {
                let mut writer =
                    primitive.new_encrypting_writer(Box::new(buf.clone()), &req.associated_data)?;
                writer
                    .write_all(&req.plaintext)
                    .map_err(|e| wrap_err("write failed", e))?;
                writer.close().map_err(|e| wrap_err("close failed", e))?;
            }
            Ok(buf.contents())
        };
        Ok(tonic::Response::new(proto::StreamingAeadEncryptResponse {
            result: Some(match closure() {
                Ok(ct) => proto::streaming_aead_encrypt_response::Result::Ciphertext(ct),
                Err(e) => proto::streaming_aead_encrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }

    async fn decrypt(
        &self,
        request: tonic::Request<proto::StreamingAeadDecryptRequest>,
    ) -> Result<tonic::Response<proto::StreamingAeadDecryptResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)
                .map_err(|e| wrap_err("read failed", e))?;
            let primitive = tink_streaming_aead::new(&handle)?;
            let mut reader = primitive.new_decrypting_reader(
                Box::new(std::io::Cursor::new(req.ciphertext)),
                &req.associated_data,
            )?;
            let mut buf = Vec::new();
            reader
                .read_to_end(&mut buf)
                .map_err(|e| wrap_err("read failed", e))?;
            Ok(buf)
        };
        Ok(tonic::Response::new(proto::StreamingAeadDecryptResponse {
            result: Some(match closure() {
                Ok(pt) => proto::streaming_aead_decrypt_response::Result::Plaintext(pt),
                Err(e) => proto::streaming_aead_decrypt_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
}

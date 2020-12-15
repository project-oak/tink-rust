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

//! Testing server for signatures.

use crate::proto;

#[derive(Debug, Default)]
pub struct SignatureServerImpl;

#[tonic::async_trait]
impl proto::signature_server::Signature for SignatureServerImpl {
    async fn sign(
        &self,
        request: tonic::Request<proto::SignatureSignRequest>,
    ) -> Result<tonic::Response<proto::SignatureSignResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.private_keyset.clone());
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let signer = tink_signature::new_signer(&handle)?;
            signer.sign(&req.data)
        };
        Ok(tonic::Response::new(proto::SignatureSignResponse {
            result: Some(match closure() {
                Ok(sig) => proto::signature_sign_response::Result::Signature(sig),
                Err(e) => proto::signature_sign_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }

    async fn verify(
        &self,
        request: tonic::Request<proto::SignatureVerifyRequest>,
    ) -> Result<tonic::Response<proto::SignatureVerifyResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.public_keyset.clone());
            let mut reader = tink::keyset::BinaryReader::new(cursor);
            let handle = tink::keyset::insecure::read(&mut reader)?;
            let verifier = tink_signature::new_verifier(&handle)?;
            verifier.verify(&req.signature, &req.data)
        };
        Ok(tonic::Response::new(proto::SignatureVerifyResponse {
            err: match closure() {
                Ok(_) => "".to_string(),
                Err(e) => format!("{:?}", e),
            },
        }))
    }
}

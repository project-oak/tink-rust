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
pub struct SignatureServerImpl {}

#[tonic::async_trait]
impl proto::signature_server::Signature for SignatureServerImpl {
    async fn sign(
        &self,
        request: tonic::Request<proto::SignatureSignRequest>,
    ) -> Result<tonic::Response<proto::SignatureSignResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.private_keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return sign_rsp_from_err(e),
            Ok(v) => v,
        };
        let signer = match tink_signature::new_signer(&handle) {
            Err(e) => return sign_rsp_from_err(e),
            Ok(v) => v,
        };
        let sig_value = match signer.sign(&req.data) {
            Err(e) => return sign_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::SignatureSignResponse {
            result: Some(proto::signature_sign_response::Result::Signature(sig_value)),
        }))
    }

    async fn verify(
        &self,
        request: tonic::Request<proto::SignatureVerifyRequest>,
    ) -> Result<tonic::Response<proto::SignatureVerifyResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.public_keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(v) => v,
        };
        let verifier = match tink_signature::new_verifier(&handle) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(v) => v,
        };
        match verifier.verify(&req.signature, &req.data) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(()) => {}
        };
        Ok(tonic::Response::new(proto::SignatureVerifyResponse {
            err: "".to_string(),
        }))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn sign_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::SignatureSignResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::SignatureSignResponse {
        result: Some(proto::signature_sign_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}
fn verify_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::SignatureVerifyResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::SignatureVerifyResponse {
        err: format!("{:?}", e),
    }))
}

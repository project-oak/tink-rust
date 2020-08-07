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

//! Testing server for MAC.

use crate::proto;

#[derive(Debug, Default)]
pub struct MacServerImpl {}

#[tonic::async_trait]
impl proto::mac_server::Mac for MacServerImpl {
    async fn compute_mac(
        &self,
        request: tonic::Request<proto::ComputeMacRequest>,
    ) -> Result<tonic::Response<proto::ComputeMacResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        let primitive = match tink_mac::new(&handle) {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        let mac_value = match primitive.compute_mac(&req.data) {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::ComputeMacResponse {
            result: Some(proto::compute_mac_response::Result::MacValue(mac_value)),
        }))
    }
    async fn verify_mac(
        &self,
        request: tonic::Request<proto::VerifyMacRequest>,
    ) -> Result<tonic::Response<proto::VerifyMacResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(v) => v,
        };
        let primitive = match tink_mac::new(&handle) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(v) => v,
        };
        match primitive.verify_mac(&req.mac_value, &req.data) {
            Err(e) => return verify_rsp_from_err(e),
            Ok(()) => {}
        };
        Ok(tonic::Response::new(proto::VerifyMacResponse {
            err: "".to_string(),
        }))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn compute_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::ComputeMacResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::ComputeMacResponse {
        result: Some(proto::compute_mac_response::Result::Err(format!("{:?}", e))),
    }))
}

fn verify_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::VerifyMacResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::VerifyMacResponse {
        err: format!("{:?}", e),
    }))
}

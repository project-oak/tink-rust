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

//! Testing server for PRF.

use crate::proto;

#[derive(Debug, Default)]
pub struct PrfSetServerImpl {}

#[tonic::async_trait]
impl proto::prf_set_server::PrfSet for PrfSetServerImpl {
    async fn key_ids(
        &self,
        request: tonic::Request<proto::PrfSetKeyIdsRequest>,
    ) -> Result<tonic::Response<proto::PrfSetKeyIdsResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return key_ids_rsp_from_err(e),
            Ok(v) => v,
        };
        let primitive = match tink_prf::Set::new(&handle) {
            Err(e) => return key_ids_rsp_from_err(e),
            Ok(v) => v,
        };
        let mut output = proto::prf_set_key_ids_response::Output {
            primary_key_id: primitive.primary_id,
            key_id: Vec::new(),
        };
        for key_id in primitive.prfs.keys() {
            output.key_id.push(*key_id);
        }
        Ok(tonic::Response::new(proto::PrfSetKeyIdsResponse {
            result: Some(proto::prf_set_key_ids_response::Result::Output(output)),
        }))
    }
    async fn compute(
        &self,
        request: tonic::Request<proto::PrfSetComputeRequest>,
    ) -> Result<tonic::Response<proto::PrfSetComputeResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        let primitive = match tink_prf::Set::new(&handle) {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        let output = match primitive.prfs[&req.key_id]
            .compute_prf(&req.input_data, req.output_length as usize)
        {
            Err(e) => return compute_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::PrfSetComputeResponse {
            result: Some(proto::prf_set_compute_response::Result::Output(output)),
        }))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn key_ids_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::PrfSetKeyIdsResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::PrfSetKeyIdsResponse {
        result: Some(proto::prf_set_key_ids_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

fn compute_rsp_from_err(
    e: tink::TinkError,
) -> Result<tonic::Response<proto::PrfSetComputeResponse>, tonic::Status> {
    Ok(tonic::Response::new(proto::PrfSetComputeResponse {
        result: Some(proto::prf_set_compute_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

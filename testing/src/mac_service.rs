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
pub struct MacServerImpl;

#[tonic::async_trait]
impl proto::mac_server::Mac for MacServerImpl {
    async fn compute_mac(
        &self,
        request: tonic::Request<proto::ComputeMacRequest>,
    ) -> Result<tonic::Response<proto::ComputeMacResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset.clone());
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)?;
            let primitive = tink_mac::new(&handle)?;
            primitive.compute_mac(&req.data)
        };
        Ok(tonic::Response::new(proto::ComputeMacResponse {
            result: Some(match closure() {
                Ok(mac) => proto::compute_mac_response::Result::MacValue(mac),
                Err(e) => proto::compute_mac_response::Result::Err(format!("{e:?}")),
            }),
        }))
    }
    async fn verify_mac(
        &self,
        request: tonic::Request<proto::VerifyMacRequest>,
    ) -> Result<tonic::Response<proto::VerifyMacResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || {
            let cursor = std::io::Cursor::new(req.keyset.clone());
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)?;
            let primitive = tink_mac::new(&handle)?;
            primitive.verify_mac(&req.mac_value, &req.data)
        };
        Ok(tonic::Response::new(proto::VerifyMacResponse {
            err: match closure() {
                Ok(_) => "".to_string(),
                Err(e) => format!("{e:?}"),
            },
        }))
    }
}

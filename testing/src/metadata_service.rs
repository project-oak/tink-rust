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

//! Testing server for metadata.

#[derive(Debug, Default)]
pub struct MetadataServerImpl;

#[tonic::async_trait]
impl crate::proto::metadata_server::Metadata for MetadataServerImpl {
    async fn get_server_info(
        &self,
        _request: tonic::Request<crate::proto::ServerInfoRequest>,
    ) -> Result<tonic::Response<crate::proto::ServerInfoResponse>, tonic::Status> {
        Ok(tonic::Response::new(crate::proto::ServerInfoResponse {
            language: "rust".to_string(),
            tink_version: "".to_string(),
        }))
    }
}

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

//! Testing server for keyset manipulation.

use crate::proto;
use prost::Message;
use tink_core::{utils::wrap_err, TinkError};

#[derive(Debug, Default)]
pub struct KeysetServerImpl;

#[tonic::async_trait]
impl proto::keyset_server::Keyset for KeysetServerImpl {
    async fn generate(
        &self,
        request: tonic::Request<proto::KeysetGenerateRequest>,
    ) -> Result<tonic::Response<proto::KeysetGenerateResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let template = tink_proto::KeyTemplate::decode(req.template.as_ref())
                .map_err(|e| wrap_err("decode failed", e))?;
            let handle = tink_core::keyset::Handle::new(&template)?;
            let mut buf = Vec::new();
            {
                let mut writer = tink_core::keyset::BinaryWriter::new(&mut buf);
                tink_core::keyset::insecure::write(&handle, &mut writer)
                    .map_err(|e| wrap_err("write failed", e))?;
            }
            Ok(buf)
        };
        Ok(tonic::Response::new(proto::KeysetGenerateResponse {
            result: Some(match closure() {
                Ok(buf) => proto::keyset_generate_response::Result::Keyset(buf),
                Err(e) => proto::keyset_generate_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
    async fn public(
        &self,
        request: tonic::Request<proto::KeysetPublicRequest>,
    ) -> Result<tonic::Response<proto::KeysetPublicResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let cursor = std::io::Cursor::new(req.private_keyset);
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let private_handle = tink_core::keyset::insecure::read(&mut reader)
                .map_err(|e| wrap_err("read failed", e))?;
            let public_handle = private_handle.public()?;
            let mut buf = Vec::new();
            {
                let mut writer = tink_core::keyset::BinaryWriter::new(&mut buf);
                tink_core::keyset::insecure::write(&public_handle, &mut writer)
                    .map_err(|e| wrap_err("write failed", e))?;
            }
            Ok(buf)
        };
        Ok(tonic::Response::new(proto::KeysetPublicResponse {
            result: Some(match closure() {
                Ok(buf) => proto::keyset_public_response::Result::PublicKeyset(buf),
                Err(e) => proto::keyset_public_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
    async fn to_json(
        &self,
        request: tonic::Request<proto::KeysetToJsonRequest>,
    ) -> Result<tonic::Response<proto::KeysetToJsonResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let cursor = std::io::Cursor::new(req.keyset);
            let mut reader = tink_core::keyset::BinaryReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)
                .map_err(|e| wrap_err("read failed", e))?;
            let mut buf = Vec::new();
            {
                let mut writer = tink_core::keyset::JsonWriter::new(&mut buf);
                tink_core::keyset::insecure::write(&handle, &mut writer)
                    .map_err(|e| wrap_err("write failed", e))?;
            }
            let json = std::str::from_utf8(&buf).map_err(|e| wrap_err("utf8 failed", e))?;
            Ok(json.to_string())
        };
        Ok(tonic::Response::new(proto::KeysetToJsonResponse {
            result: Some(match closure() {
                Ok(json) => proto::keyset_to_json_response::Result::JsonKeyset(json),
                Err(e) => proto::keyset_to_json_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
    async fn from_json(
        &self,
        request: tonic::Request<proto::KeysetFromJsonRequest>,
    ) -> Result<tonic::Response<proto::KeysetFromJsonResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let closure = move || -> Result<_, TinkError> {
            let cursor = std::io::Cursor::new(req.json_keyset.as_bytes());
            let mut reader = tink_core::keyset::JsonReader::new(cursor);
            let handle = tink_core::keyset::insecure::read(&mut reader)
                .map_err(|e| wrap_err("read failed", e))?;
            let mut buf = Vec::new();
            {
                let mut writer = tink_core::keyset::BinaryWriter::new(&mut buf);
                tink_core::keyset::insecure::write(&handle, &mut writer)
                    .map_err(|e| wrap_err("write failed", e))?;
            }
            Ok(buf)
        };
        Ok(tonic::Response::new(proto::KeysetFromJsonResponse {
            result: Some(match closure() {
                Ok(buf) => proto::keyset_from_json_response::Result::Keyset(buf),
                Err(e) => proto::keyset_from_json_response::Result::Err(format!("{:?}", e)),
            }),
        }))
    }
}

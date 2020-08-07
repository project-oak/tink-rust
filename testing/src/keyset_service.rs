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

#[derive(Debug, Default)]
pub struct KeysetServerImpl {}

#[tonic::async_trait]
impl proto::keyset_server::Keyset for KeysetServerImpl {
    async fn generate(
        &self,
        request: tonic::Request<proto::KeysetGenerateRequest>,
    ) -> Result<tonic::Response<proto::KeysetGenerateResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let template = match tink::proto::KeyTemplate::decode(req.template.as_ref()) {
            Err(e) => return generate_rsp_from_err(e),
            Ok(v) => v,
        };
        let handle = match tink::keyset::Handle::new(&template) {
            Err(e) => return generate_rsp_from_err(e),
            Ok(v) => v,
        };
        let mut buf = Vec::new();
        {
            let mut writer = tink::keyset::BinaryWriter::new(&mut buf);
            match tink::keyset::insecure::write(&handle, &mut writer) {
                Err(e) => return generate_rsp_from_err(e),
                Ok(()) => {}
            }
        }
        Ok(tonic::Response::new(proto::KeysetGenerateResponse {
            result: Some(proto::keyset_generate_response::Result::Keyset(buf)),
        }))
    }
    async fn public(
        &self,
        request: tonic::Request<proto::KeysetPublicRequest>,
    ) -> Result<tonic::Response<proto::KeysetPublicResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.private_keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let private_handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return public_rsp_from_err(e),
            Ok(v) => v,
        };
        let public_handle = match private_handle.public() {
            Err(e) => return public_rsp_from_err(e),
            Ok(v) => v,
        };
        let mut buf = Vec::new();
        {
            let mut writer = tink::keyset::BinaryWriter::new(&mut buf);
            match tink::keyset::insecure::write(&public_handle, &mut writer) {
                Err(e) => return public_rsp_from_err(e),
                Ok(()) => {}
            }
        }
        Ok(tonic::Response::new(proto::KeysetPublicResponse {
            result: Some(proto::keyset_public_response::Result::PublicKeyset(buf)),
        }))
    }
    async fn to_json(
        &self,
        request: tonic::Request<proto::KeysetToJsonRequest>,
    ) -> Result<tonic::Response<proto::KeysetToJsonResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.keyset);
        let mut reader = tink::keyset::BinaryReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return to_json_rsp_from_err(e),
            Ok(v) => v,
        };
        let mut buf = Vec::new();
        {
            let mut writer = tink::keyset::JsonWriter::new(&mut buf);
            match tink::keyset::insecure::write(&handle, &mut writer) {
                Err(e) => return to_json_rsp_from_err(e),
                Ok(()) => {}
            }
        }
        let json = match std::str::from_utf8(&buf) {
            Err(e) => return to_json_rsp_from_err(e),
            Ok(v) => v,
        };
        Ok(tonic::Response::new(proto::KeysetToJsonResponse {
            result: Some(proto::keyset_to_json_response::Result::JsonKeyset(
                json.to_string(),
            )),
        }))
    }
    async fn from_json(
        &self,
        request: tonic::Request<proto::KeysetFromJsonRequest>,
    ) -> Result<tonic::Response<proto::KeysetFromJsonResponse>, tonic::Status> {
        let req = request.into_inner(); // discard metadata
        let cursor = std::io::Cursor::new(req.json_keyset.as_bytes());
        let mut reader = tink::keyset::JsonReader::new(cursor);
        let handle = match tink::keyset::insecure::read(&mut reader) {
            Err(e) => return from_json_rsp_from_err(e),
            Ok(v) => v,
        };
        let mut buf = Vec::new();
        {
            let mut writer = tink::keyset::BinaryWriter::new(&mut buf);
            match tink::keyset::insecure::write(&handle, &mut writer) {
                Err(e) => return from_json_rsp_from_err(e),
                Ok(()) => {}
            }
        }
        Ok(tonic::Response::new(proto::KeysetFromJsonResponse {
            result: Some(proto::keyset_from_json_response::Result::Keyset(buf)),
        }))
    }
}

// The testing infrastructure expects errors to be included in the response,
// rather than using the gRPC error reporting mechanism.  Include helpers to
// make it easy to map `TinkError` instances to this.

fn generate_rsp_from_err<T>(
    e: T,
) -> Result<tonic::Response<proto::KeysetGenerateResponse>, tonic::Status>
where
    T: std::fmt::Debug,
{
    Ok(tonic::Response::new(proto::KeysetGenerateResponse {
        result: Some(proto::keyset_generate_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

fn public_rsp_from_err<T>(
    e: T,
) -> Result<tonic::Response<proto::KeysetPublicResponse>, tonic::Status>
where
    T: std::fmt::Debug,
{
    Ok(tonic::Response::new(proto::KeysetPublicResponse {
        result: Some(proto::keyset_public_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

fn to_json_rsp_from_err<T>(
    e: T,
) -> Result<tonic::Response<proto::KeysetToJsonResponse>, tonic::Status>
where
    T: std::fmt::Debug,
{
    Ok(tonic::Response::new(proto::KeysetToJsonResponse {
        result: Some(proto::keyset_to_json_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

fn from_json_rsp_from_err<T>(
    e: T,
) -> Result<tonic::Response<proto::KeysetFromJsonResponse>, tonic::Status>
where
    T: std::fmt::Debug,
{
    Ok(tonic::Response::new(proto::KeysetFromJsonResponse {
        result: Some(proto::keyset_from_json_response::Result::Err(format!(
            "{:?}",
            e
        ))),
    }))
}

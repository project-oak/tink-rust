// Copyright 2020 The Tink-Rust Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

//! Tink testing infrastructure.

use futures::future::FutureExt;
use log::info;
use structopt::StructOpt;
use tonic::transport::Server;

#[allow(clippy::wrong_self_convention)]
pub mod proto {
    //! Auto-generated code from protocol buffer message and service definitions.
    include!("codegen/tink_testing_api.rs");
}

mod aead_service;
use aead_service::*;
mod daead_service;
use daead_service::*;
mod keyset_service;
use keyset_service::*;
mod mac_service;
use mac_service::*;
mod metadata_service;
use metadata_service::*;
mod prf_set_service;
use prf_set_service::*;
mod signature_service;
use signature_service::*;
mod streaming_service;
use streaming_service::*;

/// Command-line options for Tink Rust testing server.
#[derive(Debug, StructOpt)]
#[structopt(about = "Tink test server")]
struct Opt {
    #[structopt(long, default_value = "10000", help = "Port number.")]
    port: u16,
}

/// Main entrypoint for Tink Rust testing server.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::from_args();
    env_logger::init();
    tink_aead::init();
    tink_daead::init();
    tink_mac::init();
    tink_prf::init();
    tink_signature::init();
    tink_streaming_aead::init();

    let client = tink_tests::fakekms::FakeClient::new("fake-kms://")
        .expect("Failed to generate new fakekms::FakeClient");
    tink_core::registry::register_kms_client(client);

    info!("Running testing server");

    let metadata_handler = MetadataServerImpl {};
    let keyset_handler = KeysetServerImpl {};
    let aead_handler = AeadServerImpl {};
    let daead_handler = DaeadServerImpl {};
    let mac_handler = MacServerImpl {};
    let prf_set_handler = PrfSetServerImpl {};
    let signature_handler = SignatureServerImpl {};
    let streaming_handler = StreamingAeadServerImpl {};

    let address = format!("[::]:{}", opt.port).parse()?;
    info!("Starting gRPC server at {:?}", address);
    Server::builder()
        .add_service(proto::metadata_server::MetadataServer::new(
            metadata_handler,
        ))
        .add_service(proto::keyset_server::KeysetServer::new(keyset_handler))
        .add_service(proto::aead_server::AeadServer::new(aead_handler))
        .add_service(proto::deterministic_aead_server::DeterministicAeadServer::new(daead_handler))
        .add_service(proto::mac_server::MacServer::new(mac_handler))
        .add_service(proto::prf_set_server::PrfSetServer::new(prf_set_handler))
        .add_service(proto::signature_server::SignatureServer::new(
            signature_handler,
        ))
        .add_service(proto::streaming_aead_server::StreamingAeadServer::new(
            streaming_handler,
        ))
        .serve_with_shutdown(address, tokio::signal::ctrl_c().map(|r| r.unwrap()))
        .await?;

    Ok(())
}

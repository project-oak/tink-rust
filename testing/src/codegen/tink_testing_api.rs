#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerInfoRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ServerInfoResponse {
    /// For example '1.4'
    #[prost(string, tag = "1")]
    pub tink_version: ::prost::alloc::string::String,
    /// For example 'cc', 'java', 'go' or 'python'.
    #[prost(string, tag = "2")]
    pub language: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetGenerateRequest {
    /// serialized google.crypto.tink.KeyTemplate.
    #[prost(bytes = "vec", tag = "1")]
    pub template: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetGenerateResponse {
    #[prost(oneof = "keyset_generate_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<keyset_generate_response::Result>,
}
/// Nested message and enum types in `KeysetGenerateResponse`.
pub mod keyset_generate_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// serialized google.crypto.tink.Keyset.
        #[prost(bytes, tag = "1")]
        Keyset(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetPublicRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub private_keyset: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetPublicResponse {
    #[prost(oneof = "keyset_public_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<keyset_public_response::Result>,
}
/// Nested message and enum types in `KeysetPublicResponse`.
pub mod keyset_public_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// serialized google.crypto.tink.Keyset.
        #[prost(bytes, tag = "1")]
        PublicKeyset(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetToJsonRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetToJsonResponse {
    #[prost(oneof = "keyset_to_json_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<keyset_to_json_response::Result>,
}
/// Nested message and enum types in `KeysetToJsonResponse`.
pub mod keyset_to_json_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(string, tag = "1")]
        JsonKeyset(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetFromJsonRequest {
    #[prost(string, tag = "1")]
    pub json_keyset: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetFromJsonResponse {
    #[prost(oneof = "keyset_from_json_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<keyset_from_json_response::Result>,
}
/// Nested message and enum types in `KeysetFromJsonResponse`.
pub mod keyset_from_json_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        /// serialized google.crypto.tink.Keyset.
        #[prost(bytes, tag = "1")]
        Keyset(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AeadEncryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AeadEncryptResponse {
    #[prost(oneof = "aead_encrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<aead_encrypt_response::Result>,
}
/// Nested message and enum types in `AeadEncryptResponse`.
pub mod aead_encrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Ciphertext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AeadDecryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AeadDecryptResponse {
    #[prost(oneof = "aead_decrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<aead_decrypt_response::Result>,
}
/// Nested message and enum types in `AeadDecryptResponse`.
pub mod aead_decrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Plaintext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeterministicAeadEncryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeterministicAeadEncryptResponse {
    #[prost(oneof = "deterministic_aead_encrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<deterministic_aead_encrypt_response::Result>,
}
/// Nested message and enum types in `DeterministicAeadEncryptResponse`.
pub mod deterministic_aead_encrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Ciphertext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeterministicAeadDecryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DeterministicAeadDecryptResponse {
    #[prost(oneof = "deterministic_aead_decrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<deterministic_aead_decrypt_response::Result>,
}
/// Nested message and enum types in `DeterministicAeadDecryptResponse`.
pub mod deterministic_aead_decrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Plaintext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamingAeadEncryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamingAeadEncryptResponse {
    #[prost(oneof = "streaming_aead_encrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<streaming_aead_encrypt_response::Result>,
}
/// Nested message and enum types in `StreamingAeadEncryptResponse`.
pub mod streaming_aead_encrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Ciphertext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamingAeadDecryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub associated_data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamingAeadDecryptResponse {
    #[prost(oneof = "streaming_aead_decrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<streaming_aead_decrypt_response::Result>,
}
/// Nested message and enum types in `StreamingAeadDecryptResponse`.
pub mod streaming_aead_decrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Plaintext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ComputeMacRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ComputeMacResponse {
    #[prost(oneof = "compute_mac_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<compute_mac_response::Result>,
}
/// Nested message and enum types in `ComputeMacResponse`.
pub mod compute_mac_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        MacValue(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyMacRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub mac_value: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct VerifyMacResponse {
    #[prost(string, tag = "1")]
    pub err: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HybridEncryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub public_keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub plaintext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub context_info: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HybridEncryptResponse {
    #[prost(oneof = "hybrid_encrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<hybrid_encrypt_response::Result>,
}
/// Nested message and enum types in `HybridEncryptResponse`.
pub mod hybrid_encrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Ciphertext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HybridDecryptRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub private_keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub context_info: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HybridDecryptResponse {
    #[prost(oneof = "hybrid_decrypt_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<hybrid_decrypt_response::Result>,
}
/// Nested message and enum types in `HybridDecryptResponse`.
pub mod hybrid_decrypt_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Plaintext(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureSignRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub private_keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureSignResponse {
    #[prost(oneof = "signature_sign_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<signature_sign_response::Result>,
}
/// Nested message and enum types in `SignatureSignResponse`.
pub mod signature_sign_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Signature(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureVerifyRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub public_keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signature: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub data: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureVerifyResponse {
    #[prost(string, tag = "1")]
    pub err: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfSetKeyIdsRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfSetKeyIdsResponse {
    #[prost(oneof = "prf_set_key_ids_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<prf_set_key_ids_response::Result>,
}
/// Nested message and enum types in `PrfSetKeyIdsResponse`.
pub mod prf_set_key_ids_response {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Output {
        #[prost(uint32, tag = "1")]
        pub primary_key_id: u32,
        #[prost(uint32, repeated, tag = "2")]
        pub key_id: ::prost::alloc::vec::Vec<u32>,
    }
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        Output(Output),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfSetComputeRequest {
    /// serialized google.crypto.tink.Keyset.
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint32, tag = "2")]
    pub key_id: u32,
    #[prost(bytes = "vec", tag = "3")]
    pub input_data: ::prost::alloc::vec::Vec<u8>,
    #[prost(int32, tag = "4")]
    pub output_length: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfSetComputeResponse {
    #[prost(oneof = "prf_set_compute_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<prf_set_compute_response::Result>,
}
/// Nested message and enum types in `PrfSetComputeResponse`.
pub mod prf_set_compute_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(bytes, tag = "1")]
        Output(::prost::alloc::vec::Vec<u8>),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
/// Generated client implementations.
pub mod metadata_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service providing metadata about the server.
    pub struct MetadataClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MetadataClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> MetadataClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Returns some server information. A test may use this information to verify
        /// that it is talking to the right server.
        pub async fn get_server_info(
            &mut self,
            request: impl tonic::IntoRequest<super::ServerInfoRequest>,
        ) -> Result<tonic::Response<super::ServerInfoResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tink_testing_api.Metadata/GetServerInfo");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for MetadataClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for MetadataClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MetadataClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod keyset_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service for Keyset operations.
    pub struct KeysetClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl KeysetClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> KeysetClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Generates a new keyset from a template.
        pub async fn generate(
            &mut self,
            request: impl tonic::IntoRequest<super::KeysetGenerateRequest>,
        ) -> Result<tonic::Response<super::KeysetGenerateResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Keyset/Generate");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Generates a public-key keyset from a private-key keyset.
        pub async fn public(
            &mut self,
            request: impl tonic::IntoRequest<super::KeysetPublicRequest>,
        ) -> Result<tonic::Response<super::KeysetPublicResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Keyset/Public");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Converts a Keyset from Binary to Json Format
        pub async fn to_json(
            &mut self,
            request: impl tonic::IntoRequest<super::KeysetToJsonRequest>,
        ) -> Result<tonic::Response<super::KeysetToJsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Keyset/ToJson");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Converts a Keyset from Json to Binary Format
        pub async fn from_json(
            &mut self,
            request: impl tonic::IntoRequest<super::KeysetFromJsonRequest>,
        ) -> Result<tonic::Response<super::KeysetFromJsonResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Keyset/FromJson");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for KeysetClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for KeysetClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "KeysetClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod aead_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service for AEAD encryption and decryption
    pub struct AeadClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl AeadClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> AeadClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Encrypts a plaintext with the provided keyset
        pub async fn encrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::AeadEncryptRequest>,
        ) -> Result<tonic::Response<super::AeadEncryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Aead/Encrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Decrypts a ciphertext with the provided keyset
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::AeadDecryptRequest>,
        ) -> Result<tonic::Response<super::AeadDecryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Aead/Decrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for AeadClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for AeadClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "AeadClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod deterministic_aead_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service for Deterministic AEAD encryption and decryption
    pub struct DeterministicAeadClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl DeterministicAeadClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> DeterministicAeadClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Encrypts a plaintext with the provided keyset
        pub async fn encrypt_deterministically(
            &mut self,
            request: impl tonic::IntoRequest<super::DeterministicAeadEncryptRequest>,
        ) -> Result<tonic::Response<super::DeterministicAeadEncryptResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tink_testing_api.DeterministicAead/EncryptDeterministically",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Decrypts a ciphertext with the provided keyset
        pub async fn decrypt_deterministically(
            &mut self,
            request: impl tonic::IntoRequest<super::DeterministicAeadDecryptRequest>,
        ) -> Result<tonic::Response<super::DeterministicAeadDecryptResponse>, tonic::Status>
        {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tink_testing_api.DeterministicAead/DecryptDeterministically",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for DeterministicAeadClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for DeterministicAeadClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "DeterministicAeadClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod streaming_aead_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service for Streaming AEAD encryption and decryption
    pub struct StreamingAeadClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl StreamingAeadClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> StreamingAeadClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Encrypts a plaintext with the provided keyset
        pub async fn encrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::StreamingAeadEncryptRequest>,
        ) -> Result<tonic::Response<super::StreamingAeadEncryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tink_testing_api.StreamingAead/Encrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Decrypts a ciphertext with the provided keyset
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::StreamingAeadDecryptRequest>,
        ) -> Result<tonic::Response<super::StreamingAeadDecryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tink_testing_api.StreamingAead/Decrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for StreamingAeadClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for StreamingAeadClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "StreamingAeadClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod mac_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service to compute and verify MACs
    pub struct MacClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl MacClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> MacClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Computes a MAC for given data
        pub async fn compute_mac(
            &mut self,
            request: impl tonic::IntoRequest<super::ComputeMacRequest>,
        ) -> Result<tonic::Response<super::ComputeMacResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Mac/ComputeMac");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Verifies the validity of the MAC value, no error means success
        pub async fn verify_mac(
            &mut self,
            request: impl tonic::IntoRequest<super::VerifyMacRequest>,
        ) -> Result<tonic::Response<super::VerifyMacResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Mac/VerifyMac");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for MacClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for MacClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "MacClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod hybrid_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service to hybrid encrypt and decrypt
    pub struct HybridClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl HybridClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> HybridClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Encrypts plaintext binding context_info to the resulting ciphertext
        pub async fn encrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::HybridEncryptRequest>,
        ) -> Result<tonic::Response<super::HybridEncryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Hybrid/Encrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Decrypts ciphertext verifying the integrity of context_info
        pub async fn decrypt(
            &mut self,
            request: impl tonic::IntoRequest<super::HybridDecryptRequest>,
        ) -> Result<tonic::Response<super::HybridDecryptResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Hybrid/Decrypt");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for HybridClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for HybridClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "HybridClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod signature_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service to sign and verify signatures.
    pub struct SignatureClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl SignatureClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> SignatureClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Computes the signature for data
        pub async fn sign(
            &mut self,
            request: impl tonic::IntoRequest<super::SignatureSignRequest>,
        ) -> Result<tonic::Response<super::SignatureSignResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Signature/Sign");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Verifies that signature is a digital signature for data
        pub async fn verify(
            &mut self,
            request: impl tonic::IntoRequest<super::SignatureVerifyRequest>,
        ) -> Result<tonic::Response<super::SignatureVerifyResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.Signature/Verify");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for SignatureClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for SignatureClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SignatureClient {{ ... }}")
        }
    }
}
/// Generated client implementations.
pub mod prf_set_client {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    /// Service for PrfSet computation
    pub struct PrfSetClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl PrfSetClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> PrfSetClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + HttpBody + Send + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as HttpBody>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = tonic::client::Grpc::with_interceptor(inner, interceptor);
            Self { inner }
        }
        /// Returns the key ids and the primary key id in the keyset.
        pub async fn key_ids(
            &mut self,
            request: impl tonic::IntoRequest<super::PrfSetKeyIdsRequest>,
        ) -> Result<tonic::Response<super::PrfSetKeyIdsResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.PrfSet/KeyIds");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Computes the output of the PRF with the given key_id in the PrfSet.
        pub async fn compute(
            &mut self,
            request: impl tonic::IntoRequest<super::PrfSetComputeRequest>,
        ) -> Result<tonic::Response<super::PrfSetComputeResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static("/tink_testing_api.PrfSet/Compute");
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
    impl<T: Clone> Clone for PrfSetClient<T> {
        fn clone(&self) -> Self {
            Self {
                inner: self.inner.clone(),
            }
        }
    }
    impl<T> std::fmt::Debug for PrfSetClient<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "PrfSetClient {{ ... }}")
        }
    }
}
/// Generated server implementations.
pub mod metadata_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// MetadataServer.
    #[async_trait]
    pub trait Metadata: Send + Sync + 'static {
        /// Returns some server information. A test may use this information to verify
        /// that it is talking to the right server.
        async fn get_server_info(
            &self,
            request: tonic::Request<super::ServerInfoRequest>,
        ) -> Result<tonic::Response<super::ServerInfoResponse>, tonic::Status>;
    }
    /// Service providing metadata about the server.
    #[derive(Debug)]
    pub struct MetadataServer<T: Metadata> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Metadata> MetadataServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for MetadataServer<T>
    where
        T: Metadata,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Metadata/GetServerInfo" => {
                    #[allow(non_camel_case_types)]
                    struct GetServerInfoSvc<T: Metadata>(pub Arc<T>);
                    impl<T: Metadata> tonic::server::UnaryService<super::ServerInfoRequest> for GetServerInfoSvc<T> {
                        type Response = super::ServerInfoResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ServerInfoRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).get_server_info(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = GetServerInfoSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Metadata> Clone for MetadataServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Metadata> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Metadata> tonic::transport::NamedService for MetadataServer<T> {
        const NAME: &'static str = "tink_testing_api.Metadata";
    }
}
/// Generated server implementations.
pub mod keyset_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// KeysetServer.
    #[async_trait]
    pub trait Keyset: Send + Sync + 'static {
        /// Generates a new keyset from a template.
        async fn generate(
            &self,
            request: tonic::Request<super::KeysetGenerateRequest>,
        ) -> Result<tonic::Response<super::KeysetGenerateResponse>, tonic::Status>;
        /// Generates a public-key keyset from a private-key keyset.
        async fn public(
            &self,
            request: tonic::Request<super::KeysetPublicRequest>,
        ) -> Result<tonic::Response<super::KeysetPublicResponse>, tonic::Status>;
        /// Converts a Keyset from Binary to Json Format
        async fn to_json(
            &self,
            request: tonic::Request<super::KeysetToJsonRequest>,
        ) -> Result<tonic::Response<super::KeysetToJsonResponse>, tonic::Status>;
        /// Converts a Keyset from Json to Binary Format
        async fn from_json(
            &self,
            request: tonic::Request<super::KeysetFromJsonRequest>,
        ) -> Result<tonic::Response<super::KeysetFromJsonResponse>, tonic::Status>;
    }
    /// Service for Keyset operations.
    #[derive(Debug)]
    pub struct KeysetServer<T: Keyset> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Keyset> KeysetServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for KeysetServer<T>
    where
        T: Keyset,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Keyset/Generate" => {
                    #[allow(non_camel_case_types)]
                    struct GenerateSvc<T: Keyset>(pub Arc<T>);
                    impl<T: Keyset> tonic::server::UnaryService<super::KeysetGenerateRequest> for GenerateSvc<T> {
                        type Response = super::KeysetGenerateResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::KeysetGenerateRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).generate(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = GenerateSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Keyset/Public" => {
                    #[allow(non_camel_case_types)]
                    struct PublicSvc<T: Keyset>(pub Arc<T>);
                    impl<T: Keyset> tonic::server::UnaryService<super::KeysetPublicRequest> for PublicSvc<T> {
                        type Response = super::KeysetPublicResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::KeysetPublicRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).public(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = PublicSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Keyset/ToJson" => {
                    #[allow(non_camel_case_types)]
                    struct ToJsonSvc<T: Keyset>(pub Arc<T>);
                    impl<T: Keyset> tonic::server::UnaryService<super::KeysetToJsonRequest> for ToJsonSvc<T> {
                        type Response = super::KeysetToJsonResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::KeysetToJsonRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).to_json(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = ToJsonSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Keyset/FromJson" => {
                    #[allow(non_camel_case_types)]
                    struct FromJsonSvc<T: Keyset>(pub Arc<T>);
                    impl<T: Keyset> tonic::server::UnaryService<super::KeysetFromJsonRequest> for FromJsonSvc<T> {
                        type Response = super::KeysetFromJsonResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::KeysetFromJsonRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).from_json(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = FromJsonSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Keyset> Clone for KeysetServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Keyset> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Keyset> tonic::transport::NamedService for KeysetServer<T> {
        const NAME: &'static str = "tink_testing_api.Keyset";
    }
}
/// Generated server implementations.
pub mod aead_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with AeadServer.
    #[async_trait]
    pub trait Aead: Send + Sync + 'static {
        /// Encrypts a plaintext with the provided keyset
        async fn encrypt(
            &self,
            request: tonic::Request<super::AeadEncryptRequest>,
        ) -> Result<tonic::Response<super::AeadEncryptResponse>, tonic::Status>;
        /// Decrypts a ciphertext with the provided keyset
        async fn decrypt(
            &self,
            request: tonic::Request<super::AeadDecryptRequest>,
        ) -> Result<tonic::Response<super::AeadDecryptResponse>, tonic::Status>;
    }
    /// Service for AEAD encryption and decryption
    #[derive(Debug)]
    pub struct AeadServer<T: Aead> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Aead> AeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for AeadServer<T>
    where
        T: Aead,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Aead/Encrypt" => {
                    #[allow(non_camel_case_types)]
                    struct EncryptSvc<T: Aead>(pub Arc<T>);
                    impl<T: Aead> tonic::server::UnaryService<super::AeadEncryptRequest> for EncryptSvc<T> {
                        type Response = super::AeadEncryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AeadEncryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).encrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Aead/Decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct DecryptSvc<T: Aead>(pub Arc<T>);
                    impl<T: Aead> tonic::server::UnaryService<super::AeadDecryptRequest> for DecryptSvc<T> {
                        type Response = super::AeadDecryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::AeadDecryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).decrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Aead> Clone for AeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Aead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Aead> tonic::transport::NamedService for AeadServer<T> {
        const NAME: &'static str = "tink_testing_api.Aead";
    }
}
/// Generated server implementations.
pub mod deterministic_aead_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// DeterministicAeadServer.
    #[async_trait]
    pub trait DeterministicAead: Send + Sync + 'static {
        /// Encrypts a plaintext with the provided keyset
        async fn encrypt_deterministically(
            &self,
            request: tonic::Request<super::DeterministicAeadEncryptRequest>,
        ) -> Result<tonic::Response<super::DeterministicAeadEncryptResponse>, tonic::Status>;
        /// Decrypts a ciphertext with the provided keyset
        async fn decrypt_deterministically(
            &self,
            request: tonic::Request<super::DeterministicAeadDecryptRequest>,
        ) -> Result<tonic::Response<super::DeterministicAeadDecryptResponse>, tonic::Status>;
    }
    /// Service for Deterministic AEAD encryption and decryption
    #[derive(Debug)]
    pub struct DeterministicAeadServer<T: DeterministicAead> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: DeterministicAead> DeterministicAeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for DeterministicAeadServer<T>
    where
        T: DeterministicAead,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.DeterministicAead/EncryptDeterministically" => {
                    #[allow(non_camel_case_types)]
                    struct EncryptDeterministicallySvc<T: DeterministicAead>(pub Arc<T>);
                    impl<T: DeterministicAead>
                        tonic::server::UnaryService<super::DeterministicAeadEncryptRequest>
                        for EncryptDeterministicallySvc<T>
                    {
                        type Response = super::DeterministicAeadEncryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DeterministicAeadEncryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).encrypt_deterministically(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = EncryptDeterministicallySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.DeterministicAead/DecryptDeterministically" => {
                    #[allow(non_camel_case_types)]
                    struct DecryptDeterministicallySvc<T: DeterministicAead>(pub Arc<T>);
                    impl<T: DeterministicAead>
                        tonic::server::UnaryService<super::DeterministicAeadDecryptRequest>
                        for DecryptDeterministicallySvc<T>
                    {
                        type Response = super::DeterministicAeadDecryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::DeterministicAeadDecryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).decrypt_deterministically(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = DecryptDeterministicallySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: DeterministicAead> Clone for DeterministicAeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: DeterministicAead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: DeterministicAead> tonic::transport::NamedService for DeterministicAeadServer<T> {
        const NAME: &'static str = "tink_testing_api.DeterministicAead";
    }
}
/// Generated server implementations.
pub mod streaming_aead_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// StreamingAeadServer.
    #[async_trait]
    pub trait StreamingAead: Send + Sync + 'static {
        /// Encrypts a plaintext with the provided keyset
        async fn encrypt(
            &self,
            request: tonic::Request<super::StreamingAeadEncryptRequest>,
        ) -> Result<tonic::Response<super::StreamingAeadEncryptResponse>, tonic::Status>;
        /// Decrypts a ciphertext with the provided keyset
        async fn decrypt(
            &self,
            request: tonic::Request<super::StreamingAeadDecryptRequest>,
        ) -> Result<tonic::Response<super::StreamingAeadDecryptResponse>, tonic::Status>;
    }
    /// Service for Streaming AEAD encryption and decryption
    #[derive(Debug)]
    pub struct StreamingAeadServer<T: StreamingAead> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: StreamingAead> StreamingAeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for StreamingAeadServer<T>
    where
        T: StreamingAead,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.StreamingAead/Encrypt" => {
                    #[allow(non_camel_case_types)]
                    struct EncryptSvc<T: StreamingAead>(pub Arc<T>);
                    impl<T: StreamingAead>
                        tonic::server::UnaryService<super::StreamingAeadEncryptRequest>
                        for EncryptSvc<T>
                    {
                        type Response = super::StreamingAeadEncryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::StreamingAeadEncryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).encrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.StreamingAead/Decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct DecryptSvc<T: StreamingAead>(pub Arc<T>);
                    impl<T: StreamingAead>
                        tonic::server::UnaryService<super::StreamingAeadDecryptRequest>
                        for DecryptSvc<T>
                    {
                        type Response = super::StreamingAeadDecryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::StreamingAeadDecryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).decrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: StreamingAead> Clone for StreamingAeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: StreamingAead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: StreamingAead> tonic::transport::NamedService for StreamingAeadServer<T> {
        const NAME: &'static str = "tink_testing_api.StreamingAead";
    }
}
/// Generated server implementations.
pub mod mac_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with MacServer.
    #[async_trait]
    pub trait Mac: Send + Sync + 'static {
        /// Computes a MAC for given data
        async fn compute_mac(
            &self,
            request: tonic::Request<super::ComputeMacRequest>,
        ) -> Result<tonic::Response<super::ComputeMacResponse>, tonic::Status>;
        /// Verifies the validity of the MAC value, no error means success
        async fn verify_mac(
            &self,
            request: tonic::Request<super::VerifyMacRequest>,
        ) -> Result<tonic::Response<super::VerifyMacResponse>, tonic::Status>;
    }
    /// Service to compute and verify MACs
    #[derive(Debug)]
    pub struct MacServer<T: Mac> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Mac> MacServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for MacServer<T>
    where
        T: Mac,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Mac/ComputeMac" => {
                    #[allow(non_camel_case_types)]
                    struct ComputeMacSvc<T: Mac>(pub Arc<T>);
                    impl<T: Mac> tonic::server::UnaryService<super::ComputeMacRequest> for ComputeMacSvc<T> {
                        type Response = super::ComputeMacResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ComputeMacRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).compute_mac(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = ComputeMacSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Mac/VerifyMac" => {
                    #[allow(non_camel_case_types)]
                    struct VerifyMacSvc<T: Mac>(pub Arc<T>);
                    impl<T: Mac> tonic::server::UnaryService<super::VerifyMacRequest> for VerifyMacSvc<T> {
                        type Response = super::VerifyMacResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::VerifyMacRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).verify_mac(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = VerifyMacSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Mac> Clone for MacServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Mac> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Mac> tonic::transport::NamedService for MacServer<T> {
        const NAME: &'static str = "tink_testing_api.Mac";
    }
}
/// Generated server implementations.
pub mod hybrid_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// HybridServer.
    #[async_trait]
    pub trait Hybrid: Send + Sync + 'static {
        /// Encrypts plaintext binding context_info to the resulting ciphertext
        async fn encrypt(
            &self,
            request: tonic::Request<super::HybridEncryptRequest>,
        ) -> Result<tonic::Response<super::HybridEncryptResponse>, tonic::Status>;
        /// Decrypts ciphertext verifying the integrity of context_info
        async fn decrypt(
            &self,
            request: tonic::Request<super::HybridDecryptRequest>,
        ) -> Result<tonic::Response<super::HybridDecryptResponse>, tonic::Status>;
    }
    /// Service to hybrid encrypt and decrypt
    #[derive(Debug)]
    pub struct HybridServer<T: Hybrid> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Hybrid> HybridServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for HybridServer<T>
    where
        T: Hybrid,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Hybrid/Encrypt" => {
                    #[allow(non_camel_case_types)]
                    struct EncryptSvc<T: Hybrid>(pub Arc<T>);
                    impl<T: Hybrid> tonic::server::UnaryService<super::HybridEncryptRequest> for EncryptSvc<T> {
                        type Response = super::HybridEncryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::HybridEncryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).encrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Hybrid/Decrypt" => {
                    #[allow(non_camel_case_types)]
                    struct DecryptSvc<T: Hybrid>(pub Arc<T>);
                    impl<T: Hybrid> tonic::server::UnaryService<super::HybridDecryptRequest> for DecryptSvc<T> {
                        type Response = super::HybridDecryptResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::HybridDecryptRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).decrypt(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Hybrid> Clone for HybridServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Hybrid> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Hybrid> tonic::transport::NamedService for HybridServer<T> {
        const NAME: &'static str = "tink_testing_api.Hybrid";
    }
}
/// Generated server implementations.
pub mod signature_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// SignatureServer.
    #[async_trait]
    pub trait Signature: Send + Sync + 'static {
        /// Computes the signature for data
        async fn sign(
            &self,
            request: tonic::Request<super::SignatureSignRequest>,
        ) -> Result<tonic::Response<super::SignatureSignResponse>, tonic::Status>;
        /// Verifies that signature is a digital signature for data
        async fn verify(
            &self,
            request: tonic::Request<super::SignatureVerifyRequest>,
        ) -> Result<tonic::Response<super::SignatureVerifyResponse>, tonic::Status>;
    }
    /// Service to sign and verify signatures.
    #[derive(Debug)]
    pub struct SignatureServer<T: Signature> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: Signature> SignatureServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for SignatureServer<T>
    where
        T: Signature,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.Signature/Sign" => {
                    #[allow(non_camel_case_types)]
                    struct SignSvc<T: Signature>(pub Arc<T>);
                    impl<T: Signature> tonic::server::UnaryService<super::SignatureSignRequest> for SignSvc<T> {
                        type Response = super::SignatureSignResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SignatureSignRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).sign(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = SignSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Signature/Verify" => {
                    #[allow(non_camel_case_types)]
                    struct VerifySvc<T: Signature>(pub Arc<T>);
                    impl<T: Signature> tonic::server::UnaryService<super::SignatureVerifyRequest> for VerifySvc<T> {
                        type Response = super::SignatureVerifyResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::SignatureVerifyRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).verify(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = VerifySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Signature> Clone for SignatureServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: Signature> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Signature> tonic::transport::NamedService for SignatureServer<T> {
        const NAME: &'static str = "tink_testing_api.Signature";
    }
}
/// Generated server implementations.
pub mod prf_set_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with
    /// PrfSetServer.
    #[async_trait]
    pub trait PrfSet: Send + Sync + 'static {
        /// Returns the key ids and the primary key id in the keyset.
        async fn key_ids(
            &self,
            request: tonic::Request<super::PrfSetKeyIdsRequest>,
        ) -> Result<tonic::Response<super::PrfSetKeyIdsResponse>, tonic::Status>;
        /// Computes the output of the PRF with the given key_id in the PrfSet.
        async fn compute(
            &self,
            request: tonic::Request<super::PrfSetComputeRequest>,
        ) -> Result<tonic::Response<super::PrfSetComputeResponse>, tonic::Status>;
    }
    /// Service for PrfSet computation
    #[derive(Debug)]
    pub struct PrfSetServer<T: PrfSet> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: PrfSet> PrfSetServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for PrfSetServer<T>
    where
        T: PrfSet,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/tink_testing_api.PrfSet/KeyIds" => {
                    #[allow(non_camel_case_types)]
                    struct KeyIdsSvc<T: PrfSet>(pub Arc<T>);
                    impl<T: PrfSet> tonic::server::UnaryService<super::PrfSetKeyIdsRequest> for KeyIdsSvc<T> {
                        type Response = super::PrfSetKeyIdsResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PrfSetKeyIdsRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).key_ids(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = KeyIdsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.PrfSet/Compute" => {
                    #[allow(non_camel_case_types)]
                    struct ComputeSvc<T: PrfSet>(pub Arc<T>);
                    impl<T: PrfSet> tonic::server::UnaryService<super::PrfSetComputeRequest> for ComputeSvc<T> {
                        type Response = super::PrfSetComputeResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::PrfSetComputeRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).compute(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = ComputeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: PrfSet> Clone for PrfSetServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: PrfSet> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: PrfSet> tonic::transport::NamedService for PrfSetServer<T> {
        const NAME: &'static str = "tink_testing_api.PrfSet";
    }
}

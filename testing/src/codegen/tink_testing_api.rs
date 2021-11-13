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
// TODO(b/179867503): Remove these copies of Timestamp, Duration and StringValue

/// Copied from timestamp.proto
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Timestamp {
    /// Represents seconds of UTC time since Unix epoch
    /// 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
    /// 9999-12-31T23:59:59Z inclusive.
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// Non-negative fractions of a second at nanosecond resolution. Negative
    /// second values with fractions must still have non-negative nanos values
    /// that count forward in time. Must be from 0 to 999,999,999
    /// inclusive.
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}
/// Copied from duration.proto
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Duration {
    /// Signed seconds of the span of time. Must be from -315,576,000,000
    /// to +315,576,000,000 inclusive. Note: these bounds are computed from:
    /// 60 sec/min * 60 min/hr * 24 hr/day * 365.25 days/year * 10000 years
    #[prost(int64, tag = "1")]
    pub seconds: i64,
    /// Signed fractions of a second at nanosecond resolution of the span
    /// of time. Durations less than one second are represented with a 0
    /// `seconds` field and a positive or negative `nanos` field. For durations
    /// of one second or more, a non-zero value for the `nanos` field must be
    /// of the same sign as the `seconds` field. Must be from -999,999,999
    /// to +999,999,999 inclusive.
    #[prost(int32, tag = "2")]
    pub nanos: i32,
}
/// Copied from wrappers.proto
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StringValue {
    /// The string value.
    #[prost(string, tag = "1")]
    pub value: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtClaimValue {
    #[prost(oneof = "jwt_claim_value::Kind", tags = "2, 3, 4, 5, 6, 7")]
    pub kind: ::core::option::Option<jwt_claim_value::Kind>,
}
/// Nested message and enum types in `JwtClaimValue`.
pub mod jwt_claim_value {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(enumeration = "super::NullValue", tag = "2")]
        NullValue(i32),
        #[prost(double, tag = "3")]
        NumberValue(f64),
        #[prost(string, tag = "4")]
        StringValue(::prost::alloc::string::String),
        #[prost(bool, tag = "5")]
        BoolValue(bool),
        #[prost(string, tag = "6")]
        JsonObjectValue(::prost::alloc::string::String),
        #[prost(string, tag = "7")]
        JsonArrayValue(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtToken {
    #[prost(message, optional, tag = "1")]
    pub issuer: ::core::option::Option<StringValue>,
    #[prost(message, optional, tag = "2")]
    pub subject: ::core::option::Option<StringValue>,
    #[prost(string, repeated, tag = "3")]
    pub audiences: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "4")]
    pub jwt_id: ::core::option::Option<StringValue>,
    #[prost(message, optional, tag = "5")]
    pub expiration: ::core::option::Option<Timestamp>,
    #[prost(message, optional, tag = "6")]
    pub not_before: ::core::option::Option<Timestamp>,
    #[prost(message, optional, tag = "7")]
    pub issued_at: ::core::option::Option<Timestamp>,
    #[prost(map = "string, message", tag = "8")]
    pub custom_claims: ::std::collections::HashMap<::prost::alloc::string::String, JwtClaimValue>,
    #[prost(message, optional, tag = "9")]
    pub type_header: ::core::option::Option<StringValue>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtValidator {
    #[prost(message, optional, tag = "7")]
    pub expected_type_header: ::core::option::Option<StringValue>,
    #[prost(message, optional, tag = "1")]
    pub expected_issuer: ::core::option::Option<StringValue>,
    #[prost(message, optional, tag = "2")]
    pub expected_subject: ::core::option::Option<StringValue>,
    #[prost(message, optional, tag = "3")]
    pub expected_audience: ::core::option::Option<StringValue>,
    #[prost(bool, tag = "8")]
    pub ignore_type_header: bool,
    #[prost(bool, tag = "9")]
    pub ignore_issuer: bool,
    #[prost(bool, tag = "10")]
    pub ignore_subject: bool,
    #[prost(bool, tag = "11")]
    pub ignore_audience: bool,
    #[prost(bool, tag = "12")]
    pub allow_missing_expiration: bool,
    #[prost(message, optional, tag = "5")]
    pub now: ::core::option::Option<Timestamp>,
    #[prost(message, optional, tag = "6")]
    pub clock_skew: ::core::option::Option<Duration>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtSignRequest {
    /// serialized google.crypto.tink.Keyset
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "2")]
    pub raw_jwt: ::core::option::Option<JwtToken>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtSignResponse {
    #[prost(oneof = "jwt_sign_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<jwt_sign_response::Result>,
}
/// Nested message and enum types in `JwtSignResponse`.
pub mod jwt_sign_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(string, tag = "1")]
        SignedCompactJwt(::prost::alloc::string::String),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtVerifyRequest {
    /// serialized google.crypto.tink.Keyset
    #[prost(bytes = "vec", tag = "1")]
    pub keyset: ::prost::alloc::vec::Vec<u8>,
    #[prost(string, tag = "2")]
    pub signed_compact_jwt: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "3")]
    pub validator: ::core::option::Option<JwtValidator>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtVerifyResponse {
    #[prost(oneof = "jwt_verify_response::Result", tags = "1, 2")]
    pub result: ::core::option::Option<jwt_verify_response::Result>,
}
/// Nested message and enum types in `JwtVerifyResponse`.
pub mod jwt_verify_response {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Result {
        #[prost(message, tag = "1")]
        VerifiedJwt(super::JwtToken),
        #[prost(string, tag = "2")]
        Err(::prost::alloc::string::String),
    }
}
///  Used to represent the JSON null value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum NullValue {
    NullValue = 0,
}
/// Generated client implementations.
pub mod metadata_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service providing metadata about the server.
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> MetadataClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            MetadataClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod keyset_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for Keyset operations.
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> KeysetClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            KeysetClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod aead_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for AEAD encryption and decryption
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> AeadClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            AeadClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod deterministic_aead_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for Deterministic AEAD encryption and decryption
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> DeterministicAeadClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            DeterministicAeadClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod streaming_aead_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for Streaming AEAD encryption and decryption
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> StreamingAeadClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            StreamingAeadClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod mac_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service to compute and verify MACs
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> MacClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            MacClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod hybrid_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service to hybrid encrypt and decrypt
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> HybridClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            HybridClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod signature_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service to sign and verify signatures.
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> SignatureClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            SignatureClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod prf_set_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for PrfSet computation
    #[derive(Debug, Clone)]
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
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> PrfSetClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            PrfSetClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
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
}
/// Generated client implementations.
pub mod jwt_client {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    /// Service for JSON Web Tokens (JWT)
    #[derive(Debug, Clone)]
    pub struct JwtClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl JwtClient<tonic::transport::Channel> {
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
    impl<T> JwtClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::BoxBody>,
        T::ResponseBody: Body + Send + Sync + 'static,
        T::Error: Into<StdError>,
        <T::ResponseBody as Body>::Error: Into<StdError> + Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> JwtClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T: tonic::codegen::Service<
                http::Request<tonic::body::BoxBody>,
                Response = http::Response<
                    <T as tonic::client::GrpcService<tonic::body::BoxBody>>::ResponseBody,
                >,
            >,
            <T as tonic::codegen::Service<http::Request<tonic::body::BoxBody>>>::Error:
                Into<StdError> + Send + Sync,
        {
            JwtClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress requests with `gzip`.
        ///
        /// This requires the server to support it otherwise it might respond with an
        /// error.
        pub fn send_gzip(mut self) -> Self {
            self.inner = self.inner.send_gzip();
            self
        }
        /// Enable decompressing responses with `gzip`.
        pub fn accept_gzip(mut self) -> Self {
            self.inner = self.inner.accept_gzip();
            self
        }
        /// Computes a signed compact JWT token.
        pub async fn compute_mac_and_encode(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtSignRequest>,
        ) -> Result<tonic::Response<super::JwtSignResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tink_testing_api.Jwt/ComputeMacAndEncode");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Verifies the validity of the signed compact JWT token
        pub async fn verify_mac_and_decode(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtVerifyRequest>,
        ) -> Result<tonic::Response<super::JwtVerifyResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/tink_testing_api.Jwt/VerifyMacAndDecode");
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Computes a signed compact JWT token.
        pub async fn public_key_sign_and_encode(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtSignRequest>,
        ) -> Result<tonic::Response<super::JwtSignResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tink_testing_api.Jwt/PublicKeySignAndEncode",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
        /// Verifies the validity of the signed compact JWT token
        pub async fn public_key_verify_and_decode(
            &mut self,
            request: impl tonic::IntoRequest<super::JwtVerifyRequest>,
        ) -> Result<tonic::Response<super::JwtVerifyResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::new(
                    tonic::Code::Unknown,
                    format!("Service was not ready: {}", e.into()),
                )
            })?;
            let codec = tonic::codec::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tink_testing_api.Jwt/PublicKeyVerifyAndDecode",
            );
            self.inner.unary(request.into_request(), path, codec).await
        }
    }
}
/// Generated server implementations.
pub mod metadata_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Metadata> MetadataServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for MetadataServer<T>
    where
        T: Metadata,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GetServerInfoSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Metadata> Clone for MetadataServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Metadata> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Keyset> KeysetServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for KeysetServer<T>
    where
        T: Keyset,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = GenerateSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = PublicSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ToJsonSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = FromJsonSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Keyset> Clone for KeysetServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Keyset> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Aead> AeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for AeadServer<T>
    where
        T: Aead,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Aead> Clone for AeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Aead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: DeterministicAead> DeterministicAeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for DeterministicAeadServer<T>
    where
        T: DeterministicAead,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = EncryptDeterministicallySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DecryptDeterministicallySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: DeterministicAead> Clone for DeterministicAeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: DeterministicAead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: StreamingAead> StreamingAeadServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for StreamingAeadServer<T>
    where
        T: StreamingAead,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: StreamingAead> Clone for StreamingAeadServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: StreamingAead> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Mac> MacServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for MacServer<T>
    where
        T: Mac,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ComputeMacSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = VerifyMacSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Mac> Clone for MacServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Mac> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Hybrid> HybridServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for HybridServer<T>
    where
        T: Hybrid,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = EncryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = DecryptSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Hybrid> Clone for HybridServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Hybrid> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Signature> SignatureServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for SignatureServer<T>
    where
        T: Signature,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = SignSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = VerifySvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Signature> Clone for SignatureServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Signature> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
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
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: PrfSet> PrfSetServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for PrfSetServer<T>
    where
        T: PrfSet,
        B: Body + Send + Sync + 'static,
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = KeyIdsSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ComputeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: PrfSet> Clone for PrfSetServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: PrfSet> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
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
/// Generated server implementations.
pub mod jwt_server {
    #![allow(unused_variables, dead_code, missing_docs, clippy::let_unit_value)]
    use tonic::codegen::*;
    ///Generated trait containing gRPC methods that should be implemented for use with JwtServer.
    #[async_trait]
    pub trait Jwt: Send + Sync + 'static {
        /// Computes a signed compact JWT token.
        async fn compute_mac_and_encode(
            &self,
            request: tonic::Request<super::JwtSignRequest>,
        ) -> Result<tonic::Response<super::JwtSignResponse>, tonic::Status>;
        /// Verifies the validity of the signed compact JWT token
        async fn verify_mac_and_decode(
            &self,
            request: tonic::Request<super::JwtVerifyRequest>,
        ) -> Result<tonic::Response<super::JwtVerifyResponse>, tonic::Status>;
        /// Computes a signed compact JWT token.
        async fn public_key_sign_and_encode(
            &self,
            request: tonic::Request<super::JwtSignRequest>,
        ) -> Result<tonic::Response<super::JwtSignResponse>, tonic::Status>;
        /// Verifies the validity of the signed compact JWT token
        async fn public_key_verify_and_decode(
            &self,
            request: tonic::Request<super::JwtVerifyRequest>,
        ) -> Result<tonic::Response<super::JwtVerifyResponse>, tonic::Status>;
    }
    /// Service for JSON Web Tokens (JWT)
    #[derive(Debug)]
    pub struct JwtServer<T: Jwt> {
        inner: _Inner<T>,
        accept_compression_encodings: (),
        send_compression_encodings: (),
    }
    struct _Inner<T>(Arc<T>);
    impl<T: Jwt> JwtServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner);
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for JwtServer<T>
    where
        T: Jwt,
        B: Body + Send + Sync + 'static,
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
                "/tink_testing_api.Jwt/ComputeMacAndEncode" => {
                    #[allow(non_camel_case_types)]
                    struct ComputeMacAndEncodeSvc<T: Jwt>(pub Arc<T>);
                    impl<T: Jwt> tonic::server::UnaryService<super::JwtSignRequest> for ComputeMacAndEncodeSvc<T> {
                        type Response = super::JwtSignResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtSignRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).compute_mac_and_encode(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = ComputeMacAndEncodeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Jwt/VerifyMacAndDecode" => {
                    #[allow(non_camel_case_types)]
                    struct VerifyMacAndDecodeSvc<T: Jwt>(pub Arc<T>);
                    impl<T: Jwt> tonic::server::UnaryService<super::JwtVerifyRequest> for VerifyMacAndDecodeSvc<T> {
                        type Response = super::JwtVerifyResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtVerifyRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).verify_mac_and_decode(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = VerifyMacAndDecodeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Jwt/PublicKeySignAndEncode" => {
                    #[allow(non_camel_case_types)]
                    struct PublicKeySignAndEncodeSvc<T: Jwt>(pub Arc<T>);
                    impl<T: Jwt> tonic::server::UnaryService<super::JwtSignRequest> for PublicKeySignAndEncodeSvc<T> {
                        type Response = super::JwtSignResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtSignRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).public_key_sign_and_encode(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = PublicKeySignAndEncodeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/tink_testing_api.Jwt/PublicKeyVerifyAndDecode" => {
                    #[allow(non_camel_case_types)]
                    struct PublicKeyVerifyAndDecodeSvc<T: Jwt>(pub Arc<T>);
                    impl<T: Jwt> tonic::server::UnaryService<super::JwtVerifyRequest>
                        for PublicKeyVerifyAndDecodeSvc<T>
                    {
                        type Response = super::JwtVerifyResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::JwtVerifyRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut =
                                async move { (*inner).public_key_verify_and_decode(request).await };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let inner = inner.0;
                        let method = PublicKeyVerifyAndDecodeSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec).apply_compression_config(
                            accept_compression_encodings,
                            send_compression_encodings,
                        );
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
                        .body(empty_body())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: Jwt> Clone for JwtServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
            }
        }
    }
    impl<T: Jwt> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: Jwt> tonic::transport::NamedService for JwtServer<T> {
        const NAME: &'static str = "tink_testing_api.Jwt";
    }
}

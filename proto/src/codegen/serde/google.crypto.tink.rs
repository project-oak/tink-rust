#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCmacParams {
    #[prost(uint32, tag="1")]
    pub tag_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesCmacKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCmacKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub params: ::core::option::Option<AesCmacParams>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCmacKeyFormat {
    #[prost(uint32, tag="1")]
    pub key_size: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<AesCmacParams>,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesCmacPrfKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCmacPrfKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCmacPrfKeyFormat {
    #[prost(uint32, tag="2")]
    pub version: u32,
    #[prost(uint32, tag="1")]
    pub key_size: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrParams {
    #[prost(uint32, tag="1")]
    pub iv_size: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrKeyFormat {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<AesCtrParams>,
    #[prost(uint32, tag="2")]
    pub key_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesCtrKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<AesCtrParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EllipticCurveType {
    UnknownCurve = 0,
    NistP256 = 2,
    NistP384 = 3,
    NistP521 = 4,
    Curve25519 = 5,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EcPointFormat {
    UnknownFormat = 0,
    Uncompressed = 1,
    Compressed = 2,
    /// Like UNCOMPRESSED but without the \x04 prefix. Crunchy uses this format.
    /// DO NOT USE unless you are a Crunchy user moving to Tink.
    DoNotUseCrunchyUncompressed = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum HashType {
    UnknownHash = 0,
    /// Using SHA1 for digital signature is deprecated but HMAC-SHA1 is
    Sha1 = 1,
    /// fine.
    Sha384 = 2,
    Sha256 = 3,
    Sha512 = 4,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacParams {
    /// HashType is an enum.
    #[prost(enumeration="HashType", tag="1")]
    pub hash: i32,
    #[prost(uint32, tag="2")]
    pub tag_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.HmacKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<HmacParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacKeyFormat {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<HmacParams>,
    #[prost(uint32, tag="2")]
    pub key_size: u32,
    #[prost(uint32, tag="3")]
    pub version: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrHmacAeadKeyFormat {
    #[prost(message, optional, tag="1")]
    pub aes_ctr_key_format: ::core::option::Option<AesCtrKeyFormat>,
    #[prost(message, optional, tag="2")]
    pub hmac_key_format: ::core::option::Option<HmacKeyFormat>,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrHmacAeadKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub aes_ctr_key: ::core::option::Option<AesCtrKey>,
    #[prost(message, optional, tag="3")]
    pub hmac_key: ::core::option::Option<HmacKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrHmacStreamingParams {
    #[prost(uint32, tag="1")]
    pub ciphertext_segment_size: u32,
    /// size of AES-CTR keys derived for each segment
    #[prost(uint32, tag="2")]
    pub derived_key_size: u32,
    /// hash function for key derivation via HKDF
    #[prost(enumeration="HashType", tag="3")]
    pub hkdf_hash_type: i32,
    /// params for authentication tags
    #[prost(message, optional, tag="4")]
    pub hmac_params: ::core::option::Option<HmacParams>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrHmacStreamingKeyFormat {
    #[prost(uint32, tag="3")]
    pub version: u32,
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<AesCtrHmacStreamingParams>,
    /// size of the main key (aka. "ikm", input key material)
    #[prost(uint32, tag="2")]
    pub key_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesCtrHmacStreamingKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<AesCtrHmacStreamingParams>,
    /// the main key, aka. "ikm", input key material
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
/// only allowing tag size in bytes = 16
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesEaxParams {
    /// possible value is 12 or 16 bytes.
    #[prost(uint32, tag="1")]
    pub iv_size: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesEaxKeyFormat {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<AesEaxParams>,
    #[prost(uint32, tag="2")]
    pub key_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesEaxKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesEaxKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<AesEaxParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
/// only allowing IV size in bytes = 12 and tag size in bytes = 16
/// Thus, accept no params.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmKeyFormat {
    #[prost(uint32, tag="2")]
    pub key_size: u32,
    #[prost(uint32, tag="3")]
    pub version: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesGcmKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmHkdfStreamingParams {
    #[prost(uint32, tag="1")]
    pub ciphertext_segment_size: u32,
    /// size of AES-GCM keys derived for each segment
    #[prost(uint32, tag="2")]
    pub derived_key_size: u32,
    #[prost(enumeration="HashType", tag="3")]
    pub hkdf_hash_type: i32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmHkdfStreamingKeyFormat {
    #[prost(uint32, tag="3")]
    pub version: u32,
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<AesGcmHkdfStreamingParams>,
    /// size of the main key (aka. "ikm", input key material)
    #[prost(uint32, tag="2")]
    pub key_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmHkdfStreamingKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<AesGcmHkdfStreamingParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
/// The only allowed IV size is 12 bytes and tag size is 16 bytes.
/// Thus, accept no params.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmSivKeyFormat {
    #[prost(uint32, tag="2")]
    pub key_size: u32,
    #[prost(uint32, tag="1")]
    pub version: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesGcmSivKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesGcmSivKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesSivKeyFormat {
    /// Only valid value is: 64.
    #[prost(uint32, tag="1")]
    pub key_size: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.AesSivKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AesSivKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// First half is AES-CTR key, second is AES-SIV.
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChaCha20Poly1305KeyFormat {
}
/// key_type: type.googleapis.com/google.crypto.tink.ChaCha20Poly1305.
/// This key type actually implements ChaCha20Poly1305 as described
/// at https://tools.ietf.org/html/rfc7539#section-2.8.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ChaCha20Poly1305Key {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
/// An entry that describes a key type to be used with Tink library,
/// specifying the corresponding primitive, key manager, and deprecation status.
/// All fields are required.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyTypeEntry {
    /// E.g. “Aead”, “Mac”, ... (case-insensitive)
    #[prost(string, tag="1")]
    pub primitive_name: ::prost::alloc::string::String,
    /// Name of the key type.
    #[prost(string, tag="2")]
    pub type_url: ::prost::alloc::string::String,
    /// Minimum required version of key manager.
    #[prost(uint32, tag="3")]
    pub key_manager_version: u32,
    /// Can the key manager create new keys?
    #[prost(bool, tag="4")]
    pub new_key_allowed: bool,
    /// Catalogue to be queried for key manager,
    #[prost(string, tag="5")]
    pub catalogue_name: ::prost::alloc::string::String,
}
/// A complete configuration of Tink library: a list of key types
/// to be available via the Registry after initialization.
/// All fields are required.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RegistryConfig {
    #[prost(string, tag="1")]
    pub config_name: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="2")]
    pub entry: ::prost::alloc::vec::Vec<KeyTypeEntry>,
}
/// Protos for Ecdsa.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaParams {
    /// Required.
    #[prost(enumeration="HashType", tag="1")]
    pub hash_type: i32,
    /// Required.
    #[prost(enumeration="EllipticCurveType", tag="2")]
    pub curve: i32,
    /// Required.
    #[prost(enumeration="EcdsaSignatureEncoding", tag="3")]
    pub encoding: i32,
}
/// key_type: type.googleapis.com/google.crypto.tink.EcdsaPublicKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaPublicKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<EcdsaParams>,
    /// Affine coordinates of the public key in bigendian representation. The
    /// public key is a point (x, y) on the curve defined by params.curve. For
    /// ECDH, it is crucial to verify whether the public key point (x, y) is on the
    /// private's key curve. For ECDSA, such verification is a defense in depth.
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub x: ::prost::alloc::vec::Vec<u8>,
    /// Required.
    #[prost(bytes="vec", tag="4")]
    pub y: ::prost::alloc::vec::Vec<u8>,
}
/// key_type: type.googleapis.com/google.crypto.tink.EcdsaPrivateKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaPrivateKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub public_key: ::core::option::Option<EcdsaPublicKey>,
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EcdsaKeyFormat {
    /// Required.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<EcdsaParams>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum EcdsaSignatureEncoding {
    UnknownEncoding = 0,
    /// The signature's format is r || s, where r and s are zero-padded and have
    /// the same size in bytes as the order of the curve. For example, for NIST
    /// P-256 curve, r and s are zero-padded to 32 bytes.
    IeeeP1363 = 1,
    /// The signature is encoded using ASN.1
    /// (https://tools.ietf.org/html/rfc5480#appendix-A):
    /// ECDSA-Sig-Value :: = SEQUENCE {
    ///  r INTEGER,
    ///  s INTEGER
    /// }
    Der = 2,
}
// Each instantiation of a Tink primitive is identified by type_url,
// which is a global URL pointing to a *Key-proto that holds key material
// and other parameters of the instantiation.  For standard Tink key types
// the value of type_url follows the structure of type_url-field of
// google.protobuf.Any-protos, and is given as:
//
//   type.googleapis.com/packagename.messagename
//
// For example, for an HMAC key defined in proto google.cloud.tink.HmacKey
// the value of type_url is:
//
//   type.googleapis.com/google.cloud.tink.HmacKey
//
// For each type_url, in addition to the *Key proto, there exist two
// related structures:
//   1. *Params: parameters of an instantiation of the primitive,
//      needed when a key is being used.
//   2. *KeyFormat: parameters needed to generate a new key; these
//      include the corresponding Params, since when a factory generates
//      a key based on KeyFormat, it must add Params to the resulting
//      key proto with the actual key material.
// The actual *KeyFormat proto is wrapped in a KeyTemplate message.
// By convention, the name of the *KeyFormat-proto must be equal
// to the name of the *Key-proto from type_url-field suffixed with "Format".

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyTemplate {
    /// Required.
    ///
    /// in format type.googleapis.com/packagename.messagename
    #[prost(string, tag="1")]
    pub type_url: ::prost::alloc::string::String,
    /// Optional.
    /// If missing, it means the key type doesn't require a *KeyFormat proto.
    ///
    /// contains specific serialized *KeyFormat proto
    #[prost(bytes="vec", tag="2")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    /// Optional.
    /// If missing, uses OutputPrefixType.TINK.
    #[prost(enumeration="OutputPrefixType", tag="3")]
    pub output_prefix_type: i32,
}
// Each *Key proto by convention contains a version field, which
// identifies the version of implementation that can work with this key.
//   message SomeInstantiationKey {
//     uint32 version = 1;
//     ...
//   }
// Version is a monotonic counter: each implementation of a primitive
// has its associated "current version", which starts at 0 and is incremented
// upon updates of the code/key proto.  A key with version n needs
// an implementation version n or higher to work.

// For public key primitives, the public and private keys are distinct entities
// and represent distinct primitives.  However, by convention, the private key
// of a public-key primitive contains the corresponding public key proto.

/// The actual *Key-proto is wrapped in a KeyData message, which in addition
/// to this serialized proto contains also type_url identifying the
/// definition of *Key-proto (as in KeyFormat-message), and some extra metadata
/// about the type key material.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeyData {
    /// Required.
    ///
    /// In format type.googleapis.com/packagename.messagename
    #[prost(string, tag="1")]
    pub type_url: ::prost::alloc::string::String,
    /// Required.
    ///
    /// contains specific serialized *Key proto
    #[prost(bytes="vec", tag="2")]
    #[serde(with = "crate::json::b64")]
    pub value: ::prost::alloc::vec::Vec<u8>,
    /// Required.
    #[prost(enumeration="key_data::KeyMaterialType", tag="3")]
    #[serde(with = "crate::json::key_material_type")]
    pub key_material_type: i32,
}
/// Nested message and enum types in `KeyData`.
pub mod key_data {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
    #[repr(i32)]
    pub enum KeyMaterialType {
        UnknownKeymaterial = 0,
        Symmetric = 1,
        AsymmetricPrivate = 2,
        AsymmetricPublic = 3,
        /// points to a remote key, i.e., in a KMS.
        Remote = 4,
    }
}
/// A Tink user works usually not with single keys, but with keysets,
/// to enable key rotation.  The keys in a keyset can belong to different
/// implementations/key types, but must all implement the same primitive.
/// Any given keyset (and any given key) can be used for one primitive only.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Keyset {
    /// Identifies key used to generate new crypto data (encrypt, sign).
    /// Required.
    #[prost(uint32, tag="1")]
    pub primary_key_id: u32,
    /// Actual keys in the Keyset.
    /// Required.
    #[prost(message, repeated, tag="2")]
    pub key: ::prost::alloc::vec::Vec<keyset::Key>,
}
/// Nested message and enum types in `Keyset`.
pub mod keyset {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Key {
        /// Contains the actual, instantiation specific key proto.
        /// By convention, each key proto contains a version field.
        #[prost(message, optional, tag="1")]
        pub key_data: ::core::option::Option<super::KeyData>,
        #[prost(enumeration="super::KeyStatusType", tag="2")]
        #[serde(with = "crate::json::key_status_type")]
        pub status: i32,
        /// Identifies a key within a keyset, is a part of metadata
        /// of a ciphertext/signature.
        #[prost(uint32, tag="3")]
        pub key_id: u32,
        /// Determines the prefix of the ciphertexts/signatures produced by this key.
        /// This value is copied verbatim from the key template.
        #[prost(enumeration="super::OutputPrefixType", tag="4")]
        #[serde(with = "crate::json::output_prefix_type")]
        pub output_prefix_type: i32,
    }
}
/// Represents a "safe" Keyset that doesn't contain any actual key material,
/// thus can be used for logging or monitoring. Most fields are copied from
/// Keyset.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KeysetInfo {
    /// See Keyset.primary_key_id.
    #[prost(uint32, tag="1")]
    pub primary_key_id: u32,
    /// KeyInfos in the KeysetInfo.
    /// Each KeyInfo is corresponding to a Key in the corresponding Keyset.
    #[prost(message, repeated, tag="2")]
    pub key_info: ::prost::alloc::vec::Vec<keyset_info::KeyInfo>,
}
/// Nested message and enum types in `KeysetInfo`.
pub mod keyset_info {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct KeyInfo {
        /// the type url of this key,
        /// e.g., type.googleapis.com/google.crypto.tink.HmacKey.
        #[prost(string, tag="1")]
        pub type_url: ::prost::alloc::string::String,
        /// See Keyset.Key.status.
        #[prost(enumeration="super::KeyStatusType", tag="2")]
        #[serde(with = "crate::json::key_status_type")]
        pub status: i32,
        /// See Keyset.Key.key_id.
        #[prost(uint32, tag="3")]
        pub key_id: u32,
        /// See Keyset.Key.output_prefix_type.
        #[prost(enumeration="super::OutputPrefixType", tag="4")]
        #[serde(with = "crate::json::output_prefix_type")]
        pub output_prefix_type: i32,
    }
}
/// Represents a keyset that is encrypted with a master key.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EncryptedKeyset {
    /// Required.
    #[prost(bytes="vec", tag="2")]
    #[serde(with = "crate::json::b64")]
    pub encrypted_keyset: ::prost::alloc::vec::Vec<u8>,
    /// Optional.
    #[prost(message, optional, tag="3")]
    pub keyset_info: ::core::option::Option<KeysetInfo>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum KeyStatusType {
    UnknownStatus = 0,
    /// Can be used for crypto operations.
    Enabled = 1,
    /// Cannot be used, but exists and can become ENABLED.
    Disabled = 2,
    /// Key data does not exist in this Keyset any more.
    Destroyed = 3,
}
/// Tink produces and accepts ciphertexts or signatures that consist
/// of a prefix and a payload. The payload and its format is determined
/// entirely by the primitive, but the prefix has to be one of the following
/// 4 types:
///   - Legacy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte
///             key id that is computed from the key material.
///   - Crunchy: prefix is 5 bytes, starts with \x00 and followed by a 4-byte
///             key id that is generated randomly.
///   - Tink  : prefix is 5 bytes, starts with \x01 and followed by 4-byte
///             key id that is generated randomly.
///   - Raw   : prefix is 0 byte, i.e., empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OutputPrefixType {
    UnknownPrefix = 0,
    Tink = 1,
    Legacy = 2,
    Raw = 3,
    /// CRUNCHY is like LEGACY, but with two differences:
    ///   - Its key id is generated randomly (like TINK)
    ///   - Its signature schemes don't append zero to sign messages
    Crunchy = 4,
}
// Protos for keys for ECIES with HKDF and AEAD encryption.
//
// These definitions follow loosely ECIES ISO 18033-2 standard
// (Elliptic Curve Integrated Encryption Scheme, see
// http://www.shoup.net/iso/std6.pdf), with but with some differences:
//  * use of HKDF key derivation function (instead of KDF1 and KDF2) enabling
//  the use
//    of optional parameters to the key derivation function, which strenghten
//    the overall security and allow for binding the key material to
//    application-specific information (cf. RFC 5869,
//    https://tools.ietf.org/html/rfc5869)
//  * use of modern AEAD schemes rather than "manual composition" of symmetric
//  encryption
//    with message authentication codes (as in DEM1, DEM2, and DEM3 schemes of
//    ISO 18033-2)
//
// ECIES-keys represent HybridEncryption resp. HybridDecryption primitives.

/// Parameters of KEM (Key Encapsulation Mechanism)
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesHkdfKemParams {
    /// Required.
    #[prost(enumeration="EllipticCurveType", tag="1")]
    pub curve_type: i32,
    /// Required.
    #[prost(enumeration="HashType", tag="2")]
    pub hkdf_hash_type: i32,
    /// Optional.
    #[prost(bytes="vec", tag="11")]
    pub hkdf_salt: ::prost::alloc::vec::Vec<u8>,
}
/// Parameters of AEAD DEM (Data Encapsulation Mechanism).
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesAeadDemParams {
    /// Required.
    ///
    /// Contains e.g. AesCtrHmacAeadKeyFormat or AesGcmKeyFormat.
    #[prost(message, optional, tag="2")]
    pub aead_dem: ::core::option::Option<KeyTemplate>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesAeadHkdfParams {
    /// Key Encapsulation Mechanism.
    /// Required.
    #[prost(message, optional, tag="1")]
    pub kem_params: ::core::option::Option<EciesHkdfKemParams>,
    /// Data Encapsulation Mechanism.
    /// Required.
    #[prost(message, optional, tag="2")]
    pub dem_params: ::core::option::Option<EciesAeadDemParams>,
    /// EC point format.
    /// Required.
    #[prost(enumeration="EcPointFormat", tag="3")]
    pub ec_point_format: i32,
}
/// EciesAeadHkdfPublicKey represents HybridEncryption primitive.
/// key_type: type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesAeadHkdfPublicKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<EciesAeadHkdfParams>,
    /// Affine coordinates of the public key in bigendian representation.
    /// The public key is a point (x, y) on the curve defined by
    /// params.kem_params.curve. Required.
    #[prost(bytes="vec", tag="3")]
    pub x: ::prost::alloc::vec::Vec<u8>,
    /// Required.
    #[prost(bytes="vec", tag="4")]
    pub y: ::prost::alloc::vec::Vec<u8>,
}
/// EciesKdfAeadPrivateKey represents HybridDecryption primitive.
/// key_type: type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesAeadHkdfPrivateKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub public_key: ::core::option::Option<EciesAeadHkdfPublicKey>,
    /// Required.
    ///
    /// Big integer in bigendian representation.
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EciesAeadHkdfKeyFormat {
    /// Required.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<EciesAeadHkdfParams>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ed25519KeyFormat {
}
/// key_type: type.googleapis.com/google.crypto.tink.Ed25519PublicKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ed25519PublicKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// The public key is 32 bytes, encoded according to
    /// https://tools.ietf.org/html/rfc8032#section-5.1.2.
    /// Required.
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
/// key_type: type.googleapis.com/google.crypto.tink.Ed25519PrivateKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Ed25519PrivateKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// The private key is 32 bytes of cryptographically secure random data.
    /// See https://tools.ietf.org/html/rfc8032#section-5.1.5.
    /// Required.
    #[prost(bytes="vec", tag="2")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
    /// The corresponding public key.
    #[prost(message, optional, tag="3")]
    pub public_key: ::core::option::Option<Ed25519PublicKey>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Empty {
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HkdfPrfParams {
    #[prost(enumeration="HashType", tag="1")]
    pub hash: i32,
    /// Salt, optional in RFC 5869. Using "" is equivalent to zeros of length up to
    /// the block length of the HMac.
    #[prost(bytes="vec", tag="2")]
    pub salt: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HkdfPrfKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<HkdfPrfParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HkdfPrfKeyFormat {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<HkdfPrfParams>,
    #[prost(uint32, tag="2")]
    pub key_size: u32,
    #[prost(uint32, tag="3")]
    pub version: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacPrfParams {
    /// HashType is an enum.
    #[prost(enumeration="HashType", tag="1")]
    pub hash: i32,
}
/// key_type: type.googleapis.com/google.crypto.tink.HmacPrfKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacPrfKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<HmacPrfParams>,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HmacPrfKeyFormat {
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<HmacPrfParams>,
    #[prost(uint32, tag="2")]
    pub key_size: u32,
    #[prost(uint32, tag="3")]
    pub version: u32,
}
/// key_type: type.googleapis.com/google.crypto.tink.JwtHmacKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtHmacKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(enumeration="HashType", tag="2")]
    pub hash_type: i32,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct JwtHmacKeyFormat {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(enumeration="HashType", tag="2")]
    pub hash_type: i32,
    #[prost(uint32, tag="3")]
    pub key_size: u32,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KmsAeadKeyFormat {
    /// Required.
    /// The location of a KMS key.
    /// With Google Cloud KMS, valid values have this format:
    /// gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.
    /// With AWS KMS, valid values have this format:
    /// aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>
    #[prost(string, tag="1")]
    pub key_uri: ::prost::alloc::string::String,
}
/// There is no actual key material in the key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KmsAeadKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// The key format also contains the params.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<KmsAeadKeyFormat>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KmsEnvelopeAeadKeyFormat {
    /// Required.
    /// The location of the KEK in a remote KMS.
    /// With Google Cloud KMS, valid values have this format:
    /// gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*.
    /// With AWS KMS, valid values have this format:
    /// aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>
    #[prost(string, tag="1")]
    pub kek_uri: ::prost::alloc::string::String,
    /// Key template of the Data Encryption Key, e.g., AesCtrHmacAeadKeyFormat.
    /// Required.
    #[prost(message, optional, tag="2")]
    pub dek_template: ::core::option::Option<KeyTemplate>,
}
/// There is no actual key material in the key.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct KmsEnvelopeAeadKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// The key format also contains the params.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<KmsEnvelopeAeadKeyFormat>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfBasedDeriverParams {
    #[prost(message, optional, tag="1")]
    pub derived_key_template: ::core::option::Option<KeyTemplate>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfBasedDeriverKeyFormat {
    #[prost(message, optional, tag="1")]
    pub prf_key_template: ::core::option::Option<KeyTemplate>,
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<PrfBasedDeriverParams>,
}
/// key_type: type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrfBasedDeriverKey {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(message, optional, tag="2")]
    pub prf_key: ::core::option::Option<KeyData>,
    #[prost(message, optional, tag="3")]
    pub params: ::core::option::Option<PrfBasedDeriverParams>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPkcs1Params {
    /// Hash function used in computing hash of the signing message
    /// (see https://tools.ietf.org/html/rfc8017#section-9.2).
    /// Required.
    #[prost(enumeration="HashType", tag="1")]
    pub hash_type: i32,
}
/// key_type: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPkcs1PublicKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<RsaSsaPkcs1Params>,
    /// Modulus.
    /// Unsigned big integer in bigendian representation.
    #[prost(bytes="vec", tag="3")]
    pub n: ::prost::alloc::vec::Vec<u8>,
    /// Public exponent.
    /// Unsigned big integer in bigendian representation.
    #[prost(bytes="vec", tag="4")]
    pub e: ::prost::alloc::vec::Vec<u8>,
}
/// key_type: type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPkcs1PrivateKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub public_key: ::core::option::Option<RsaSsaPkcs1PublicKey>,
    /// Private exponent.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub d: ::prost::alloc::vec::Vec<u8>,
    /// The following parameters are used to optimize RSA signature computation.
    /// The prime factor p of n.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="4")]
    pub p: ::prost::alloc::vec::Vec<u8>,
    /// The prime factor q of n.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="5")]
    pub q: ::prost::alloc::vec::Vec<u8>,
    /// d mod (p - 1).
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="6")]
    pub dp: ::prost::alloc::vec::Vec<u8>,
    /// d mod (q - 1).
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="7")]
    pub dq: ::prost::alloc::vec::Vec<u8>,
    /// Chinese Remainder Theorem coefficient q^(-1) mod p.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="8")]
    pub crt: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPkcs1KeyFormat {
    /// Required.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<RsaSsaPkcs1Params>,
    /// Required.
    #[prost(uint32, tag="2")]
    pub modulus_size_in_bits: u32,
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub public_exponent: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPssParams {
    /// Hash function used in computing hash of the signing message
    /// (see https://tools.ietf.org/html/rfc8017#section-9.1.1).
    /// Required.
    #[prost(enumeration="HashType", tag="1")]
    pub sig_hash: i32,
    /// Hash function used in MGF1 (a mask generation function based on a
    /// hash function) (see https://tools.ietf.org/html/rfc8017#appendix-B.2.1).
    /// Required.
    #[prost(enumeration="HashType", tag="2")]
    pub mgf1_hash: i32,
    /// Salt length (see https://tools.ietf.org/html/rfc8017#section-9.1.1)
    /// Required.
    #[prost(int32, tag="3")]
    pub salt_length: i32,
}
/// key_type: type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPssPublicKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub params: ::core::option::Option<RsaSsaPssParams>,
    /// Modulus.
    /// Unsigned big integer in bigendian representation.
    #[prost(bytes="vec", tag="3")]
    pub n: ::prost::alloc::vec::Vec<u8>,
    /// Public exponent.
    /// Unsigned big integer in bigendian representation.
    #[prost(bytes="vec", tag="4")]
    pub e: ::prost::alloc::vec::Vec<u8>,
}
/// key_type: type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPssPrivateKey {
    /// Required.
    #[prost(uint32, tag="1")]
    pub version: u32,
    /// Required.
    #[prost(message, optional, tag="2")]
    pub public_key: ::core::option::Option<RsaSsaPssPublicKey>,
    /// Private exponent.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub d: ::prost::alloc::vec::Vec<u8>,
    /// The following parameters are used to optimize RSA signature computation.
    /// The prime factor p of n.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="4")]
    pub p: ::prost::alloc::vec::Vec<u8>,
    /// The prime factor q of n.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="5")]
    pub q: ::prost::alloc::vec::Vec<u8>,
    /// d mod (p - 1).
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="6")]
    pub dp: ::prost::alloc::vec::Vec<u8>,
    /// d mod (q - 1).
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="7")]
    pub dq: ::prost::alloc::vec::Vec<u8>,
    /// Chinese Remainder Theorem coefficient q^(-1) mod p.
    /// Unsigned big integer in bigendian representation.
    /// Required.
    #[prost(bytes="vec", tag="8")]
    pub crt: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RsaSsaPssKeyFormat {
    /// Required.
    #[prost(message, optional, tag="1")]
    pub params: ::core::option::Option<RsaSsaPssParams>,
    /// Required.
    #[prost(uint32, tag="2")]
    pub modulus_size_in_bits: u32,
    /// Required.
    #[prost(bytes="vec", tag="3")]
    pub public_exponent: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XChaCha20Poly1305KeyFormat {
}
/// key_type: type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct XChaCha20Poly1305Key {
    #[prost(uint32, tag="1")]
    pub version: u32,
    #[prost(bytes="vec", tag="3")]
    pub key_value: ::prost::alloc::vec::Vec<u8>,
}

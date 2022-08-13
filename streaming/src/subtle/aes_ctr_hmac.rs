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

//! AES-CTR-HMAC based implementation of the [`tink_core::StreamingAead`] trait.

use super::{noncebased, AesVariant};
use aes::cipher::{KeyIvInit, StreamCipher};
use std::convert::TryInto;
use tink_core::{subtle::random::get_random_bytes, utils::wrap_err, Mac, TinkError};
use tink_proto::HashType;

/// The size of the nonces used as IVs for CTR.
pub const AES_CTR_HMAC_NONCE_SIZE_IN_BYTES: usize = 16;

/// The size of the nonce prefix.
pub const AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES: usize = 7;

/// The size of the HMAC key.
pub const AES_CTR_HMAC_KEY_SIZE_IN_BYTES: usize = 32;

type Aes128Ctr = ::ctr::Ctr64BE<aes::Aes128>;
type Aes256Ctr = ::ctr::Ctr64BE<aes::Aes256>;

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum AesCtrKeyVariant {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
}

/// `AesCtrHmac` implements streaming AEAD encryption using AES-CTR and HMAC.
///
/// Each ciphertext uses new AES-CTR and HMAC keys. These keys are derived using
/// HKDF and are derived from the key derivation key, a randomly chosen salt of
/// the same size as the key and a nonce prefix.
#[derive(Clone)]
pub struct AesCtrHmac {
    pub main_key: Vec<u8>,
    hkdf_alg: HashType,
    aes_variant: AesVariant,
    tag_alg: HashType,
    tag_size_in_bytes: usize,
    ciphertext_segment_size: usize,
    plaintext_segment_size: usize,
    first_ciphertext_segment_offset: usize,
}

/// Calculate the header length for a given key size.  The header includes
/// space for:
/// - a single byte indicating header length
/// - a salt that is the same size as the sub key
/// - a nonce prefix.
fn header_length_for(key_size_in_bytes: usize) -> usize {
    1 + key_size_in_bytes + AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES
}

impl AesCtrHmac {
    /// Initialize an AES_CTR_HMAC primitive with a key derivation key and encryption parameters.
    ///
    /// `main_key` is input keying material used to derive sub keys.  This must be
    /// longer than the size of the sub keys (`key_size_in_bytes`).
    /// `hkdf_alg` is a MAC algorithm hash type, used for the HKDF key derivation.
    /// `key_size_in_bytes` is the key size of the sub keys.
    /// `tag_alg` is the MAC algorithm hash type, used for generating per segment tags.
    /// `tag_size_in_bytes` is the size of the per segment tags.
    /// `ciphertext_segment_size` is the size of ciphertext segments.
    /// `first_segment_offset` is the offset of the first ciphertext segment.
    pub fn new(
        main_key: &[u8],
        hkdf_alg: HashType,
        key_size_in_bytes: usize,
        tag_alg: HashType,
        tag_size_in_bytes: usize,
        ciphertext_segment_size: usize,
        first_segment_offset: usize,
    ) -> Result<AesCtrHmac, TinkError> {
        if main_key.len() < 16 || main_key.len() < key_size_in_bytes {
            return Err("main_key too short".into());
        }
        let aes_variant = super::validate_aes_key_size(key_size_in_bytes)?;
        if tag_size_in_bytes < 10 {
            return Err("tag size too small".into());
        }
        let digest_size = tink_core::subtle::get_hash_digest_size(tag_alg)?;
        if tag_size_in_bytes > digest_size {
            return Err("tag size too big".into());
        }
        let header_len = header_length_for(key_size_in_bytes);
        if ciphertext_segment_size <= first_segment_offset + header_len + tag_size_in_bytes {
            return Err("ciphertext_segment_size too small".into());
        }

        Ok(AesCtrHmac {
            main_key: main_key.to_vec(),
            hkdf_alg,
            aes_variant,
            tag_alg,
            tag_size_in_bytes,
            ciphertext_segment_size,
            first_ciphertext_segment_offset: first_segment_offset + header_len,
            plaintext_segment_size: ciphertext_segment_size - tag_size_in_bytes,
        })
    }

    /// Return the length of the encryption header.
    pub fn header_length(&self) -> usize {
        header_length_for(self.aes_variant.key_size())
    }

    /// Return a key derived from the main key using` salt` and `aad` as parameters.
    fn derive_key_material(&self, salt: &[u8], aad: &[u8]) -> Result<Vec<u8>, TinkError> {
        let key_material_size = self.aes_variant.key_size() + AES_CTR_HMAC_KEY_SIZE_IN_BYTES;
        tink_core::subtle::compute_hkdf(self.hkdf_alg, &self.main_key, salt, aad, key_material_size)
    }
}

impl tink_core::StreamingAead for AesCtrHmac {
    /// Return a wrapper around an underlying [`std::io.Write`], such that
    /// any write-operation via the wrapper results in AEAD-encryption of the
    /// written data, using `aad` as associated authenticated data. The associated
    /// data is not included in the ciphertext and has to be passed in as parameter
    /// for decryption.
    fn new_encrypting_writer(
        &self,
        mut w: Box<dyn std::io::Write>,
        aad: &[u8],
    ) -> Result<Box<dyn tink_core::EncryptingWrite>, TinkError> {
        let key_size = self.aes_variant.key_size();
        let salt = get_random_bytes(key_size);
        let nonce_prefix = get_random_bytes(AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES);

        let km = self.derive_key_material(&salt, aad)?;

        let aes_key = match self.aes_variant {
            AesVariant::Aes128 => {
                AesCtrKeyVariant::Aes128(
                    km[..key_size].to_vec().try_into().unwrap(/* safe: len checked */),
                )
            }
            AesVariant::Aes256 => {
                AesCtrKeyVariant::Aes256(
                    km[..key_size].to_vec().try_into().unwrap(/* safe: len checked */),
                )
            }
        };
        let hmac_key = &km[key_size..];
        let hmac = tink_mac::subtle::Hmac::new(self.tag_alg, hmac_key, self.tag_size_in_bytes)?;

        let mut header = Vec::with_capacity(self.header_length());
        header.push(
            self.header_length()
                .try_into()
                .map_err(|e| wrap_err("header length too long", e))?,
        );
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce_prefix);
        w.write(&header).map_err(|e| wrap_err("write failed", e))?;

        let nw = noncebased::Writer::new(noncebased::WriterParams {
            w,
            segment_encrypter: Box::new(AesCtrHmacSegmentEncrypter {
                aes_key,
                hmac,
                tag_size_in_bytes: self.tag_size_in_bytes,
            }),
            nonce_size: AES_CTR_HMAC_NONCE_SIZE_IN_BYTES,
            nonce_prefix,
            plaintext_segment_size: self.plaintext_segment_size,
            first_ciphertext_segment_offset: self.first_ciphertext_segment_offset,
        })?;
        Ok(Box::new(nw))
    }

    /// Return a wrapper around an underlying [`std::io::Read`], such that
    /// any read-operation via the wrapper results in AEAD-decryption of the
    /// underlying ciphertext, using aad as associated authenticated data.
    fn new_decrypting_reader(
        &self,
        mut r: Box<dyn std::io::Read>,
        aad: &[u8],
    ) -> Result<Box<dyn std::io::Read>, TinkError> {
        let mut hlen = vec![0; 1];
        r.read_exact(&mut hlen)
            .map_err(|e| wrap_err("failed to reader header len", e))?;
        if hlen[0] as usize != self.header_length() {
            return Err("invalid header length".into());
        }

        let key_size = self.aes_variant.key_size();
        let mut salt = vec![0; key_size];
        r.read_exact(&mut salt)
            .map_err(|e| wrap_err("cannot read salt", e))?;

        let mut nonce_prefix = vec![0; AES_CTR_HMAC_NONCE_PREFIX_SIZE_IN_BYTES];
        r.read_exact(&mut nonce_prefix)
            .map_err(|e| wrap_err("cannot read nonce_prefix", e))?;

        let km = self.derive_key_material(&salt, aad)?;

        let aes_key = match self.aes_variant {
            AesVariant::Aes128 => {
                AesCtrKeyVariant::Aes128(
                    km[..key_size].to_vec().try_into().unwrap(/* safe: len checked */),
                )
            }
            AesVariant::Aes256 => {
                AesCtrKeyVariant::Aes256(
                    km[..key_size].to_vec().try_into().unwrap(/* safe: len checked */),
                )
            }
        };
        let hmac_key = &km[self.aes_variant.key_size()..];
        let hmac = tink_mac::subtle::Hmac::new(self.tag_alg, hmac_key, self.tag_size_in_bytes)?;

        let nr = noncebased::Reader::new(noncebased::ReaderParams {
            r,
            segment_decrypter: Box::new(AesCtrHmacSegmentDecrypter {
                aes_key,
                hmac,
                tag_size_in_bytes: self.tag_size_in_bytes,
            }),
            nonce_size: AES_CTR_HMAC_NONCE_SIZE_IN_BYTES,
            nonce_prefix,
            ciphertext_segment_size: self.ciphertext_segment_size,
            first_ciphertext_segment_offset: self.first_ciphertext_segment_offset,
        })?;

        Ok(Box::new(nr))
    }
}

/// A [`noncebased::SegmentEncrypter`] based on AES-CTR-HMAC.
struct AesCtrHmacSegmentEncrypter {
    aes_key: AesCtrKeyVariant,
    hmac: tink_mac::subtle::Hmac,
    tag_size_in_bytes: usize,
}

impl noncebased::SegmentEncrypter for AesCtrHmacSegmentEncrypter {
    fn encrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError> {
        let s_len = segment.len();
        let n_len = nonce.len();
        let ct_len = s_len + self.tag_size_in_bytes;
        let mut ciphertext = vec![0; ct_len];

        ciphertext[..s_len].copy_from_slice(segment);
        match &self.aes_key {
            AesCtrKeyVariant::Aes128(key) => {
                let mut stream =
                    Aes128Ctr::new_from_slices(key, nonce).unwrap(/* safe: len checked */);
                stream.apply_keystream(&mut ciphertext[..s_len]);
            }
            AesCtrKeyVariant::Aes256(key) => {
                let mut stream =
                    Aes256Ctr::new_from_slices(key, nonce).unwrap(/* safe: len checked */);
                stream.apply_keystream(&mut ciphertext[..s_len]);
            }
        }

        let mut mac_input = Vec::with_capacity(n_len + s_len);
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(&ciphertext[..s_len]);
        let tag = self.hmac.compute_mac(&mac_input)?;
        ciphertext[s_len..].copy_from_slice(&tag);

        Ok(ciphertext)
    }
}

/// A [`noncebased::SegmentDecrypter`] based on AES-CTR-HMAC.
struct AesCtrHmacSegmentDecrypter {
    aes_key: AesCtrKeyVariant,
    hmac: tink_mac::subtle::Hmac,
    tag_size_in_bytes: usize,
}

impl noncebased::SegmentDecrypter for AesCtrHmacSegmentDecrypter {
    fn decrypt_segment(&self, segment: &[u8], nonce: &[u8]) -> Result<Vec<u8>, TinkError> {
        let s_len = segment.len();
        let n_len = nonce.len();
        if self.tag_size_in_bytes > s_len {
            return Err("segment too short".into());
        }
        let tag_start = s_len - self.tag_size_in_bytes;
        let tag = &segment[tag_start..];

        let mut mac_input = Vec::with_capacity(n_len + s_len);
        mac_input.extend_from_slice(nonce);
        mac_input.extend_from_slice(&segment[..tag_start]);
        if self.hmac.verify_mac(tag, &mac_input).is_err() {
            return Err("tag mismatch".into());
        }

        let mut result = (&segment[..tag_start]).to_vec();
        match &self.aes_key {
            AesCtrKeyVariant::Aes128(key) => {
                let mut stream =
                    Aes128Ctr::new_from_slices(key, nonce).unwrap(/* safe: len checked */);
                stream.apply_keystream(&mut result);
            }
            AesCtrKeyVariant::Aes256(key) => {
                let mut stream =
                    Aes256Ctr::new_from_slices(key, nonce).unwrap(/* safe: len checked */);
                stream.apply_keystream(&mut result);
            }
        }

        Ok(result)
    }
}

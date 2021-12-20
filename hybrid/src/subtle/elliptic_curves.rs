// Copyright 2020-2021 The Tink-Rust Authors
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

use p256::{
    elliptic_curve,
    elliptic_curve::{
        ecdh,
        generic_array::typenum::Unsigned,
        sec1::{EncodedPoint, FromEncodedPoint},
        AffinePoint,
    },
};
use tink_core::{utils::wrap_err, TinkError};
use tink_proto::{EcPointFormat, EllipticCurveType};

// See SEC 1 section 2.3.3.
/// Prefix byte indicating uncompressed format (x || y)
const EC_FORMAT_PREFIX_UNCOMPRESSED: u8 = 4;
/// Prefix byte indicating compressed format (x, with y having 1 final bit).
const EC_FORMAT_PREFIX_COMPRESSED_ODD: u8 = 3;
/// Prefix byte indicating compressed format (x, with y having 0 final bit).
const EC_FORMAT_PREFIX_COMPRESSED_EVEN: u8 = 2;

/// An elliptic curve public key.
#[derive(Debug, Clone)]
pub enum EcPublicKey {
    NistP256(AffinePoint<p256::NistP256>),
}

impl EcPublicKey {
    pub fn new(curve: EllipticCurveType, x: &[u8], y: &[u8]) -> Result<Self, TinkError> {
        match curve {
            EllipticCurveType::NistP256 => {
                let x = element_from_padded_slice::<p256::NistP256>(x)?;
                let y = element_from_padded_slice::<p256::NistP256>(y)?;
                let encoded_pt = EncodedPoint::<p256::NistP256>::from_affine_coordinates(
                    &x, &y, /* compress= */ false,
                );
                let affine_pt = AffinePoint::<p256::NistP256>::from_encoded_point(&encoded_pt)
                    .ok_or_else(|| TinkError::new("invalid point"))?;
                Ok(EcPublicKey::NistP256(affine_pt))
            }
            _ => Err(format!("unsupported curve {:?}", curve).into()),
        }
    }

    pub fn curve(&self) -> EllipticCurveType {
        match self {
            EcPublicKey::NistP256(_) => EllipticCurveType::NistP256,
        }
    }

    pub fn x_y_bytes(&self) -> Result<(Vec<u8>, Vec<u8>), TinkError> {
        match self {
            EcPublicKey::NistP256(affine_pt) => {
                // Check that the public key data is in the expected uncompressed format:
                //  - 1 byte uncompressed prefix (0x04)
                //  - P bytes of X coordinate
                //  - P bytes of Y coordinate
                // where P is the field element size.
                let encoded_pt: EncodedPoint<p256::NistP256> =
                    EncodedPoint::<p256::NistP256>::from(*affine_pt);
                let pub_key_data = encoded_pt.as_bytes().to_vec();
                let point_len = elliptic_curve::FieldSize::<p256::NistP256>::to_usize();
                if pub_key_data.len() != 2 * point_len + 1
                    || pub_key_data[0] != EC_FORMAT_PREFIX_UNCOMPRESSED
                {
                    Err("unexpected public key data format".into())
                } else {
                    Ok((
                        pub_key_data[1..point_len + 1].to_vec(),
                        pub_key_data[point_len + 1..].to_vec(),
                    ))
                }
            }
        }
    }
}

/// An elliptic curve private key.
#[derive(Clone)]
pub enum EcPrivateKey {
    NistP256(p256::NonZeroScalar),
}

impl EcPrivateKey {
    pub fn public_key(&self) -> EcPublicKey {
        match self {
            EcPrivateKey::NistP256(d) => {
                let pub_key = p256::PublicKey::from_secret_scalar(d);
                EcPublicKey::NistP256(*pub_key.as_affine())
            }
        }
    }
    pub fn d_bytes(&self) -> Vec<u8> {
        match self {
            EcPrivateKey::NistP256(d) => d.to_bytes().to_vec(),
        }
    }
}

impl EcPrivateKey {
    /// Convert a stored private key to an `EcPrivateKey`.
    pub fn new(curve: EllipticCurveType, d: &[u8]) -> Result<EcPrivateKey, TinkError> {
        match curve {
            EllipticCurveType::NistP256 => {
                let d_elt = element_from_padded_slice::<p256::NistP256>(d)?;
                let d_scalar = p256::NonZeroScalar::from_repr(d_elt)
                    .ok_or_else(|| TinkError::new("failed to parse D value"))?;
                Ok(EcPrivateKey::NistP256(d_scalar))
            }
            _ => Err(format!("unsupported curve {:?}", curve).into()),
        }
    }
}

fn field_size_in_bytes(c: EllipticCurveType) -> Result<usize, TinkError> {
    match c {
        EllipticCurveType::NistP256 => Ok(elliptic_curve::FieldSize::<p256::NistP256>::to_usize()),
        _ => Err(format!("unsupported curve {:?}", c).into()),
    }
}

pub fn encoding_size_in_bytes(c: EllipticCurveType, p: EcPointFormat) -> Result<usize, TinkError> {
    let c_size = field_size_in_bytes(c)?;
    match p {
        EcPointFormat::Uncompressed => Ok(2 * c_size + 1), // 04 || x || y
        EcPointFormat::DoNotUseCrunchyUncompressed => Ok(2 * c_size), // x || y
        EcPointFormat::Compressed => Ok(c_size + 1),       // {02,03} || x
        _ => Err(format!("invalid point format {:?}", p).into()),
    }
}

/// Encode a point into the format specified.
pub fn point_encode(
    c: EllipticCurveType,
    p_format: EcPointFormat,
    pub_key: &EcPublicKey,
) -> Result<Vec<u8>, TinkError> {
    let c_size = field_size_in_bytes(c)?;
    let (x, y) = pub_key.x_y_bytes()?;
    match p_format {
        EcPointFormat::Uncompressed => {
            let mut encoded = vec![0; 2 * c_size + 1];
            (&mut encoded[1 + 2 * c_size - y.len()..]).copy_from_slice(&y);
            (&mut encoded[1 + c_size - x.len()..1 + c_size]).copy_from_slice(&x);
            encoded[0] = EC_FORMAT_PREFIX_UNCOMPRESSED;
            Ok(encoded)
        }
        EcPointFormat::DoNotUseCrunchyUncompressed => {
            let mut encoded = vec![0; 2 * c_size];
            (&mut encoded[2 * c_size - y.len()..]).copy_from_slice(&y);
            (&mut encoded[c_size - x.len()..c_size]).copy_from_slice(&x);
            Ok(encoded)
        }
        EcPointFormat::Compressed => {
            let mut encoded = vec![0; c_size + 1];
            encoded[0] = if y[y.len() - 1] & 0x01 == 1 {
                EC_FORMAT_PREFIX_COMPRESSED_ODD
            } else {
                EC_FORMAT_PREFIX_COMPRESSED_EVEN
            };
            (&mut encoded[1 + c_size - x.len()..]).copy_from_slice(&x);
            Ok(encoded)
        }
        _ => Err("invalid point format".into()),
    }
}

// Decode an encoded point to return an [`EcPubKey`].
pub fn point_decode(
    c: EllipticCurveType,
    p_format: EcPointFormat,
    e: &[u8],
) -> Result<EcPublicKey, TinkError> {
    let c_size = field_size_in_bytes(c)?;
    match p_format {
        EcPointFormat::Uncompressed => {
            if e.len() != (2 * c_size + 1) {
                return Err("invalid point size".into());
            }
            if e[0] != EC_FORMAT_PREFIX_UNCOMPRESSED {
                return Err("invalid point format".into());
            }
            match c {
                EllipticCurveType::NistP256 => {
                    let pub_key = p256::PublicKey::from_sec1_bytes(e)
                        .map_err(|e| wrap_err("invalid point", e))?;
                    Ok(EcPublicKey::NistP256(*pub_key.as_affine()))
                }
                _ => Err(format!("unsupported curve {:?}", c).into()),
            }
        }
        EcPointFormat::DoNotUseCrunchyUncompressed => {
            if e.len() != 2 * c_size {
                return Err("invalid point size".into());
            }
            let mut e_prefixed = Vec::with_capacity(1 + e.len());
            e_prefixed.push(EC_FORMAT_PREFIX_UNCOMPRESSED);
            e_prefixed.extend_from_slice(e);
            point_decode(c, EcPointFormat::Uncompressed, &e_prefixed)
        }
        EcPointFormat::Compressed => {
            if e.len() != c_size + 1 {
                return Err("compressed point has wrong length".into());
            }
            let _lsb = match e[0] {
                EC_FORMAT_PREFIX_COMPRESSED_EVEN => false,
                EC_FORMAT_PREFIX_COMPRESSED_ODD => true,
                _ => return Err("invalid format".into()),
            };
            match c {
                EllipticCurveType::NistP256 => {
                    let pub_key = p256::PublicKey::from_sec1_bytes(e)
                        .map_err(|e| wrap_err("invalid point", e))?;
                    Ok(EcPublicKey::NistP256(*pub_key.as_affine()))
                }
                _ => Err(format!("unsupported curve {:?}", c).into()),
            }
        }
        _ => Err(format!("invalid point format: {:?}", p_format).into()),
    }
}

/// Compute a shared secret using given private key and peer public key.
pub fn compute_shared_secret(
    peer_pub_key: &EcPublicKey,
    priv_key: &EcPrivateKey,
) -> Result<Vec<u8>, TinkError> {
    let shared_secret = match (peer_pub_key, priv_key) {
        (EcPublicKey::NistP256(peer_pub_key), EcPrivateKey::NistP256(priv_key)) => {
            ecdh::diffie_hellman(priv_key, peer_pub_key)
                .as_bytes()
                .to_vec()
        }
    };
    Ok(shared_secret)
}

/// Create a new private key for a given curve.
pub fn generate_ecdh_key_pair(c: EllipticCurveType) -> Result<EcPrivateKey, TinkError> {
    let mut csprng = elliptic_curve::rand_core::OsRng {};
    match c {
        EllipticCurveType::NistP256 => Ok(EcPrivateKey::NistP256(p256::NonZeroScalar::random(
            &mut csprng,
        ))),
        _ => Err(format!("unsupported curve {:?}", c).into()),
    }
}

/// Produce an elliptic field element from a byte slice, allowing for padding
pub(crate) fn element_from_padded_slice<C: elliptic_curve::Curve>(
    data: &[u8],
) -> Result<elliptic_curve::FieldBytes<C>, TinkError> {
    let point_len = elliptic_curve::FieldSize::<C>::to_usize();
    if data.len() >= point_len {
        let offset = data.len() - point_len;
        for v in data.iter().take(offset) {
            // Check that any excess bytes on the left over and above
            // the field size are all zeroes.
            if *v != 0 {
                return Err("point too large".into());
            }
        }
        Ok(elliptic_curve::FieldBytes::<C>::clone_from_slice(
            &data[offset..],
        ))
    } else {
        // We have been given data that is too short for the field size.
        // Left-pad it with zero bytes up to the field size.
        let mut data_copy = vec![0; point_len];
        data_copy[(point_len - data.len())..].copy_from_slice(data);
        Ok(elliptic_curve::FieldBytes::<C>::clone_from_slice(
            &data_copy,
        ))
    }
}

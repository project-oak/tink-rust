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

//! Handle wrapper for keysets.

use crate::{utils::wrap_err, TinkError};
use std::sync::Arc;
use tink_proto::{key_data::KeyMaterialType, prost::Message, Keyset, KeysetInfo};

/// `Handle` provides access to a [`Keyset`] protobuf, to limit the exposure
/// of actual protocol buffers that hold sensitive key material.
pub struct Handle {
    ks: Keyset,
}

impl Handle {
    /// Create a keyset handle that contains a single fresh key generated according
    /// to the given [`KeyTemplate`](tink_proto::KeyTemplate).
    pub fn new(kt: &tink_proto::KeyTemplate) -> Result<Self, TinkError> {
        let mut ksm = super::Manager::new();
        ksm.rotate(kt)
            .map_err(|e| wrap_err("keyset::Handle: cannot generate new keyset", e))?;
        ksm.handle()
            .map_err(|e| wrap_err("keyset::Handle: cannot get keyset handle", e))
    }

    /// Create a new instance of [`Handle`] using the given [`Keyset`] which does not contain any
    /// secret key material.
    pub fn new_with_no_secrets(ks: Keyset) -> Result<Self, TinkError> {
        let h = Handle {
            ks: validate_keyset(ks)?,
        };
        if h.has_secrets()? {
            // If you need to do this, you have to use `tink_core::keyset::insecure::read()`
            // instead.
            return Err("importing unencrypted secret key material is forbidden".into());
        }
        Ok(h)
    }

    /// Attempt to create a [`Handle`] from an encrypted keyset obtained via a
    /// [`Reader`](crate::keyset::Reader).
    pub fn read<T>(reader: &mut T, master_key: Box<dyn crate::Aead>) -> Result<Self, TinkError>
    where
        T: crate::keyset::Reader,
    {
        Self::read_with_associated_data(reader, master_key, &[])
    }

    /// Attempt to create a [`Handle`] from an encrypted keyset obtained via a
    /// [`Reader`](crate::keyset::Reader) using the provided associated data.
    pub fn read_with_associated_data<T>(
        reader: &mut T,
        master_key: Box<dyn crate::Aead>,
        associated_data: &[u8],
    ) -> Result<Self, TinkError>
    where
        T: crate::keyset::Reader,
    {
        let encrypted_keyset = reader.read_encrypted()?;
        let ks = decrypt(&encrypted_keyset, master_key, associated_data)?;
        Ok(Handle {
            ks: validate_keyset(ks)?,
        })
    }

    /// Attempt to create a [`Handle`] from a keyset obtained via a
    /// [`Reader`](crate::keyset::Reader).
    pub fn read_with_no_secrets<T>(reader: &mut T) -> Result<Self, TinkError>
    where
        T: crate::keyset::Reader,
    {
        let ks = reader.read()?;
        Handle::new_with_no_secrets(ks)
    }

    /// Return a [`Handle`] of the public keys if the managed keyset contains private keys.
    pub fn public(&self) -> Result<Self, TinkError> {
        let priv_keys = &self.ks.key;
        let mut pub_keys = Vec::with_capacity(priv_keys.len());
        for priv_key in priv_keys {
            let priv_key_data = priv_key
                .key_data
                .as_ref()
                .ok_or_else(|| TinkError::new("keyset::Handle: invalid keyset"))?;
            let pub_key_data =
                public_key_data(priv_key_data).map_err(|e| wrap_err("keyset::Handle", e))?;
            pub_keys.push(tink_proto::keyset::Key {
                key_data: Some(pub_key_data),
                status: priv_key.status,
                key_id: priv_key.key_id,
                output_prefix_type: priv_key.output_prefix_type,
            });
        }
        let ks = Keyset {
            primary_key_id: self.ks.primary_key_id,
            key: pub_keys,
        };
        Ok(Handle { ks })
    }

    /// Encrypts and writes the enclosed [`Keyset`].
    pub fn write<T>(
        &self,
        writer: &mut T,
        master_key: Box<dyn crate::Aead>,
    ) -> Result<(), TinkError>
    where
        T: super::Writer,
    {
        self.write_with_associated_data(writer, master_key, &[])
    }

    /// Encrypts and writes the enclosed [`Keyset`] using the provided associated data.
    pub fn write_with_associated_data<T>(
        &self,
        writer: &mut T,
        master_key: Box<dyn crate::Aead>,
        associated_data: &[u8],
    ) -> Result<(), TinkError>
    where
        T: super::Writer,
    {
        let encrypted = encrypt(&self.ks, master_key, associated_data)?;
        writer.write_encrypted(&encrypted)
    }

    /// Export the keyset in `h` to the given [`Writer`](super::Writer) returning an error if the
    /// keyset contains secret key material.
    pub fn write_with_no_secrets<T>(&self, w: &mut T) -> Result<(), TinkError>
    where
        T: super::Writer,
    {
        if self.has_secrets()? {
            Err("exporting unencrypted secret key material is forbidden".into())
        } else {
            w.write(&self.ks)
        }
    }

    /// Create a set of primitives corresponding to the keys with status=ENABLED in the keyset of
    /// the given keyset [`Handle`], assuming all the corresponding key managers are present (keys
    /// with status!=ENABLED are skipped).
    ///
    /// The returned set is usually later "wrapped" into a class that implements the corresponding
    /// [`Primitive`](crate::Primitive) interface.
    pub fn primitives(&self) -> Result<crate::primitiveset::PrimitiveSet, TinkError> {
        self.primitives_with_key_manager(None)
    }

    /// Create a set of primitives corresponding to the keys with status=ENABLED in the keyset of
    /// the given keyset [`Handle`], using the given key manager (instead of registered key
    /// managers) for keys supported by it.  Keys not supported by the key manager are handled
    /// by matching registered key managers (if present), and keys with status!=ENABLED are
    /// skipped.
    ///
    /// This enables custom treatment of keys, for example providing extra context (e.g. credentials
    /// for accessing keys managed by a KMS), or gathering custom monitoring/profiling
    /// information.
    ///
    /// The returned set is usually later "wrapped" into a class that implements the corresponding
    /// [`Primitive`](crate::Primitive)-interface.
    pub fn primitives_with_key_manager(
        &self,
        km: Option<Arc<dyn crate::registry::KeyManager>>,
    ) -> Result<crate::primitiveset::PrimitiveSet, TinkError> {
        super::validate(&self.ks)
            .map_err(|e| wrap_err("primitives_with_key_manager: invalid keyset", e))?;
        let mut primitive_set = crate::primitiveset::PrimitiveSet::new();
        for key in &self.ks.key {
            if key.status != tink_proto::KeyStatusType::Enabled as i32 {
                continue;
            }
            let key_data = key
                .key_data
                .as_ref()
                .ok_or_else(|| TinkError::new("primitives_with_key_manager: no key_data"))?;
            let primitive = match &km {
                Some(km) if km.does_support(&key_data.type_url) => km.primitive(&key_data.value),
                Some(_) | None => crate::registry::primitive_from_key_data(key_data),
            }
            .map_err(|e| {
                wrap_err(
                    "primitives_with_key_manager: cannot get primitive from key",
                    e,
                )
            })?;

            let entry = primitive_set
                .add(primitive, key)
                .map_err(|e| wrap_err("primitives_with_key_manager: cannot add primitive", e))?;
            if key.key_id == self.ks.primary_key_id {
                primitive_set.primary = Some(entry.clone());
            }
        }
        Ok(primitive_set)
    }

    /// Check if the keyset handle contains any key material considered secret.  Both symmetric keys
    /// and the private key of an asymmetric crypto system are considered secret keys. Also
    /// returns true when encountering any errors.
    fn has_secrets(&self) -> Result<bool, TinkError> {
        let mut result = false;
        for k in &self.ks.key {
            match &k.key_data {
                None => return Err("invalid keyset".into()),
                Some(kd) => match KeyMaterialType::from_i32(kd.key_material_type) {
                    Some(KeyMaterialType::UnknownKeymaterial) => result = true,
                    Some(KeyMaterialType::Symmetric) => result = true,
                    Some(KeyMaterialType::AsymmetricPrivate) => result = true,
                    Some(KeyMaterialType::AsymmetricPublic) => {}
                    Some(KeyMaterialType::Remote) => {}
                    None => return Err("invalid key material type".into()),
                },
            }
        }
        Ok(result)
    }

    /// Return [`KeysetInfo`] representation of the managed keyset. The result does not
    /// contain any sensitive key material.
    pub fn keyset_info(&self) -> KeysetInfo {
        get_keyset_info(&self.ks)
    }

    /// Consume the `Handle` and return the enclosed [`Keyset`].
    pub(crate) fn into_inner(self) -> Keyset {
        self.ks
    }

    /// Return a copy of the enclosed [`Keyset`]; for internal
    /// use only.
    #[cfg(feature = "insecure")]
    #[cfg_attr(docsrs, doc(cfg(feature = "insecure")))]
    pub(crate) fn clone_keyset(&self) -> Keyset {
        self.ks.clone()
    }

    /// Create a `Handle` from a [`Keyset`].  Implemented as a standalone method rather than
    /// as an `impl` of the `From` trait so visibility can be restricted.
    pub(crate) fn from_keyset(ks: Keyset) -> Result<Self, TinkError> {
        Ok(Handle {
            ks: validate_keyset(ks)?,
        })
    }
}

/// Check that a [`Keyset`] is valid.
fn validate_keyset(ks: Keyset) -> Result<Keyset, TinkError> {
    for k in &ks.key {
        match &k.key_data {
            None if k.status == tink_proto::KeyStatusType::Destroyed as i32 => {}
            None => return Err("invalid keyset".into()),
            Some(kd) => match KeyMaterialType::from_i32(kd.key_material_type) {
                Some(_) => {}
                None => return Err("invalid key material type".into()),
            },
        }
    }
    Ok(ks)
}

/// Extract the public key data corresponding to private key data.
fn public_key_data(priv_key_data: &tink_proto::KeyData) -> Result<tink_proto::KeyData, TinkError> {
    if priv_key_data.key_material_type
        != tink_proto::key_data::KeyMaterialType::AsymmetricPrivate as i32
    {
        return Err("keyset::Handle: keyset contains a non-private key".into());
    }
    let km = crate::registry::get_key_manager(&priv_key_data.type_url)?;

    if !km.supports_private_keys() {
        return Err(format!(
            "keyset::Handle: {} does not belong to a KeyManager that handles private keys",
            priv_key_data.type_url
        )
        .into());
    }
    km.public_key_data(&priv_key_data.value)
}

/// Decrypt a keyset with a master key.
fn decrypt(
    encrypted_keyset: &tink_proto::EncryptedKeyset,
    master_key: Box<dyn crate::Aead>,
    associated_data: &[u8],
) -> Result<Keyset, TinkError> {
    let decrypted = master_key
        .decrypt(&encrypted_keyset.encrypted_keyset, associated_data)
        .map_err(|e| wrap_err("keyset::Handle: decryption failed", e))?;
    Keyset::decode(&decrypted[..]).map_err(|_| TinkError::new("keyset::Handle:: invalid keyset"))
}

/// Encrypt a keyset with a master key.
fn encrypt(
    keyset: &Keyset,
    master_key: Box<dyn crate::Aead>,
    associated_data: &[u8],
) -> Result<tink_proto::EncryptedKeyset, TinkError> {
    let mut serialized_keyset = vec![];
    keyset
        .encode(&mut serialized_keyset)
        .map_err(|e| wrap_err("keyset::Handle: invalid keyset", e))?;
    let encrypted = master_key
        .encrypt(&serialized_keyset, associated_data)
        .map_err(|e| wrap_err("keyset::Handle: encrypted failed", e))?;
    Ok(tink_proto::EncryptedKeyset {
        encrypted_keyset: encrypted,
        keyset_info: Some(get_keyset_info(keyset)),
    })
}

/// Return a [`KeysetInfo`] from a [`Keyset`] protobuf.
fn get_keyset_info(keyset: &Keyset) -> KeysetInfo {
    let n_key = keyset.key.len();
    let mut key_infos = Vec::with_capacity(n_key);
    for key in &keyset.key {
        key_infos.push(get_key_info(key));
    }
    KeysetInfo {
        primary_key_id: keyset.primary_key_id,
        key_info: key_infos,
    }
}

/// Return a [`KeyInfo`](tink_proto::keyset_info::KeyInfo) from a
/// [`Key`](tink_proto::keyset::Key) protobuf.
fn get_key_info(key: &tink_proto::keyset::Key) -> tink_proto::keyset_info::KeyInfo {
    tink_proto::keyset_info::KeyInfo {
        type_url: match &key.key_data {
            Some(kd) => kd.type_url.clone(),
            None => "".to_string(),
        },
        status: key.status,
        key_id: key.key_id,
        output_prefix_type: key.output_prefix_type,
    }
}

impl std::fmt::Debug for Handle {
    /// Return a string representation of the managed keyset.
    /// The result does not contain any sensitive key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", get_keyset_info(&self.ks))
    }
}

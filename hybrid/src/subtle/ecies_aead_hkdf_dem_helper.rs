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

/// Helper trait for DEM (data encapsulation mechanism) of ECIES-AEAD-HKDF.
pub trait EciesAeadHkdfDemHelper {
    /// Size of the DEM-key in bytes.
    fn get_symmetric_key_size(&self) -> usize;

    /// Returns a newly created `Aead` or `DeterministicAead` primitive.
    fn get_aead_or_daead(
        &self,
        symmetric_key_value: &[u8],
    ) -> Result<tink_core::Primitive, tink_core::TinkError>;
}

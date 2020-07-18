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

//! Provides an implementation of MAC using AES-CMAC.

use tink::{utils::wrap_err, Prf, TinkError};

const MIN_CMAC_KEY_SIZE_IN_BYTES: usize = 16;
const RECOMMENDED_CMAC_KEY_SIZE_IN_BYTES: usize = 32;
const MIN_TAG_LENGTH_IN_BYTES: usize = 10;
const MAX_TAG_LENGTH_IN_BYTES: usize = 16;

/// `AesCmac` represents an AES-CMAC struct that implements the [`tink::Mac`] interface.
pub struct AesCmac {
    prf: tink_prf::subtle::AesCmacPrf,
    tag_size: usize,
}

impl AesCmac {
    /// Create a new [`AesCmac`] object that implements the [`tink::Mac`] interface.
    pub fn new(key: &[u8], tag_size: usize) -> Result<AesCmac, TinkError> {
        if key.len() < MIN_CMAC_KEY_SIZE_IN_BYTES {
            return Err("AesCmac: Only 256 bit keys are allowed".into());
        }
        if tag_size < MIN_TAG_LENGTH_IN_BYTES {
            return Err(format!(
                "AesCmac: tag length {} is shorter than minimum tag length {}",
                tag_size, MIN_TAG_LENGTH_IN_BYTES
            )
            .into());
        }
        if tag_size > MAX_TAG_LENGTH_IN_BYTES {
            return Err(format!(
                "AesCmac: tag length {} is longer than maximum tag length {}",
                tag_size, MIN_TAG_LENGTH_IN_BYTES
            )
            .into());
        }
        let prf = tink_prf::subtle::AesCmacPrf::new(key)
            .map_err(|e| wrap_err("AesCmac: could not create AES-CMAC prf", e))?;
        Ok(AesCmac { prf, tag_size })
    }
}

impl tink::Mac for AesCmac {
    fn compute_mac(&self, data: &[u8]) -> Result<Vec<u8>, TinkError> {
        self.prf.compute_prf(data, self.tag_size)
    }
}

/// Validate the parameters for an AES-CMAC against the recommended parameters.
pub fn validate_cmac_params(key_size: usize, tag_size: usize) -> Result<(), TinkError> {
    if key_size != RECOMMENDED_CMAC_KEY_SIZE_IN_BYTES {
        return Err(format!(
            "Only {} sized keys are allowed with Tink's AES-CMAC",
            RECOMMENDED_CMAC_KEY_SIZE_IN_BYTES
        )
        .into());
    }
    if tag_size < MIN_TAG_LENGTH_IN_BYTES {
        return Err("Tag size too short".into());
    }
    if tag_size > MAX_TAG_LENGTH_IN_BYTES {
        return Err("Tag size too long".into());
    }
    Ok(())
}

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

use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // As of prost-build v0.11, there is no longer a fallback version of `protoc` included in
    // prost-build; instead, prost-build needs an externally supplied version of `protoc`.
    //
    // - If `PROTOC` is set, assume that it points to a valid `protoc` and continue with generation.
    // - If `PROTOC` is not set, don't generate (and use the checked-in pre-generated versions of
    //   the code).
    if std::env::var_os("PROTOC").is_none() {
        return Ok(());
    }

    let source_files = [
        "aes_cmac.proto",
        "aes_cmac_prf.proto",
        "aes_ctr.proto",
        "aes_ctr_hmac_aead.proto",
        "aes_ctr_hmac_streaming.proto",
        "aes_eax.proto",
        "aes_gcm.proto",
        "aes_gcm_hkdf_streaming.proto",
        "aes_gcm_siv.proto",
        "aes_siv.proto",
        "chacha20_poly1305.proto",
        "common.proto",
        "config.proto",
        "ecdsa.proto",
        "ecies_aead_hkdf.proto",
        "ed25519.proto",
        "empty.proto",
        "hkdf_prf.proto",
        "hmac.proto",
        "hmac_prf.proto",
        "jwt_hmac.proto",
        "kms_aead.proto",
        "kms_envelope.proto",
        "prf_based_deriver.proto",
        "rsa_ssa_pkcs1.proto",
        "rsa_ssa_pss.proto",
        "tink.proto",
        "xchacha20_poly1305.proto",
    ];
    let proto_path = Path::new("proto").to_path_buf();
    let proto_files: Vec<PathBuf> = source_files.iter().map(|f| proto_path.join(f)).collect();

    // Tell cargo to rerun this build script if any proto file has changed.
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#cargorerun-if-changedpath
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    prost_build::Config::new()
        // Emit generated code into the source directory, so it can be checked in.
        .out_dir("src/codegen")
        .compile_protos(&proto_files, &[PathBuf::from(".")])?;

    // Separate variant with serde-related annotations
    prost_build::Config::new()
        // Emit generated code into the source directory, so it can be checked in.
        .out_dir("src/codegen/serde")
        // Set up serde-json options for Keyset-related messages
        .type_attribute(
            "EncryptedKeyset",
            "#[derive(serde::Deserialize, serde::Serialize)] #[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "Keyset",
            "#[derive(serde::Deserialize, serde::Serialize)] #[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "KeysetInfo",
            "#[derive(serde::Deserialize, serde::Serialize)] #[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "Key",
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "KeyInfo",
            "#[derive(serde::Serialize, serde::Deserialize)] #[serde(rename_all = \"camelCase\")]",
        )
        .type_attribute(
            "KeyData",
            "#[derive(serde::Deserialize, serde::Serialize)] #[serde(rename_all = \"camelCase\")]",
        )
        // Set up serde-json options for fields that need special parsing
        .field_attribute(
            "Key.status",
            "#[serde(with = \"crate::json::key_status_type\")]",
        )
        .field_attribute(
            "KeyInfo.status",
            "#[serde(with = \"crate::json::key_status_type\")]",
        )
        .field_attribute(
            "Key.output_prefix_type",
            "#[serde(with = \"crate::json::output_prefix_type\")]",
        )
        .field_attribute(
            "KeyInfo.output_prefix_type",
            "#[serde(with = \"crate::json::output_prefix_type\")]",
        )
        .field_attribute(
            "KeyData.key_material_type",
            "#[serde(with = \"crate::json::key_material_type\")]",
        )
        .field_attribute("KeyData.value", "#[serde(with = \"crate::json::b64\")]")
        .field_attribute(
            "EncryptedKeyset.encrypted_keyset",
            "#[serde(with = \"crate::json::b64\")]",
        )
        .compile_protos(&proto_files, &[PathBuf::from(".")])?;

    Ok(())
}

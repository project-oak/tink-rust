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

use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source_files = ["testing_api.proto"];
    let proto_path = Path::new("../proto/testing").to_path_buf();
    let proto_files: Vec<PathBuf> = source_files.iter().map(|f| proto_path.join(f)).collect();

    // Tell cargo to rerun this build script if any proto file has changed.
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#cargorerun-if-changedpath
    for proto_file in &proto_files {
        println!("cargo:rerun-if-changed={}", proto_file.display());
    }

    // Emit generated code into the source directory, so it can be checked in.
    tonic_build::configure()
        .out_dir("src/codegen")
        .compile(&proto_files, &[PathBuf::from("..")])?;

    Ok(())
}

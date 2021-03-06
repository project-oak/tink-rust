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

pub mod common;

mod ecdsa_signer_key_manager_test;
mod ecdsa_verifier_key_manager_test;
mod ed25519_signer_key_manager_test;
mod ed25519_verifier_key_manager_test;
mod integration_test;
mod signature_factory_test;
mod signature_key_templates_test;
mod subtle;

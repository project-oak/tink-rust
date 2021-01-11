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

//! Command line utility for keyset management.

use std::{
    cell::RefCell,
    fs::{File, OpenOptions},
    path::PathBuf,
    rc::Rc,
    str::FromStr,
};
use structopt::StructOpt;
use tink_core::TinkError;
use tink_proto::{KeyStatusType, OutputPrefixType};

/// File format for a keyset.
#[derive(Clone, StructOpt)]
enum KeysetFormat {
    Json,
    Binary,
}

impl FromStr for KeysetFormat {
    type Err = String;
    fn from_str(variant: &str) -> Result<Self, Self::Err> {
        match variant.to_lowercase().as_ref() {
            "json" => Ok(KeysetFormat::Json),
            "binary" => Ok(KeysetFormat::Binary),
            _ => Err(format!("Failed to parse format {}", variant)),
        }
    }
}

/// Wrapper for [`std::io::Read`] to allow the [`FromStr`] trait to be implemented.
#[derive(Clone)]
struct KeysetReader(Rc<RefCell<dyn std::io::Read>>);

impl std::io::Read for KeysetReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().read(buf)
    }
}

impl FromStr for KeysetReader {
    type Err = std::io::Error;
    fn from_str(filename: &str) -> Result<Self, Self::Err> {
        if filename.is_empty() {
            Ok(KeysetReader(Rc::new(RefCell::new(std::io::stdin()))))
        } else {
            Ok(KeysetReader(Rc::new(RefCell::new(File::open(filename)?))))
        }
    }
}

/// Wrapper for [`std::io::Write`] to allow the [`FromStr`] trait to be implemented.
#[derive(Clone)]
struct KeysetWriter(Rc<RefCell<dyn std::io::Write>>);

impl std::io::Write for KeysetWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.borrow_mut().flush()
    }
}

impl FromStr for KeysetWriter {
    type Err = std::io::Error;
    fn from_str(filename: &str) -> Result<Self, Self::Err> {
        if filename.is_empty() {
            Ok(KeysetWriter(Rc::new(RefCell::new(std::io::stdout()))))
        } else {
            Ok(KeysetWriter(Rc::new(RefCell::new(
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(filename)?,
            ))))
        }
    }
}

/// Wrapper for [`tink_proto::KeyTemplate`] to allow the [`FromStr`] trait to be implemented.
#[derive(Clone)]
struct KeyTemplate(tink_proto::KeyTemplate);

impl FromStr for KeyTemplate {
    type Err = String;
    fn from_str(template_name: &str) -> Result<Self, Self::Err> {
        if let Some(generator) = tink_core::registry::get_template_generator(template_name) {
            Ok(KeyTemplate(generator()))
        } else {
            Err(format!("Unknown key template name {}", template_name))
        }
    }
}

/// Common args for key wrapping/unwrapping.
#[derive(Clone, StructOpt)]
struct WrappingOptions {
    #[structopt(
        long,
        help = "The keyset might be encrypted with a master key in Google Cloud KMS or AWS KMS. This option specifies the URI of the master key. If missing, read or write cleartext keysets. Google Cloud KMS keys have this format: gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*. AWS KMS keys have this format: aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>.",
        default_value = ""
    )]
    master_key_uri: String,

    #[structopt(
        long,
        help = "If --master-key-uri is specified, this option specifies the credentials file path. Must exist if specified. If missing, use default credentials. Google Cloud credentials are service account JSON files. AWS credentials are properties files with the AWS access key ID is expected to be in the accessKey property and the AWS secret key is expected to be in the secretKey property.",
        default_value = ""
    )]
    credential_path: String,
}

/// Common args for commands that read from file.
#[derive(Clone, StructOpt)]
struct InOptions {
    #[structopt(
        long = "in",
        help = "The input filename, must exist, to read the keyset from or standard input if not specified",
        default_value = ""
    )]
    in_file: KeysetReader,

    #[structopt(
        long,
        help = "The input format: json or binary (case-insensitive).",
        default_value = "json"
    )]
    in_format: KeysetFormat,

    #[structopt(flatten)]
    wrap_opts: WrappingOptions,
}

/// Common args for commands that write to file and need credential.
#[derive(Clone, StructOpt)]
struct OutOptions {
    #[structopt(
        long = "out",
        help = "The output filename, must not exist, to write the keyset to or standard output if not specified",
        default_value = ""
    )]
    out_file: KeysetWriter,

    #[structopt(
        long,
        help = "The output format: json or binary (case-insensitive).",
        default_value = "json"
    )]
    out_format: KeysetFormat,
}

/// Options for create-public-keyset command.
#[derive(Clone, StructOpt)]
struct PublicKeysetOptions {
    #[structopt(flatten)]
    in_opts: InOptions,

    #[structopt(flatten)]
    out_opts: OutOptions,
}

/// Options for add-key or rotate-keyset command.
#[derive(Clone, StructOpt)]
struct AddRotateOptions {
    #[structopt(flatten)]
    in_opts: InOptions,

    #[structopt(flatten)]
    out_opts: OutOptions,

    #[structopt(
        long,
        help = "The key template name. Run list-key-templates to get supported names."
    )]
    key_template: KeyTemplate,
}

/// Options for convert-keyset command.
#[derive(Clone, StructOpt)]
struct ConvertKeysetOptions {
    #[structopt(flatten)]
    in_opts: InOptions,

    #[structopt(flatten)]
    out_opts: OutOptions,

    #[structopt(long, help = "The new master key URI", default_value = "")]
    new_master_key_uri: String,

    #[structopt(
        long,
        help = "The new master key credential, must exist if specified",
        default_value = ""
    )]
    new_credential: String,
}

/// Options for command to create a keyset.
#[derive(Clone, StructOpt)]
struct CreateKeysetOptions {
    #[structopt(flatten)]
    wrap_opts: WrappingOptions,

    #[structopt(flatten)]
    out_opts: OutOptions,

    #[structopt(
        long,
        help = "The key template name. Run list-key-templates to get supported names."
    )]
    key_template: KeyTemplate,
}

/// Options for commands that take a key id option, e.g., enable, disable or destroy.
#[derive(Clone, StructOpt)]
struct KeyIdOptions {
    #[structopt(flatten)]
    in_opts: InOptions,

    #[structopt(flatten)]
    out_opts: OutOptions,

    #[structopt(long, help = "The target key id")]
    key_id: tink_core::KeyId,
}

/// Top-level command to perform.
#[derive(Clone, StructOpt)]
enum Command {
    #[structopt(about = "Generate and add a new key to a keyset")]
    AddKey(AddRotateOptions),
    #[structopt(about = "Change format, encrypt or decrypt a keyset")]
    ConvertKeyset(ConvertKeysetOptions),
    #[structopt(about = "Create a new keyset")]
    CreateKeyset(CreateKeysetOptions),
    #[structopt(about = "Create a public keyset from an existing private keyset")]
    CreatePublicKeyset(PublicKeysetOptions),
    #[structopt(about = "Delete a key with some key id in a keyset")]
    DeleteKey(KeyIdOptions),
    #[structopt(about = "Destroy a key with some key id in a keyset")]
    DestroyKey(KeyIdOptions),
    #[structopt(about = "Disable a key with some key id in a keyset")]
    DisableKey(KeyIdOptions),
    #[structopt(about = "Enable a key with some key id in a keyset")]
    EnableKey(KeyIdOptions),
    #[structopt(about = "List keys in a keyset")]
    ListKeyset(InOptions),
    #[structopt(about = "List available key template names")]
    ListKeyTemplates,
    #[structopt(
        about = "Generate, add a new key to an existing keyset and set the new key as the primary key"
    )]
    RotateKeyset(AddRotateOptions),
    #[structopt(about = "Promote a specified key to primary")]
    PromoteKey(KeyIdOptions),
}

fn main() {
    tink_aead::init();
    tink_daead::init();
    tink_mac::init();
    tink_prf::init();
    tink_signature::init();
    tink_streaming_aead::init();

    match Command::from_args() {
        Command::AddKey(opts) => add_key(opts),
        Command::ConvertKeyset(opts) => convert_keyset(opts),
        Command::CreateKeyset(opts) => create_keyset(opts),
        Command::CreatePublicKeyset(opts) => create_public_keyset(opts),
        Command::DeleteKey(opts) => delete_key(opts),
        Command::DestroyKey(opts) => destroy_key(opts),
        Command::DisableKey(opts) => disable_key(opts),
        Command::EnableKey(opts) => enable_key(opts),
        Command::ListKeyset(opts) => list_keyset(opts),
        Command::ListKeyTemplates => list_key_templates(),
        Command::RotateKeyset(opts) => rotate_keyset(opts),
        Command::PromoteKey(opts) => promote_key(opts),
    }
}

/// Generate and add a new key to a keyset
fn add_key(opts: AddRotateOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    let template = opts.key_template.0;
    mgr.add(&template, false).expect("Invalid key template");
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Change format, encrypt or decrypt a keyset
fn convert_keyset(opts: ConvertKeysetOptions) {
    let kh = read_keyset(opts.in_opts);

    let new_wrap_opts = WrappingOptions {
        master_key_uri: opts.new_master_key_uri,
        credential_path: opts.new_credential,
    };
    write_keyset(opts.out_opts, new_wrap_opts, kh);
}

/// Create a new keyset
fn create_keyset(opts: CreateKeysetOptions) {
    let template = opts.key_template.0;
    let kh = tink_core::keyset::Handle::new(&template).expect("Invalid key template");
    write_keyset(opts.out_opts, opts.wrap_opts, kh);
}

/// Create a public keyset from an existing private keyset
fn create_public_keyset(opts: PublicKeysetOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let kh = read_keyset(opts.in_opts);
    let pub_kh = kh.public().expect("Failed to convert keyset");
    write_keyset(opts.out_opts, wrap_opts, pub_kh);
}

/// Delete a key with some key id in a keyset
fn delete_key(opts: KeyIdOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    mgr.delete(opts.key_id).unwrap();
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Destroy a key with some key id in a keyset
fn destroy_key(opts: KeyIdOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    mgr.destroy(opts.key_id).unwrap();
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Disable a key with some key id in a keyset
fn disable_key(opts: KeyIdOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    mgr.disable(opts.key_id).unwrap();
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Enable a key with some key id in a keyset
fn enable_key(opts: KeyIdOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    mgr.enable(opts.key_id).unwrap();
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// List keys in a keyset
fn list_keyset(opts: InOptions) {
    let kh = read_keyset(opts);
    let info = kh.keyset_info();

    // prost does not support text format conversion for protobuf messages,
    // so manually build the text representaion of the keyset.
    println!("primary_key_id: {}", info.primary_key_id);
    for key in &info.key_info {
        println!("key_info {{");
        println!("  type_url: \"{}\"", key.type_url);
        println!(
            "  status: {}",
            match KeyStatusType::from_i32(key.status) {
                Some(KeyStatusType::Enabled) => "ENABLED",
                Some(KeyStatusType::Disabled) => "DISABLED",
                Some(KeyStatusType::Destroyed) => "DESTROYED",
                _ => "UNKNOWN",
            }
        );
        println!("  key_id: {}", key.key_id);
        println!(
            "  output_prefix_type: {}",
            match OutputPrefixType::from_i32(key.output_prefix_type) {
                Some(OutputPrefixType::Tink) => "TINK",
                Some(OutputPrefixType::Legacy) => "LEGACY",
                Some(OutputPrefixType::Raw) => "RAW",
                Some(OutputPrefixType::Crunchy) => "CRUNCHY",
                _ => "UNKNOWN",
            }
        );
        println!("}}");
    }
    println!();
}

/// List available key template names
fn list_key_templates() {
    println!("The following key templates are supported:");
    for name in tink_core::registry::template_names() {
        println!("{}", name);
    }
}

/// Generate, add a new key to an existing keyset and set the new key as the primary key
fn rotate_keyset(opts: AddRotateOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    let template = opts.key_template.0;
    mgr.rotate(&template).expect("Invalid key template");
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Promote a specified key to primary
fn promote_key(opts: KeyIdOptions) {
    let wrap_opts = opts.in_opts.wrap_opts.clone();
    let mut mgr = get_manager(opts.in_opts);
    mgr.set_primary(opts.key_id).unwrap();
    put_manager(opts.out_opts, wrap_opts, mgr);
}

/// Return a [`tink_core::keyset::Manager`] for a keyset identified by [`InOptions`]
fn get_manager(opts: InOptions) -> tink_core::keyset::Manager {
    let kh = read_keyset(opts);
    tink_core::keyset::Manager::new_from_handle(kh)
}

/// Write out the keyset identified by a [`tink_core::keyset::Manager`] with the specified output
/// options.
fn put_manager(opts: OutOptions, wrap_opts: WrappingOptions, mgr: tink_core::keyset::Manager) {
    let new_kh = mgr.handle().expect("Failed to create new handle");
    write_keyset(opts, wrap_opts, new_kh);
}

/// Return a [`tink_core::keyset::Handle`] for a keyset identified by [`InOptions`]
fn read_keyset(opts: InOptions) -> tink_core::keyset::Handle {
    match opts.in_format {
        KeysetFormat::Json => read_keyset_with(
            tink_core::keyset::JsonReader::new(opts.in_file),
            opts.wrap_opts,
        ),
        KeysetFormat::Binary => read_keyset_with(
            tink_core::keyset::BinaryReader::new(opts.in_file),
            opts.wrap_opts,
        ),
    }
}

/// Return a [`tink_core::keyset::Handle`] for a keyset read in via `reader`.
fn read_keyset_with<T: tink_core::keyset::Reader>(
    mut reader: T,
    wrap_opts: WrappingOptions,
) -> tink_core::keyset::Handle {
    if wrap_opts.master_key_uri.is_empty() {
        tink_core::keyset::insecure::read(&mut reader).expect("Read failure")
    } else {
        let kms_client = get_kms_client(&wrap_opts).expect("No KMS client found");
        let aead = kms_client
            .get_aead(&wrap_opts.master_key_uri)
            .expect("Failed to build KMS AEAD");
        tink_core::keyset::Handle::read(&mut reader, aead).expect("Read failure")
    }
}

/// Write out the keyset identified by a [`tink_core::keyset::Handle`] with the specified output
/// options.
fn write_keyset(opts: OutOptions, wrap_opts: WrappingOptions, kh: tink_core::keyset::Handle) {
    match opts.out_format {
        KeysetFormat::Json => write_keyset_with(
            tink_core::keyset::JsonWriter::new(opts.out_file),
            wrap_opts,
            kh,
        ),
        KeysetFormat::Binary => write_keyset_with(
            tink_core::keyset::BinaryWriter::new(opts.out_file),
            wrap_opts,
            kh,
        ),
    }
}

/// Write out the keyset identified by a [`tink_core::keyset::Handle`] using the given `writer`.
fn write_keyset_with<T: tink_core::keyset::Writer>(
    mut writer: T,
    wrap_opts: WrappingOptions,
    kh: tink_core::keyset::Handle,
) {
    if wrap_opts.master_key_uri.is_empty() {
        tink_core::keyset::insecure::write(&kh, &mut writer).expect("Write failure")
    } else {
        let kms_client = get_kms_client(&wrap_opts).expect("No KMS client found");
        let aead = kms_client
            .get_aead(&wrap_opts.master_key_uri)
            .expect("Failed to build KMS AEAD");
        kh.write(&mut writer, aead).expect("Write failure")
    }
}

/// Build and register a KMS Client.
fn get_kms_client(
    wrap_opts: &WrappingOptions,
) -> Result<std::sync::Arc<dyn tink_core::registry::KmsClient>, TinkError> {
    if wrap_opts
        .master_key_uri
        .starts_with(tink_awskms::AWS_PREFIX)
    {
        let g = if wrap_opts.credential_path.is_empty() {
            tink_awskms::AwsClient::new(&wrap_opts.master_key_uri)?
        } else {
            tink_awskms::AwsClient::new_with_credentials(
                &wrap_opts.master_key_uri,
                &PathBuf::from(&wrap_opts.credential_path),
            )?
        };
        tink_core::registry::register_kms_client(g);
        tink_core::registry::get_kms_client(&wrap_opts.master_key_uri)
    } else if wrap_opts
        .master_key_uri
        .starts_with(tink_gcpkms::GCP_PREFIX)
    {
        let g = if wrap_opts.credential_path.is_empty() {
            tink_gcpkms::GcpClient::new(&wrap_opts.master_key_uri)?
        } else {
            tink_gcpkms::GcpClient::new_with_credentials(
                &wrap_opts.master_key_uri,
                &PathBuf::from(&wrap_opts.credential_path),
            )?
        };
        tink_core::registry::register_kms_client(g);
        tink_core::registry::get_kms_client(&wrap_opts.master_key_uri)
    } else {
        Err("Unrecognized key URI".into())
    }
}

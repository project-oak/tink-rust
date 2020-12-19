# Tink for Rust HOW-TO

This document contains instructions and Rust code snippets for common tasks in
[Tink](https://github.com/project-oak/tink-rust).

- [Setup Instructions](#setup-instructions)
- [Rustdoc](#rustdoc)
- [Obtaining and Using Primitives](#obtaining-and-using-primitives)
    - [AEAD](#aead)
    - [MAC](#mac)
    - [Deterministic AEAD](#deterministic-aead)
    - [Signature](#signature)
    - [Symmetric Key Encryption of Streaming Data](#symmetric-key-encryption-of-streaming-data)
- [Key Management](#key-management)
    - [Generating New Keys and Keysets](#generating-new-keys-and-keysets)
    - [Storing and Loading Existing Keysets](#storing-and-loading-existing-keysets)

## Setup Instructions

To install the Tink-Rust repository locally run:

```sh
git clone https://github.com/project-oak/tink-rust
cd tink-rust
git submodule update # get local copy of Wycheproof test vectors
```

to run all the tests locally:

```sh
cargo test --all
```

TODO(#32): replace with crates.io instructions

## Rustdoc

Documentation for the Tink Rust API can be found [here](https://project-oak.github.io/tink-rust/).

## Obtaining and Using Primitives

[_Primitives_](https://github.com/google/tink/blob/v1.5.0/docs/PRIMITIVES.md) represent cryptographic operations offered
by Tink, hence they form the core of Tink API. A primitive is just a trait that specifies what operations are offered by
the primitive. A primitive can have multiple implementations, and you choose a desired implementation by using a key of
corresponding type (see the [this
section](https://github.com/google/tink/blob/v1.5.0/docs/KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

A list of primitives and their implementations currently supported by Tink in
Rust can be found [here](PRIMITIVES.md#rust).

### AEAD

AEAD encryption assures the confidentiality and authenticity of the data. This
primitive is CPA secure.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/aead/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_aead::init();
    let kh = tink::keyset::Handle::new(&tink_aead::aes256_gcm_key_template()).unwrap();
    let a = tink_aead::new(&kh).unwrap();

    let pt = b"this data needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct = a.encrypt(pt, aad).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&ct));

    let pt2 = a.decrypt(&ct, aad).unwrap();
    assert_eq!(&pt[..], pt2);
}
```
<!-- prettier-ignore-end -->

### MAC

MAC computes a tag for a given message that can be used to authenticate a
message. MAC protects data integrity as well as provides for authenticity of the
message.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/mac/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_mac::init();
    let kh = tink::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template()).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let pt = b"this data needs to be MACed";
    let mac = m.compute_mac(pt).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&mac));

    assert!(m.verify_mac(&mac, b"this data needs to be MACed").is_ok());
    println!("MAC verification succeeded.");
}
```
<!-- prettier-ignore-end -->

### Deterministic AEAD

Unlike AEAD, implementations of this interface are not semantically secure,
because encrypting the same plaintext always yields the same ciphertext.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/daead/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_daead::init();
    let kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();
    let d = tink_daead::new(&kh).unwrap();

    let pt = b"this data needs to be encrypted";
    let ad = b"additional data";
    let ct1 = d.encrypt_deterministically(pt, ad).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&ct1));

    let ct2 = d.encrypt_deterministically(pt, ad).unwrap();
    assert_eq!(ct1, ct2, "cipher texts are not equal");
    println!("Cipher texts are equal.");

    let pt2 = d.decrypt_deterministically(&ct1, ad).unwrap();
    assert_eq!(&pt[..], pt2);
}
```
<!-- prettier-ignore-end -->

### Signature

To sign data using Tink you can use ECDSA (with P-256) or ED25519 key templates.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/signature/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();

    let pt = b"this data needs to be signed";
    let a = s.sign(pt).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&a));

    let pubkh = kh.public().unwrap();
    let v = tink_signature::new_verifier(&pubkh).unwrap();
    assert!(v.verify(&a, b"this data needs to be signed").is_ok());
    println!("Signature verified.");
}
```
<!-- prettier-ignore-end -->

### Symmetric Key Encryption of Streaming Data

You can obtain and use a
[Streaming AEAD](PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data)
(Streaming Authenticated Encryption with Associated Data) primitive to encrypt
or decrypt data streams:

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/streaming/src/main.rs Rust /.*streaming_aead::init/ /^}/)
```Rust
    tink_streaming_aead::init();

    // Generate fresh key material.
    let kh = tink::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())
        .unwrap();

    // Get the primitive that uses the key material.
    let a = tink_streaming_aead::new(&kh).unwrap();

    // Use the primitive to create a [`std::io::Write`] object that writes ciphertext
    // to a file.
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct_file = std::fs::File::create(ct_filename.clone()).unwrap();
    let mut w = a
        .new_encrypting_writer(Box::new(ct_file), &aad[..])
        .unwrap();

    // Write data to the encrypting-writer, in chunks to simulate streaming.
    let mut offset = 0;
    while offset < PT.len() {
        let end = std::cmp::min(PT.len(), offset + CHUNK_SIZE);
        let written = w.write(&PT[offset..end]).unwrap();
        offset += written;
        // Can flush but it does nothing.
        w.flush().unwrap();
    }
    // Complete the encryption (process any remaining buffered plaintext).
    w.close().unwrap();

    // For the other direction, given a [`std::io::Read`] object that reads ciphertext,
    // use the primitive to create a [`std::io::Read`] object that emits the corresponding
    // plaintext.
    let ct_file = std::fs::File::open(ct_filename).unwrap();
    let mut r = a
        .new_decrypting_reader(Box::new(ct_file), &aad[..])
        .unwrap();

    // Read data from the decrypting-reader, in chunks to simulate streaming.
    let mut recovered = vec![];
    loop {
        let mut chunk = vec![0; CHUNK_SIZE];
        let len = r.read(&mut chunk).unwrap();
        if len == 0 {
            break;
        }
        recovered.extend_from_slice(&chunk[..len]);
    }

    assert_eq!(recovered, PT);
}
```
<!-- prettier-ignore-end -->

## Key Management

### Generating New Keys and Keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets. `Keyset`s are just sets of keys
with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but user code should
normally use a **keyset handle**. This is a wrapper that enforces restrictions
on access to the underlying keyset, to prevent accidental leakage of the
sensitive key material.

Generating a new key for a keyset involves the use of a `KeyTemplate`, which
describes the parameters of the key being generated.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/keygen/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_daead::init();

    // Other key templates can also be used, if the relevant primitive crate
    // is initialized.
    let kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();

    println!("{:?}", kh);
}
```
<!-- prettier-ignore-end -->

Tink provides a **keyset manager** object for operations on keysets that contain
multiple keys, each identified by a key ID.  This manager allows keys to be:

- generated (based on key templates)
- set to primary (the primary key is the one used for encryption operations;
  all of the available keys are tried out for decryption operations)
- enabled/disabled
- destroyed (where the key material is removed but the key ID remains)
- deleted (where the key material is removed along with the key ID).

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/keymgr/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_aead::init();

    // Create a keyset with a single key in it, and encrypt something.
    let kh = tink::keyset::Handle::new(&tink_aead::aes128_gcm_key_template()).unwrap();
    let cipher = tink_aead::new(&kh).unwrap();
    let ct = cipher.encrypt(b"data", b"aad").unwrap();

    // Move ownership of the `Handle` into a `keyset::Manager`.
    let mut km = tink::keyset::Manager::new_from_handle(kh);

    // Rotate in a new primary key, and add an additional secondary key.
    let key_id_a = km.rotate(&tink_aead::aes256_gcm_key_template()).unwrap();
    let key_id_b = km
        .add(
            &tink_aead::aes256_gcm_key_template(),
            /* primary = */ false,
        )
        .unwrap();

    // Create a new keyset handle for the current state of the managed keyset.
    let kh2 = km.handle().unwrap();
    println!("{:?}", kh2); // debug output does not include key material

    // The original key is still in the keyset, and so can decrypt.
    let cipher2 = tink_aead::new(&kh2).unwrap();
    let pt = cipher2.decrypt(&ct, b"aad").unwrap();
    assert_eq!(pt, b"data");

    // Set the third key to primary and disable the previous primary key.
    km.set_primary(key_id_b).unwrap();
    km.disable(key_id_a).unwrap();
    let kh3 = km.handle().unwrap();
    println!("{:?}", kh3);
}
```
<!-- prettier-ignore-end -->

#### Key Templates

Key templates are available for different primitives as follows.

Key Template Type  | Key Template
------------------ | ------------
AEAD               | `tink_aead::aes128_ctr_hmac_sha256_key_template()`
AEAD               | `tink_aead::aes128_gcm_key_template()`
AEAD               | `tink_aead::aes128_gcm_siv_key_template()`
AEAD               | `tink_aead::aes256_ctr_hmac_sha256_key_template()`
AEAD               | `tink_aead::aes256_gcm_key_template()`
AEAD               | `tink_aead::aes256_gcm_siv_key_template()`
AEAD               | `tink_aead::cha_cha20_poly1305_key_template()`
AEAD               | `tink_aead::x_cha_cha20_poly1305_key_template()`
DAEAD              | `tink_daead::aes_siv_key_template()`
MAC                | `tink_mac::hmac_sha256_tag128_key_template()`
MAC                | `tink_mac::hmac_sha256_tag256_key_template()`
MAC                | `tink_mac::hmac_sha512_tag256_key_template()`
MAC                | `tink_mac::hmac_sha512_tag512_key_template()`
Signature          | `tink_signature::ecdsa_p256_key_template()`
Signature          | `tink_signature::ed25519_key_template()`
Streaming AEAD     | `tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes128_gcm_hkdf_1mb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes256_gcm_hkdf_4kb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes256_gcm_hkdf_1mb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes128_ctr_hmac_sha256_segment_4kb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes128_ctr_hmac_sha256_segment_1mb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes256_ctr_hmac_sha256_segment_4kb_key_template`
Streaming AEAD     | `tink_streaming_aead::aes256_ctr_hmac_sha256_segment_1mb_key_template`

To avoid accidental leakage of sensitive key material, one should avoid mixing
keyset generation and usage in code. To support the separation of these
activities Tink-Rust provides a command-line tool, `rinkey` that is equivalent
to the upstream [tinkey](
https://github.com/google/tink/blob/v1.5.0/docs/TINKEY.md) tool, which can be
used for common key management tasks.

### Storing and Loading Existing Keysets

After generating key material, you might want to persist it to a storage system.
Tink supports persisting the keys after encryption to any `std::io::Write` and
`std::io::Read` implementations.

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/kms/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_aead::init();

    // Generate a new key.
    let kh1 = tink::keyset::Handle::new(&tink_aead::aes256_gcm_key_template()).unwrap();

    // Set up the main key-encryption key at a KMS. This is an AEAD which will generate a new
    // data-encryption key (DEK) for each encryption operation; the DEK is included in the
    // ciphertext emitted from the encryption operation, in encrypted form (encrypted by the
    // KMS main key).
    let kms_client =
        tink_awskms::AwsClient::new_with_credentials(KEY_URI, &PathBuf::from(CRED_INI_FILE))
            .unwrap();
    let backend = kms_client.get_aead(KEY_URI).unwrap();
    let main_key = Box::new(tink_aead::KmsEnvelopeAead::new(
        tink_aead::aes256_gcm_key_template(),
        backend,
    ));

    // The `keyset::Reader` and `keyset::Writer` traits allow for reading/writing a keyset to
    // some kind of store; this particular implementation just holds the keyset in memory.
    let mut mem_keyset = tink::keyset::MemReaderWriter::default();

    // The `Handle::write` method encrypts the keyset that is associated with the handle, using the
    // given AEAD (`main_key`), and then writes the encrypted keyset to the `keyset::Writer`
    // implementation (`mem_keyset`).  We recommend you encrypt the keyset handle before
    // persisting it.
    kh1.write(&mut mem_keyset, main_key.box_clone()).unwrap();
    println!("Encrypted keyset: {:?}", mem_keyset.encrypted_keyset);

    // The `Handle::read` method reads the encrypted keyset back from the `keyset::Reader`
    // implementation and decrypts it using the AEAD used to encrypt it (`main_key`), giving a
    // handle to the recovered keyset.
    let kh2 = tink::keyset::Handle::read(&mut mem_keyset, main_key).unwrap();

    assert_eq!(
        insecure::keyset_material(&kh1),
        insecure::keyset_material(&kh2)
    );
    println!("Key handles are equal.");
}
```
<!-- prettier-ignore-end -->

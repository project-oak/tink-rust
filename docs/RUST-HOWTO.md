# Tink for Rust HOW-TO

This document contains instructions and Rust code snippets for common tasks in
[Tink](https://github.com/project-oak/tink-rust).

## Setup Instructions

To install the Tink-Rust repository locally run:

```sh
git clone https://github.com/project-oak/tink-rust
cd tink-rust
```

to run all the tests locally:

```sh
cargo test --all
```

TODO: replace with crates.io instructions

## Rustdoc

Documentation for the Tink API can be found [here](https://project-oak.github.io/tink-rust/).

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

## Key management

### Generating new keys and keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets. Keysets are just sets of keys
with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but you can work with
keysets via a wrapper called keyset handle. You can generate a new keyset and
obtain its handle using a KeyTemplate. KeysetHandle objects enforce certain
restrictions that prevent accidental leakage of the sensitive key material.

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

Key templates are available for MAC and DAEAD encryption.

Key Template Type  | Key Template
------------------ | ------------
AEAD               | `tink_aead::aes128_ctr_hmac_sha256_key_template()`
AEAD               | `tink_aead::aes128_gcm_key_template()`
AEAD               | `tink_aead::aes256_ctr_hmac_sha256_key_template()`
AEAD               | `tink_aead::aes256_gcm_key_template()`
AEAD               | `tink_aead::cha_cha20_poly1305_key_template()`
AEAD               | `tink_aead::x_cha_cha20_poly1305_key_template()`
DAEAD              | `tink_daead::aes_siv_key_template()`
MAC                | `tink_mac::hmac_sha256_tag128_key_template()`
MAC                | `tink_mac::hmac_sha256_tag256_key_template()`
MAC                | `tink_mac::hmac_sha512_tag256_key_template()`
MAC                | `tink_mac::hmac_sha512_tag512_key_template()`
Signature          | `tink_signature::ecdsa_p256_key_template()`
Signature          | `tink_signature::ed25519_key_template()`

To avoid accidental leakage of sensitive key material, one should avoid mixing keyset generation and usage in code. To
support the separation of these activities Tink-Rust provides a command-line tool, `rinkey` that is equivalent to the
upstream [tinkey]( https://github.com/google/tink/blob/v1.5.0/docs/TINKEY.md) tool,which can be used for common key
management tasks.

### Storing and loading existing keysets

After generating key material, you might want to persist it to a storage system.
Tink supports persisting the keys after encryption to any `std::io::Write` and
`std::io::Read` implementations.

TODO: KMS example here
```Rust
```

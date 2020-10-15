# Tink for Rust HOW-TO

This document contains instructions and Rust code snippets for common tasks in
[Tink](https://github.com/tink-crypto/tink-rust).

## Setup instructions

TODO: confirm official location

To install Tink locally run:

```sh
git clone https://github.com/tink-crypto/tink-rust
cd tink-rust
```

to run all the tests locally:

```sh
cargo test --all
```

## Rustdoc

Documentation for the Tink API can be found
[here](https://tink-crypto.github.io/tink-rust/).

## Obtaining and using primitives

[_Primitives_](PRIMITIVES.md) represent cryptographic operations offered by
Tink, hence they form the core of Tink API. A primitive is just a trait
that specifies what operations are offered by the primitive. A primitive can
have multiple implementations, and you choose a desired implementation by
using a key of corresponding type (see the [this
section](KEY-MANAGEMENT.md#key-keyset-and-keysethandle) for details).

A list of primitives and their implementations currently supported by Tink in
Rust can be found [here](PRIMITIVES.md#rust).

### AEAD

AEAD encryption assures the confidentiality and authenticity of the data. This
primitive is CPA secure.

```Rust
fn main() {
    tink_aead::init();
    let kh = tink::keyset::Handle::new(&tink_aead::aes256_gcm_key_template()).unwrap();
    let a = tink_aead::new(&kh).unwrap();
    let ct = a
        .encrypt(
            b"this data needs to be encrypted",
            b"this data needs to be authenticated, but not encrypted",
        )
        .unwrap();
    let pt = a
        .decrypt(
            &ct,
            b"this data needs to be authenticated, but not encrypted",
        )
        .unwrap();

    assert_eq!(b"this data needs to be encrypted".to_vec(), pt);
}
```

### MAC

MAC computes a tag for a given message that can be used to authenticate a
message. MAC protects data integrity as well as provides for authenticity of the
message.

```Rust
fn main() {
    tink_mac::init();
    let kh = tink::keyset::Handle::new(tink_mac::hmac_sha256_tag256_key_template()).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let mac = m.compute_mac(b"this data needs to be MACed").unwrap();

    assert!(m.verify_mac(mac, b"this data needs to be MACed").is_ok());

    // Output:
    println!("MAC verification succeeded.");
}
```

### Deterministic AEAD

Unlike AEAD, implementations of this interface are not semantically secure,
because encrypting the same plaintext always yields the same ciphertext.

```Rust
fn main() {
    tink_daead::init();
    let kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();
    let d = tink_daead::new(&kh).unwrap();
    let pt = b"this data needs to be encrypted";
    let ad = b"additional data";
    let ct1 = d.encrypt_deterministically(pt, ad).unwrap();
    let ct2 = d.encrypt_deterministically(pt, ad).unwrap();

    assert_eq!(ct1, ct2, "cipher texts are not equal");
    println!("Cipher texts are equal.");

    let pt2 = d.decrypt_deterministically(&ct1, ad).unwrap();

    println!("Plain text: {}", String::from_utf8_lossy(pt));
}
```

### Signature

To sign data using Tink you can use ECDSA or ED25519 key templates.

```Rust
fn example_ecdsa() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
    let s = tink_signature::new_signer(&kh).unwrap();

    let a = s.sign(b"this data needs to be signed").unwrap();

    let pubkh = kh.public().unwrap();
    let v = tink_signature::new_verifier(&pubkh).unwrap();
    assert!(v.verify(&a, b"this data needs to be signed").is_ok());
}
```

## Key management

### Generating new keys and keysets

To take advantage of key rotation and other key management features, you usually
do not work with single keys, but with keysets. Keysets are just sets of keys
with some additional parameters and metadata.

Internally Tink stores keysets as Protocol Buffers, but you can work with
keysets via a wrapper called keyset handle. You can generate a new keyset and
obtain its handle using a KeyTemplate. KeysetHandle objects enforce certain
restrictions that prevent accidental leakage of the sensitive key material.

```Rust
fn main() {
    tink_daead::init();
    // Other key templates can also be used, if the relevant primitive crate
    // is initialized.
    let kh = tink::keyset::Handle::new(&tink_daead::aes_siv_key_template()).unwrap();

    println!("{:?}", kh);
}
```

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

To avoid accidental leakage of sensitive key material, one should avoid mixing
keyset generation and usage in code. To support the separation of these
activities Tink provides a command-line tool, [Tinkey](TINKEY.md), which can be
used for common key management tasks.

### Storing and loading existing keysets

After generating key material, you might want to persist it to a storage system.
Tink supports persisting the keys after encryption to any `std::io::Write` and
`std::io::Read`` implementations.

TODO: KMS example here
```Rust
```

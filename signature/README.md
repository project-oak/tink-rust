# Tink-Rust: Digital Signatures

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-signature)
![MSRV](https://img.shields.io/badge/rustc-1.49+-yellow?style=for-the-badge)

This crate provides digital signature functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#digital-signatures).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/signature/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_signature::init();
    // Other key templates can also be used.
    let kh = tink_core::keyset::Handle::new(&tink_signature::ecdsa_p256_key_template()).unwrap();
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

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

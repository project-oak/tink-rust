# Tink-Rust: Authenticated Encryption with Additional Data

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-aead)
![MSRV](https://img.shields.io/badge/rustc-1.71.1+-yellow?style=for-the-badge)

This crate provides authenticated encryption with additional data (AEAD) functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#authenticated-encryption-with-associated-data).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/aead/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() -> Result<(), Box<dyn Error>> {
    tink_aead::init();
    let kh = tink_core::keyset::Handle::new(&tink_aead::aes256_gcm_key_template())?;
    let a = tink_aead::new(&kh)?;

    let pt = b"this data needs to be encrypted";
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct = a.encrypt(pt, aad)?;
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&ct));

    let pt2 = a.decrypt(&ct, aad)?;
    assert_eq!(&pt[..], pt2);
    Ok(())
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Known Issues

- Before version 0.2.4, AES-CTR-HMAC-AEAD keys and the
  [`subtle::EncryptThenAuthenticate`](https://docs.rs/tink-aead/latest/tink_aead/subtle/struct.EncryptThenAuthenticate.html)
  implementation may be vulnerable to chosen-ciphertext attacks. An attacker can generate ciphertexts that bypass the
  HMAC verification if and only if all of the following conditions are true:
    - Tink is used on systems where `usize` is a 32-bit integer. This is usually the case on 32-bit machines.
    - The attacker can specify long (>= 2^29 bytes ~ 536MB) associated data

## Disclaimer

This is not an officially supported Google product.

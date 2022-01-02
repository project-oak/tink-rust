# Tink-Rust: Hybrid Encryption

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-hybrid)
![MSRV](https://img.shields.io/badge/rustc-1.51+-yellow?style=for-the-badge)

This crate provides hybrid encryption functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#hybrid-encryption).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/hybrid/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() -> Result<(), Box<dyn Error>> {
    tink_hybrid::init();
    let kh_priv = tink_core::keyset::Handle::new(
        &tink_hybrid::ecies_hkdf_aes128_ctr_hmac_sha256_key_template(),
    )?;

    // NOTE: save the private keyset to a safe location. DO NOT hardcode it in source code.
    // Consider encrypting it with a remote key in Cloud KMS, AWS KMS or HashiCorp Vault.  See
    // https://github.com/google/tink/blob/master/docs/GOLANG-HOWTO.md#storing-and-loading-existing-keysets.

    let kh_pub = kh_priv.public()?;

    // NOTE: share the public keyset with the sender.

    let enc = tink_hybrid::new_encrypt(&kh_pub)?;

    let msg = b"this data needs to be encrypted";
    let encryption_context = b"encryption context";
    let ct = enc.encrypt(msg, encryption_context)?;

    let dec = tink_hybrid::new_decrypt(&kh_priv)?;

    let pt = dec.decrypt(&ct, encryption_context)?;
    assert_eq!(msg[..], pt);

    println!("Ciphertext: {}\n", hex::encode(&ct));
    println!("Original  plaintext: {}\n", String::from_utf8_lossy(msg));
    println!("Decrypted plaintext: {}\n", String::from_utf8_lossy(&pt));
    Ok(())
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

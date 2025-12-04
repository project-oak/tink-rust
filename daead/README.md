# Tink-Rust: Deterministic Authenticated Encryption with Additional Data

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-daead)
![MSRV](https://img.shields.io/badge/rustc-1.78.0+-yellow?style=for-the-badge)

This crate provides deterministic authenticated encryption with additional data (DAEAD) functionality, as described in
the upstream [Tink
documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#deterministic-authenticated-encryption-with-associated-data).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/daead/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() -> Result<(), Box<dyn Error>> {
    tink_daead::init();
    let kh = tink_core::keyset::Handle::new(&tink_daead::aes_siv_key_template())?;
    let d = tink_daead::new(&kh)?;

    let pt = b"this data needs to be encrypted";
    let ad = b"additional data";
    let ct1 = d.encrypt_deterministically(pt, ad)?;
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&ct1));

    let ct2 = d.encrypt_deterministically(pt, ad)?;
    assert_eq!(ct1, ct2, "cipher texts are not equal");
    println!("Cipher texts are equal.");

    let pt2 = d.decrypt_deterministically(&ct1, ad)?;
    assert_eq!(&pt[..], pt2);
    Ok(())
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

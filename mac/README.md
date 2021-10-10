# Tink-Rust: Message Authentication Code

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-mac)
![MSRV](https://img.shields.io/badge/rustc-1.49+-yellow?style=for-the-badge)

This crate provides message authentication code (MAC) functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#message-authentication-code).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/mac/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_mac::init();
    let kh = tink_core::keyset::Handle::new(&tink_mac::hmac_sha256_tag256_key_template()).unwrap();
    let m = tink_mac::new(&kh).unwrap();

    let pt = b"this data needs to be MACed";
    let mac = m.compute_mac(pt).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&mac));

    assert!(m.verify_mac(&mac, b"this data needs to be MACed").is_ok());
    println!("MAC verification succeeded.");
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

# Tink-Rust: Pseudo-Random Functions

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-prf)
![MSRV](https://img.shields.io/badge/rustc-1.49+-yellow?style=for-the-badge)

This crate provides pseudo-random function (PRF) functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#pseudo-random-function-families).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/prf/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() {
    tink_prf::init();
    let kh = tink_core::keyset::Handle::new(&tink_prf::hmac_sha256_prf_key_template()).unwrap();
    let m = tink_prf::Set::new(&kh).unwrap();

    let pt = b"need pseudo-random data deterministically produced from this input";
    let out = m.compute_primary_prf(pt, 16).unwrap();
    println!("'{}' => {}", String::from_utf8_lossy(pt), hex::encode(&out));
    assert_eq!(out.len(), 16);
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

# Tink-Rust: Protobuf Definitions

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-proto)
![MSRV](https://img.shields.io/badge/rustc-1.65+-yellow?style=for-the-badge)

This crate holds Rust structures auto-generated (using [prost](https://docs.rs/prost)) from the protocol
buffer message definitions in the `proto/` subdirectory.  These `.proto` files are copies from
the upstream [Tink project](https://github.com/google/tink/tree/master/proto).

The version of `prost` used by the library is re-exported as `tink_proto::prost`, to allow library users to get a
precise version match.

## Features

The `json` feature enables [`serde_json`](https://docs.rs/serde-json) based serialization of the structures.

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

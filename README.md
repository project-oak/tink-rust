# Tink in Rust

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://project-oak.github.io/tink-rust)
![MSRV](https://img.shields.io/badge/rustc-1.60+-yellow?style=for-the-badge)
[![CI Status](https://img.shields.io/github/actions/workflow/status/project-oak/tink-rust/ci.yml?branch=main&color=blue&style=for-the-badge)](https://github.com/project-oak/tink-rust/actions?query=workflow%3ACI)
[![Interop Status](https://img.shields.io/github/actions/workflow/status/project-oak/tink-rust/crosstest.yml?branch=main&color=orange&label=interop&style=for-the-badge)](https://github.com/project-oak/tink-rust/actions?query=workflow%3Acrosstest)
[![codecov](https://img.shields.io/codecov/c/github/project-oak/tink-rust?style=for-the-badge)](https://codecov.io/gh/project-oak/tink-rust)

This repository holds a Rust port of Google's [Tink cryptography library](https://github.com/google/tink).

The following warnings apply to use of this repo:

- This is not an official port of Tink, and is **not supported** by Google's cryptography teams.
- **The repo is under construction** and so details of the API and the code may change without warning.

Also, this repository does not implement cryptographic functionality itself; the underlying cryptographic operations are
currently provided by the [RustCrypto](https://github.com/RustCrypto) crates &ndash; this repo focuses on making
those cryptographic operations available via the Tink API.

This means that **all of the security warnings** for the underlying RustCrypto crates apply to this repo too.

## Disclaimer

This is not an officially supported Google product.

## Usage Overview

An introduction to working with the Tink API is [provided here](docs/RUST-HOWTO.md).

## Crate Structure

The `tink-core` crate holds common functionality and includes the `trait` definitions for all
[primitives](https://github.com/google/tink/blob/v1.5.0/docs/PRIMITIVES.md), but includes
very little cryptographic functionality.

Individual cryptographic primitives are implemented in `tink-<primitive>` crates, which depend on:

- the `tink-core` crate for common types and helpers
- the `tink-proto` crate for protobuf-derived `struct`s
- the RustCrypto crates to provide underlying cryptographic implementations.

For example, the `tink-aead` crate provides code that performs authenticated encryption with additional data (AEAD),
implementing the `Aead` trait from `tink-core`.

All of the tests for the Tink crates are integration tests (i.e. only use public APIs) and reside in a separate
`tink-tests` crate.

### Crate Features

The following [crate features](https://doc.rust-lang.org/cargo/reference/features.html) are available.

- The [`tink-proto`](https://docs.rs/tink-proto) crate has a `json` feature that enables methods for serializing keysets
  to/from JSON.  This additional functionality requires `serde` and `serde_json` as dependencies.
- The [`tink-core`](https://docs.rs/tink-core) crate also has a `json` feature that enables methods for serializing
  keysets to/from JSON, using `tink-proto/json` as above.
- The `tink-core` crate also has an `insecure` feature, which enables methods that expose unencrypted key material. This
  feature should only be enabled for testing and development.

## Port Design

A [separate document](docs/RUST-DESIGN.md) describes the design choices involved in the Rust port.

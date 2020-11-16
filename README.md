# Tink in Rust

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

The core `tink` crate holds common functionality and includes the `trait` definitions for all
[primitives](https://github.com/google/tink/blob/v1.5.0/docs/PRIMITIVES.md), but includes
very little cryptographic functionality.

Individual cryptographic primitives are implemented in `tink-<primitive>` crates, which depend on:

- the `tink` crate for common types and helpers
 - the RustCrypto crates to provide underlying cryptographic implementations.

For example, the `tink-aead` crate provides code that performs authenticated encryption with additional data (AEAD),
implementing the `tink::Aead` trait.

(However, integration tests can and do include `dev-dependencies` on both core `tink` and particular primitive crates.  For
example, `tink` tests depend on `tink-mac` and `tink-testutil`, the latter of which depends on the `insecure` feature
of `tink` itself.)

## Rust Port Design

The Rust port of Tink has the following meta-goals:

 - **Diverge as little as possible from the upstream Tink code**: The Rust port is primarily based on the Go language
   version of upstream Tink, and aims to stay as close to it as possible so that future changes to Tink can be
   merged more easily. However, this does mean that some aspects of the port are not quite idiomatic Rust.
 - **Don't write any crypto code**: The Rust port aims to defer all cryptographic implementations to external crates
  (currently the [RustCrypto](https://github.com/RustCrypto) crates).

The remainder of this section describes design decisions involved in the conversion from Go to Rust.

### The `Primitive` Type

The Go port uses `interface {}` to hold an arbitrary primitive, and uses [type
assertions](https://tour.golang.org/methods/15) to convert to particular primitive `interface` types.  This is not
possible in Rust, and so the Rust port includes a `Primitive` `enum` that holds all of the possible primitive types (as
trait objects):

```Rust
enum Primitive {
    Aead(Box<dyn Aead>),
    DeterministicAead(Box<dyn DeterministicAead>),
    // ...
    Verifier(Box<dyn Verifier>),
}
```

However, this has the big downside that it is impossible for third parties to extend the Rust port of Tink to include
new types of primitive without modifying the Tink source.

### The `KeyManager` Registry

A `KeyManager` is an object that handles the translation from a `Key` instance to a `Primitive` object that uses the
`Key` for its key material. Tink has a **global** registry of `KeyManager` instances, each indexed by a **type URL**
that identifies the kind of keys it supports.

This registry allows an arbitrary `Key` to be converted to a `Primitive` of the relevant type:
 - In Go, primitives are of type `interface {}`, and the user of the registry uses [type
   assertions](https://tour.golang.org/methods/15) to convert a general primitive to a more specific object that
   implements the `interface` of a particular primitive.
     - The global registry is automatically populated at start-of-day, by the use of
       [`init()`](https://golang.org/doc/effective_go.html#init) methods for each particular `KeyManager`
       implementation.
 - In C++, the `KeyManager<P>` type is a template that is parameterized by the particular primitive
   type that it handles, so it returns primitives that are automatically type safe.  Internally, the global registry of
   key manager instances maps type URL strings to a combination of (roughly) `void *` and
   [`type_info`](https://en.cppreference.com/w/cpp/types/type_info); the particular `KeyManager<P>` is then
   recovered via `static_cast` (modulo a check that the `type_info` is sensible).
     - The global registry has to be manually populated by calling `<Primitive>Config::Register()` methods before use.
 - In Rust, the `Primitive` type is an enum that encompasses all primitive types, and the user of the registry
   checks that the relevant enum variant is returned.
     - The global registry has to be manually populated by calling `tink_<primitive>::init()` methods before use.

**TODO**: Investigate whether there's a safe way in Rust to have a global registry of `KeyManager` instances that are
typed to a particular primitive (rather than the catchall `enum Primitive`)

### Error Handling

Many Go functions return values of form `(ReturnType, error)`; the Rust equivalent of this is a `Result<ReturnType, E>`,
where `E` is some type that implements the [`Error` trait](https://doc.rust-lang.org/std/error/trait.Error.html).

The Rust port uses the `TinkError` type for `E`.  This type includes an optional inner `Error`, and the
`tink::utils` module also includes the `wrap_err()` helper, which is used as an equivalent for the common Go pattern
of wrapping errors:

```Go
x, err := library.DoSomething()
if err != nil {
	return nil, fmt.Errorf("doing something failed: %s", err)
}
```

like so:

```Rust
let x = library::do_something().map_err(|e| wrap_err("doing something failed", e))?;
```

### The `PrivateKeyManager` Type

The Go version of Tink includes a `PrivateKeyManager` interface which extends the `KeyManager` interface, and uses
down-casting type assertions to see if an instance of the latter is also an instance of the former:

```Go
	km, err := registry.GetKeyManager(privKeyData.TypeUrl)
	if err != nil {
		return nil, err
	}
	pkm, ok := km.(registry.PrivateKeyManager)
```

Rust allows a trait definition to indicate a required trait bound (`trait PrivateKeyManager: KeyManager {..}`), but does
not support down-casting; given a trait object of type `dyn KeyManager`, there is no way to determine if the object also
references a concrete type that implements the `dyn PrivateKeyManager` trait.

As a result, there is no `PrivateKeyManager` trait in the Rust port. Instead, the `KeyManager` trait includes the
`public_key_data()` method from Go's `PrivateKeyManager`, together with a `supports_private_keys()` method to allow
discovery of whether a `KeyManager` trait object supports this or not.  Both of these trait methods have default
implementations that indicate no support for private keys.

### `init` Methods

The Go port uses [`init()` functions](https://golang.org/doc/effective_go.html#init) to register primitive factories;
this is not supported in Rust, so each crate that provides a primitive has an `init()` function that should be called
before use.

### `KeyManager::new_key` Method

The Go port has a `KeyManager.NewKey` method which returns a `proto.Message` holding a new key. For the Rust port, the
equivalent `KeyManager::new_key` method returns a *serialized* protobuf message (as a `Vec<u8>`) rather than a
`prost::Message`.

This is because a returned trait object of type `dyn prost::Message` would not be of much use &ndash; almost all of the methods
on the [`prost::Message` trait](https://docs.rs/prost/0.6.1/prost/trait.Message.html) require a `self` parameter that is
[`Sized`](https://doc.rust-lang.org/std/marker/trait.Sized.html), and a bare trait object is *not* `Sized`.

### `std` Support

The Rust port of Tink requires `std`, primarily due to the use of [prost](https://crates.io/crates/prost) for protocol
buffer support. If Prost gets [`no_std` support](https://github.com/danburkert/prost/issues/51), this can be revisited.

The obvious changes needed to make Tink `no_std` compatible would include the following, but there are bound to be
others:

 - Depend on `core` + `alloc` instead of `std`, and have a `std` feature for those things that definitely need `std`:
     - keyset I/O (both binary and JSON-based)
     - streaming AEAD
 - Changes to use `core` / `alloc` types:
     - `Box` => `alloc::boxed::Box`
     - `String` => `alloc::string::String`
     - `Vec` => `alloc::vec::Vec`
     - `std::sync::Arc` => `alloc::sync::Arc`
     - `std::fmt::*` => `core::fmt::*`
     - `std::collections::HashMap` => `alloc::collections::BTreeMap`
     - `std::sync::RwLock` => `spin::RwLock`
     - `std::convert::From` => `core::convert::From`
     - Move `TinkError` to wrap something that just implements `core::fmt::Debug` rather than `std::error::Error`.

### Stringly-Typed Parameters

The Go port uses [stringly-typed parameters](https://wiki.c2.com/?StringlyTyped) to indicate enumerations in various
places (e.g. hash function names, curve names).  Wherever possible, the Rust port uses strongly typed `enum`s instead:

- When the main enumeration definition is from a [protobuf
  file](https://developers.google.com/protocol-buffers/docs/proto3#enum), the generated Rust code has a corresponding
  `enum` type, but fields using that type are encoded as `i32` values.  The `enum` type is used for API parameters in
  the Rust port, and converted to `i32` values when held in a protobuf-generated `struct`.
- When enumeration values are serialized to/from JSON, their `i32` values are converted to/from string values that match
  the Go string values (see [below](#json-output)).
- Test vectors from [Wycheproof](https://github.com/google/wycheproof) use string names to identify enumeration values;
  these are converted to the relevant `enum` type in the relevant Wycheproof-driven test cases.

### JSON Output

Tink supports the encoding of `Keyset` and `EncryptedKeyset` types as JSON, with the following conventions:
 - Values of type `bytes` are serialized to base64-encoded strings (standard encoding).
 - Enum values are serialized as capitalized strings (e.g. `"ASYMMETRIC_PRIVATE"`).

The `tink::keyset::json_io` module includes `serde` serialization code which matches these conventions.

However, in Rust, the `Keyset` types are derived from protobuf message definitions (via
[prost-build](https://crates.io/crates/prost-build), which makes it difficult to invoke these
conventions via [`serde-json` attributes](https://serde.rs/field-attrs.html).

The `tink::keyset::json_io` module therefore also includes manual copies of these data structure definitions, together
with:
 - `serde-json` annotations to invoke the relevant serialization code
 - implementations of the `From` trait to ensure that the base structures and the copies can be
   converted into each other.

This has the obvious disadvantage that any changes to the `Keyset`-related protobuf definitions will need
to be manually synced with the copy data structures.  (However, note that Rust requires all `struct` fields to be
initialized so any change will induce a **compile-time** error.)

**TODO**: fix prost-build => serde-json generation so the field attributes are automatically
attached and the manually-cloned `struct`s can be dropped.


### Code Structure

This section describes the mapping between the upstream Go packages and the equivalent Rust crates and modules.

#### Infrastructure

|  Rust Crate/Module   | Go Package |
|----------------------|------------|
| `tink::cryptofmt`    | `core/cryptofmt` |
| `tink::keyset`       | `keyset` |
| `tink::primitiveset` | `core/primitiveset` |
| `tink::registry`     | `core/registry` |
| `tink`               | `tink` |
| `tink::proto`        | `*_go_proto` |

#### Common Crypto

|  Rust Crate/Module     | Go Package |
|------------------------|------------|
|                        | `kwp` |
| `tink::subtle::random` | `subtle/random` |
| `tink::subtle`         | `subtle` |

#### Primitives

|  Rust Crate/Module   | Go Package |
|----------------------|------------|
| `tink-aead`          | `aead` |
| `tink-daead`         | `daead` |
|                      | `hybrid` |
| `tink-mac`           | `mac` |
| `tink-prf`           | `prf` |
| `tink-signature`     | `signature` |
|                      | `streamingaead` |

#### Testing

|  Rust Crate/Module       | Go Package |  Notes |
|--------------------------|------------|--------|
| `tink::keyset::insecure` | `insecurecleartextkeyset` | Gated on (non-default) `insecure` feature |
| `tink::keyset::insecure` | `internal` | Gated on (non-default) `insecure` feature |
| `tink::keyset::insecure` | `testkeyset` | Gated on (non-default) `insecure` feature |
| `tink-testutil`          | `testutil` | Depends on `insecure` feature of `tink` crate |
| `tink-testing`           | `services` (`/testing/go/`) |
| `tink-testing::proto`    | `testing_api_go_grpc` (`/proto/testing/`) |
|                          | `main` (`/tools/testing/go/`) |

#### Key Management Systems

|  Rust Crate/Module   | Go Package |
|----------------------|------------|
| `tink-awskms`        | `integration/awskms` |
|                      | `integration/gcpkms` |
|                      | `integration/hcvault` |

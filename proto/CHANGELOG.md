# Change Log

## 0.2.5 - TBD

- Increase MSRV to 1.57.0
- Upgrade dependencies
- Only rebuild generated code if PROTOC environment variable is set

## 0.2.4 - 2022-03-25

- Increase MSRV to 1.52.0
- Upgrade dependencies

## 0.2.3 - 2022-01-03

- Add crate `README.md`.
- Re-export `prost`.
- Adjust comments on protobuf-generated code to match upstream.
- Add `CustomKid` field to `JwtHmacKey` struct.
- Update unused proto files to match current upstream.
- Upgrade dependencies.

## 0.2.2 - 2021-10-09

- Enable `doc_cfg` feature.

## 0.2.1 - 2021-10-08

- Add `#[doc(cfg)]` markers for feature-gated code
- Upgrade dependencies.

## 0.2.0 - 2021-05-24

- Sync with upstream Tink version 1.6.0
- Add `version` field to `AesSivKeyFormat` (breaking change).
- Add `version` field to `Ed25519KeyFormat` (breaking change).
- Add `version` field to `XChaCha20Poly1305KeyFormat` (breaking change).
- Add `HashType::SHA224` enum (breaking change).
- Change `hash_type` to `algorithm` in `JwtHmacKey[Format]` (breaking change).
- Update unused proto files to match current upstream.
- Upgrade dependencies.

## 0.1.1 - 2021-04-23

- Upgrade dependencies.

## 0.1.0 - 2021-01-21

- Initial version, based on upstream Tink (Go) version 1.5.0

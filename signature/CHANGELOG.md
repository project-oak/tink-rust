# Change Log

## 0.2.4 - TBD

- Increase MSRV to 1.52.0
- Upgrade dependencies

## 0.2.3 - 2022-01-03

- Add crate `README.md`.
- Use `tink-proto`'s re-export of `prost` to ensure versions match.
- Add `ecdsa_p256_raw_key_template()`,
- Register key template generator for `ECDSA_P256_RAW`.
- Add `ecdsa_p384_sha384_key_template()`, `ecdsa_p384_sha512_key_template()`
- Deprecate `ecdsa_p384_key_template()`.
- Register key template generators for (unsupported) P384 and P521 key templates.
- Upgrade dependencies.

## 0.2.2 - 2021-10-09

(Version skipped to align `tink-*` crate versions.)

## 0.2.1 - 2021-10-08

- Upgrade dependencies.

## 0.2.0 - 2021-05-24

- Sync with upstream Tink version 1.6.0
- Upgrade dependencies.

## 0.1.1 - 2021-04-23

- Add verification failure cases to benchmarks.
- Upgrade dependencies.

## 0.1.0 - 2021-01-21

- Initial version, based on upstream Tink (Go) version 1.5.0

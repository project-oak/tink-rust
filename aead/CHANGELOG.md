# Change Log

## 0.4.0 - TBD

- Increase MSRV to 1.78.0

## 0.3.0 - 2024-11-28

- Increase MSRV to 1.71.1
- Upgrade dependencies

## 0.2.5 - 2023-03-14

- Increase MSRV to 1.60.0
- Upgrade dependencies

## 0.2.4 - 2022-03-25

- Fix potential AAD overflow vulnerability on 32-bit platforms.
- Increase MSRV to 1.52.0
- Upgrade dependencies

## 0.2.3 - 2022-01-03

- Add crate `README.md`.
- Use `tink-proto`'s re-export of `prost` to ensure versions match.
- Register `AES256_GCM_NO_PREFIX` and `AES256_GCM_SIV_NO_PREFIX` templates.
- Upgrade dependencies.

## 0.2.2 - 2021-10-09

(Version skipped to align `tink-*` crate versions.)

## 0.2.1 - 2021-10-08

- Upgrade dependencies.

## 0.2.0 - 2021-05-24

- Sync with upstream Tink version 1.6.0
- Change prefix type from `Tink` to `Raw` for `KmsEnvelopeAeadKeyFormat` generation.
- Upgrade dependencies.

## 0.1.1 - 2021-04-23

- Add decryption failure cases to benchmarks.
- Upgrade dependencies.

## 0.1.0 - 2021-01-21

- Initial version, based on upstream Tink (Go) version 1.5.0

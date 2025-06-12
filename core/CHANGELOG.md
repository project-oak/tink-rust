# Change Log

## 0.4.0 - TBD

- Make `tink_core::TinkError` implement `Sync`; this is a breaking change, as it requires a `Sync` bound on wrapped errors

## 0.3.0 - 2024-11-28

- Increase MSRV to 1.71.1
- Upgrade dependencies
- Make `tink_core::TinkError` implement `Send`; this is a breaking change, as it requires a `Send` bound on wrapped errors

## 0.2.5 - 2023-03-14

- Increase MSRV to 1.60.0
- Upgrade dependencies

## 0.2.4 - 2022-03-25

- Increase MSRV to 1.52.0
- Upgrade dependencies

## 0.2.3 - 2022-01-03

- Add crate `README.md`.
- Use `tink-proto`'s re-export of `prost` to ensure versions match.
- Implement `Clone` for `TypedEntry<Box<HybridEncrypt>>` and `TypedEntry<Box<HybridDecrypt>>`
- Upgrade dependencies.

## 0.2.2 - 2021-10-09

- Enable `doc_cfg` feature.

## 0.2.1 - 2021-10-08

- Add `#[doc(cfg)]` markers for feature-gated code
- Add `keyset::Handle::read_with_associated_data()`
- Upgrade dependencies.

## 0.2.0 - 2021-05-24

- Sync with upstream Tink version 1.6.0
- Don't allow unknown prefix types in `keyset::Manager::add()` (breaking change).
- Cope with `HashType::Sha224`.
- Upgrade dependencies.

## 0.1.1 - 2021-04-23

- Improve doc comments.
- Upgrade dependencies.

## 0.1.0 - 2021-01-21

- Initial version, based on upstream Tink (Go) version 1.5.0

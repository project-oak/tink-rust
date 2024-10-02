# Tink-Rust: AWS-KMS integration

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-awskms)
![MSRV](https://img.shields.io/badge/rustc-1.71.1+-yellow?style=for-the-badge)

This crate provides functionality for integrating Tink with [AWS KMS](https://aws.amazon.com/kms/).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../../examples/kms/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() -> Result<(), Box<dyn Error>> {
    tink_aead::init();

    // Generate a new key.
    let kh1 = tink_core::keyset::Handle::new(&tink_aead::aes256_gcm_key_template())?;

    // Set up the main key-encryption key at a KMS. This is an AEAD which will generate a new
    // data-encryption key (DEK) for each encryption operation; the DEK is included in the
    // ciphertext emitted from the encryption operation, in encrypted form (encrypted by the
    // KMS main key).
    let kms_client =
        tink_awskms::AwsClient::new_with_credentials(KEY_URI, &PathBuf::from(CRED_INI_FILE))?;
    let backend = kms_client.get_aead(KEY_URI)?;
    let main_key = Box::new(tink_aead::KmsEnvelopeAead::new(
        tink_aead::aes256_gcm_key_template(),
        backend,
    ));

    // The `keyset::Reader` and `keyset::Writer` traits allow for reading/writing a keyset to
    // some kind of store; this particular implementation just holds the keyset in memory.
    let mut mem_keyset = tink_core::keyset::MemReaderWriter::default();

    // The `Handle::write` method encrypts the keyset that is associated with the handle, using the
    // given AEAD (`main_key`), and then writes the encrypted keyset to the `keyset::Writer`
    // implementation (`mem_keyset`).  We recommend you encrypt the keyset handle before
    // persisting it.
    kh1.write(&mut mem_keyset, main_key.box_clone())?;
    println!("Encrypted keyset: {:?}", mem_keyset.encrypted_keyset);

    // The `Handle::read` method reads the encrypted keyset back from the `keyset::Reader`
    // implementation and decrypts it using the AEAD used to encrypt it (`main_key`), giving a
    // handle to the recovered keyset.
    let kh2 = tink_core::keyset::Handle::read(&mut mem_keyset, main_key)?;

    assert_eq!(
        insecure::keyset_material(&kh1),
        insecure::keyset_material(&kh2)
    );
    println!("Key handles are equal.");
    Ok(())
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

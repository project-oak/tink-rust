# Tink-Rust: Streaming Authenticated Encryption with Additional Data

[![Docs](https://img.shields.io/badge/docs-rust-brightgreen?style=for-the-badge)](https://docs.rs/tink-streaming-aead)
![MSRV](https://img.shields.io/badge/rustc-1.78.0+-yellow?style=for-the-badge)

This crate provides streaming authenticated encryption with additional data functionality, as described in the upstream
[Tink documentation](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data).

## Usage

<!-- prettier-ignore-start -->
[embedmd]:# (../examples/streaming/src/main.rs Rust /fn main/ /^}/)
```Rust
fn main() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?.into_path();
    let ct_filename = dir.join("ciphertext.bin");

    tink_streaming_aead::init();

    // Generate fresh key material.
    let kh =
        tink_core::keyset::Handle::new(&tink_streaming_aead::aes128_gcm_hkdf_4kb_key_template())?;

    // Get the primitive that uses the key material.
    let a = tink_streaming_aead::new(&kh)?;

    // Use the primitive to create a [`std::io::Write`] object that writes ciphertext
    // to a file.
    let aad = b"this data needs to be authenticated, but not encrypted";
    let ct_file = std::fs::File::create(ct_filename.clone())?;
    let mut w = a.new_encrypting_writer(Box::new(ct_file), &aad[..])?;

    // Write data to the encrypting-writer, in chunks to simulate streaming.
    let mut offset = 0;
    while offset < PT.len() {
        let end = std::cmp::min(PT.len(), offset + CHUNK_SIZE);
        let written = w.write(&PT[offset..end])?;
        offset += written;
        // Can flush but it does nothing.
        w.flush()?;
    }
    // Complete the encryption (process any remaining buffered plaintext).
    w.close()?;

    // For the other direction, given a [`std::io::Read`] object that reads ciphertext,
    // use the primitive to create a [`std::io::Read`] object that emits the corresponding
    // plaintext.
    let ct_file = std::fs::File::open(ct_filename)?;
    let mut r = a.new_decrypting_reader(Box::new(ct_file), &aad[..])?;

    // Read data from the decrypting-reader, in chunks to simulate streaming.
    let mut recovered = vec![];
    loop {
        let mut chunk = vec![0; CHUNK_SIZE];
        let len = r.read(&mut chunk)?;
        if len == 0 {
            break;
        }
        recovered.extend_from_slice(&chunk[..len]);
    }

    assert_eq!(recovered, PT);
    Ok(())
}
```
<!-- prettier-ignore-end -->

## License

[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

## Disclaimer

This is not an officially supported Google product.

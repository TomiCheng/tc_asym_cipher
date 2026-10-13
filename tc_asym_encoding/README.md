# tc_asym_encoding

[![crates.io](https://img.shields.io/crates/v/tc_asym_encoding.svg)](https://crates.io/crates/tc_asym_encoding)
[![docs.rs](https://docs.rs/tc_asym_encoding/badge.svg)](https://docs.rs/tc_asym_encoding)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

PKCS#1 v1.5 and OAEP over any asymmetric block cipher of
[`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher), such as the RSA
engines of [`tc_rsa`](https://crates.io/crates/tc_rsa), after Bouncy Castle's
`crypto/encodings`. Each encoding is an asymmetric block cipher of its own.
`no_std` with `alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `OaepEncoding` — OAEP with MGF1 over a `tc_digest` digest, an optional label and a seed from a caller's random source.
- `Pkcs1Encoding` — PKCS#1 v1.5, block type 2 with a public key and type 1 with a private one.
- `EncodingError` — the failures of an encoding, wrapping the engine's.

## Traits

The encodings implement `AsymmetricBlockCipher` and
`AsymmetricBlockCipherInit` of `tc_asym_cipher`.

## Features

None; the crate always uses `alloc` for its block buffers.

## Usage

```rust
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_encoding::OaepEncoding;
use tc_rsa::RsaEngine;
use tc_sha::Sha256Digest;

let mut oaep = OaepEncoding::from_parts(RsaEngine::new(), Sha256Digest::new(), rand::rng());
oaep.init(CipherDirection::Encrypt, &public_key).expect("a valid RSA key");
let mut ciphertext = vec![0; oaep.output_block_size()];
oaep.process_block(b"attack at dawn", &mut ciphertext).expect("a short message");
```

## Security

Use OAEP for new designs. PKCS#1 v1.5 decryption with a private key tells
through its error whether the padding was good, which Bleichenbacher's attack
turns into decryption; where an attacker can send ciphertexts, fix the
plaintext length with `with_plaintext_length`, or use OAEP. Every failure of an
OAEP block is the same `InvalidBlock`, found after the whole block is checked.
Both encodings are constant time in the message and the block, apart from the
engine and the digest; the documentation states the timing of every item.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

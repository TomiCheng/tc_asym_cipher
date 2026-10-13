# tc_asym_cipher

[![crates.io](https://img.shields.io/crates/v/tc_asym_cipher.svg)](https://crates.io/crates/tc_asym_cipher)
[![docs.rs](https://docs.rs/tc_asym_cipher/badge.svg)](https://docs.rs/tc_asym_cipher)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Shared contracts for asymmetric block ciphers and key pair generators, after
Bouncy Castle's `IAsymmetricBlockCipher` and
`IAsymmetricCipherKeyPairGenerator`. [`tc_rsa`](https://crates.io/crates/tc_rsa)
implements them, and [`tc_asym_encoding`](https://crates.io/crates/tc_asym_encoding)
wraps any engine that does. `no_std`, no allocator, no dependencies, no
`unsafe`, Rust 1.85 or later.

## Traits

- `AsymmetricBlockCipher` — block sizes and `process_block` for one block of any length up to the input block.
- `AsymmetricBlockCipherInit<P>` — `init` with a direction and a key of type `P`.
- `AsymmetricKeyParams` — whether a key is private.
- `KeyPairGenerator` — `generate_key_pair` returns the public and the private key.
- `KeyPairGeneratorInit<P>` — `init` with parameters that carry the random source.

## Types

- `CipherDirection` — `Encrypt` or `Decrypt`.

## Features

None; the crate needs neither `std` nor `alloc`.

## Usage

```rust
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};

fn encrypt<C, K>(cipher: &mut C, key: &K, message: &[u8], output: &mut [u8]) -> Option<usize>
where
    C: AsymmetricBlockCipher + AsymmetricBlockCipherInit<K>,
{
    cipher.init(CipherDirection::Encrypt, key).ok()?;
    cipher.process_block(message, output).ok()
}
```

## Security

The traits make no timing promise. Accepted keys, the state left by a rejected
initialization and whether an engine runs in constant time are documented by
each engine. Raw RSA is not an encryption scheme: put a padding such as OAEP
from `tc_asym_encoding` over the engine.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

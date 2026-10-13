# tc_rsa

[![crates.io](https://img.shields.io/crates/v/tc_rsa.svg)](https://crates.io/crates/tc_rsa)
[![docs.rs](https://docs.rs/tc_rsa/badge.svg)](https://docs.rs/tc_rsa)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

RSA after Bouncy Castle: key pair generation, blinding and the RSA operation
as an asymmetric block cipher of
[`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher), over the integers
of [`tc_bigint`](https://crates.io/crates/tc_bigint) or, behind a feature, the
RustCrypto [`rsa`](https://crates.io/crates/rsa) crate. `no_std`, no `unsafe`,
Rust 1.85 or later. Benchmarks are in [BENCHES.md](BENCHES.md).

## Types

- `RsaEngine` (`alloc`) — RSA over an `RsaKey`, on the engine the key and the features suit best.
- `RsaKeyGenerator` (`alloc`) — generates pairs of `RsaKey`.
- `RsaKey` (`alloc`) — a key over `PaddedBigUint`, raised by its exponent or through the CRT.
- `RsaBlindedEngine` — blinds the private operation of an engine with a fresh random factor per block.
- `FixedRsaCoreEngine`, `FixedRsaCrtCoreEngine` — RSA without and with the CRT over `FixedBigUint`, with no allocator.
- `PaddedRsaCoreEngine`, `PaddedRsaCrtCoreEngine` (`alloc`) — the same over `PaddedBigUint`, at the width of the modulus.
- `RsaCoreEngineRustCrypto`, `RsaCrtCoreEngineRustCrypto` (`rustcrypto`) — the public and private operations of the `rsa` crate.
- `RsaKeyPairGenerator` (`alloc`) — generates key pairs into integers of the caller's type.
- `RsaKeyPairGeneratorRustCrypto` (`rustcrypto`) — generates key pairs through the `rsa` crate.
- `RsaBlindingEngine`, `RsaBlindingFactorGenerator`, `RsaBlindingParams` (`alloc`) — Chaum's blinding for a blind signature.
- `RsaKeyOwned`, `RsaKeyRef`, `RsaPrivateCrtKeyOwned`, `RsaPrivateCrtKeyRef` — keys held by value or borrowed.
- `RsaKeyRustCrypto`, `RsaPrivateCrtKeyRustCrypto` (`rustcrypto`) — keys of the `rsa` crate.
- `RsaKeyGenerationParamsOwned`, `RsaKeyGenerationParamsRef` (`alloc`) — the random source, public exponent, strength and certainty to generate to.
- `RsaError` — what can go wrong in RSA.
- `ALGO_NAME` — `"RSA"`, the name every engine writes through `Display`.

## Traits

- `RsaKeyParams` — the modulus, one exponent and the check of a key.
- `RsaPrivateCrtKeyParams` — the primes and the values modulo them.
- `RsaKeyGenerationParams` (`alloc`) — what a key pair is generated to.
- `RsaBlinding` — an engine that can blind its private operation.

## Features

- `alloc` (on by default) — the padded engines, `RsaEngine`, `RsaKey`, key generation and blinding for blind signatures; without it, the fixed-width engines remain, for a target with no allocator.
- `rustcrypto` (off by default) — the engines, keys and generator of the RustCrypto `rsa` crate, which `RsaEngine` and `RsaKeyGenerator` then prefer. `rsa` 0.10 is still a release candidate and pinned exactly, and the feature follows the Rust version it requires, newer than 1.85.

## Usage

```rust
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator, KeyPairGeneratorInit};
use tc_rsa::{RsaEngine, RsaKeyGenerationParamsOwned, RsaKeyGenerator};

let mut generator = RsaKeyGenerator::new();
generator.init(RsaKeyGenerationParamsOwned::new(rand::rng())).expect("valid parameters");
let (public, private) = generator.generate_key_pair().expect("a 2048-bit key pair");
let mut engine = RsaEngine::new();
engine.init(CipherDirection::Encrypt, &public).expect("a valid key");
let mut ciphertext = [0; 256];
engine.process_block(b"a block of at most 255 bytes", &mut ciphertext).expect("a short block");
```

Decrypt or sign through `RsaBlindedEngine`, which blinds the private power;
the crate documentation walks through both directions.

## Security

Raw RSA is not an encryption or signature scheme: put a padding such as OAEP
from [`tc_asym_encoding`](https://crates.io/crates/tc_asym_encoding) over the
engine. The fixed-width and padded engines are constant time in the input and
the private key; the public exponent and the outcome of range and key checks
show. The CRT engines check each result by raising it back to `e`, against
fault attacks. Key generation is variable time, as Bouncy Castle's is. The
documentation states the timing of every item.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

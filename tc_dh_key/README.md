# tc_dh_key

[![crates.io](https://img.shields.io/crates/v/tc_dh_key.svg)](https://crates.io/crates/tc_dh_key)
[![docs.rs](https://docs.rs/tc_dh_key/badge.svg)](https://docs.rs/tc_dh_key)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

Diffie-Hellman domain parameters and keys after Bouncy Castle, the layer that
Diffie-Hellman key agreement and ElGamal share: the groups of RFC 2409, 3526
and 7919, safe-prime group generation, and key pair generation. `no_std` with
`alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `DhParameters` — p, g and the optional q, m, l, j and generation data; `validate` runs Bouncy Castle's checks.
- `DhPublicKey` — y with its parameters; `validate` checks its range and its subgroup.
- `DhPrivateKey` — x with its parameters, wiped on drop.
- `DhKeyGenerationParams` — the parameters a key pair is generated over.
- `DhKeyPairGenerator` — draws x and works out y = g^x mod p.
- `DhGroupGenerationParams` — the size and certainty of a group to generate, 2048 bits and 100 by default.
- `DhGroupGenerator` — generates a safe-prime group with g = 2.
- `DhValidationParameters` — the seed and counter a modulus was generated from.
- `DhError` — what the checks and the generators turn down.
- `standard_groups` — the groups of RFC 2409, 3526 and 7919.

## Traits

`DhKeyPairGenerator` implements `KeyPairGenerator` and `KeyPairGeneratorInit`
of [`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher).

## Features

None; the crate always uses `alloc` for its integers.

## Usage

```rust
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_dh_key::{standard_groups, DhKeyGenerationParams, DhKeyPairGenerator};

let params = DhKeyGenerationParams::new(standard_groups::rfc7919_ffdhe2048());
let mut generator = DhKeyPairGenerator::new(rand::rng());
generator.init(&params)?;
let (public_key, private_key) = generator.generate_key_pair()?;
peer_public_key.validate()?; // before agreeing on a peer's key
```

## Security

Check every public key and parameter set that comes from a peer with
`validate`; without it a peer can send a value of small order. `validate` does
not test p and q for primality, so prefer the standard groups to parameters
from elsewhere, and use groups of 2048 bits or more. Key generation is constant
time in the private value; the checks and group generation are variable time,
for public values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

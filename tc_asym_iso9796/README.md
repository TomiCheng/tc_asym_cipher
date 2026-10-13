# tc_asym_iso9796

[![crates.io](https://img.shields.io/crates/v/tc_asym_iso9796.svg)](https://crates.io/crates/tc_asym_iso9796)
[![docs.rs](https://docs.rs/tc_asym_iso9796/badge.svg)](https://docs.rs/tc_asym_iso9796)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

ISO/IEC 9796-1 digital signatures with message recovery over the RSA of
[`tc_rsa`](https://crates.io/crates/tc_rsa), after Bouncy Castle's
`ISO9796d1Encoding`. Part 2, Bouncy Castle's `Iso9796d2Signer`, is not
implemented yet. `no_std` with `alloc`, no `unsafe`, Rust 1.85 or later.

## Types

- `Iso9796d1Encoding` — ISO 9796-1 padding over a blinded `RsaEngine`: signs by encrypting with the private key and gives the message back when verifying with the public one.
- `Iso9796Error` — the failures of the encoding, wrapping those of RSA.

## Traits

`Iso9796d1Encoding` implements `AsymmetricBlockCipher` and
`AsymmetricBlockCipherInit` of
[`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher).

## Features

- `rustcrypto` (off by default) — turns on the `rustcrypto` feature of `tc_rsa`, so that the encoding runs on the RustCrypto `rsa` engines where they apply. It follows the Rust version that `rsa` and its dependencies require, outside the 1.85 guarantee.

## Usage

```rust
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_asym_iso9796::Iso9796d1Encoding;

let mut encoding = Iso9796d1Encoding::new(rand::rng());
encoding.init(CipherDirection::Encrypt, &private_key).expect("a valid RSA key");
let mut signature = vec![0; encoding.output_block_size()];
encoding.process_block(&hash, &mut signature).expect("a hash of at most half the modulus");
```

## Security

ISO 9796-1 is withdrawn: sign only a hash or a random value with it, never a
message as it is. The encoding is variable time, only for public values, as a
signature, the key that verifies it and the hash that is signed are. A private
key with its CRT values is blinded when it signs; one without them is not, as
in Bouncy Castle.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

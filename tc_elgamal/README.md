# tc_elgamal

[![crates.io](https://img.shields.io/crates/v/tc_elgamal.svg)](https://crates.io/crates/tc_elgamal)
[![docs.rs](https://docs.rs/tc_elgamal/badge.svg)](https://docs.rs/tc_elgamal)
[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

ElGamal encryption after Bouncy Castle, over the Diffie-Hellman groups and
generators of [`tc_dh_key`](https://crates.io/crates/tc_dh_key): the engine,
its keys, and key pair and group generation. `no_std` with `alloc`, no
`unsafe`, Rust 1.85 or later.

## Types

- `ElGamalEngine` — encrypts to γ = g^k and φ = y^k · m, and decrypts with x.
- `ElGamalParameters` — p, g and the optional length l of the private value; `validate` runs the Diffie-Hellman checks.
- `ElGamalPublicKey` — y with its parameters.
- `ElGamalPrivateKey` — x with its parameters, wiped on drop.
- `ElGamalKeyGenerationParams` — the parameters a key pair is generated over.
- `ElGamalKeyPairGenerator` — draws x and works out y = g^x mod p.
- `ElGamalGroupGenerator` — generates a safe-prime group with g = 2.
- `ElGamalError` — what the checks, the generators and the engine turn down.

## Traits

`ElGamalEngine` implements `AsymmetricBlockCipher` and
`AsymmetricBlockCipherInit` for both keys, and `ElGamalKeyPairGenerator`
implements `KeyPairGenerator` and `KeyPairGeneratorInit`, of
[`tc_asym_cipher`](https://crates.io/crates/tc_asym_cipher). Its block sizes
are those of `tc_rsa`, so the PKCS#1 and OAEP of
[`tc_asym_encoding`](https://crates.io/crates/tc_asym_encoding) wrap it.

## Features

None; the crate always uses `alloc` for its integers.

## Usage

```rust
let mut encryptor = ElGamalEngine::new(rand::rng());
encryptor.init(CipherDirection::Encrypt, &public_key)?;
let mut ciphertext = vec![0; encryptor.output_block_size()];
encryptor.process_block(b"hello", &mut ciphertext)?;

let mut decryptor = ElGamalEngine::new(rand::rng());
decryptor.init(CipherDirection::Decrypt, &private_key)?;
let mut plaintext = vec![0; decryptor.output_block_size()];
let length = decryptor.process_block(&ciphertext, &mut plaintext)?;
```

## Security

Raw ElGamal is malleable; wrap the engine in OAEP for messages from
untrusted senders. Prefer the standard groups of `tc_dh_key` to parameters
from elsewhere, and use groups of 2048 bits or more. Encryption is constant
time in the message and k, and decryption in x and the message; the range
checks of keys and ciphertexts and group generation are variable time, for
public values.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

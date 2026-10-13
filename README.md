# tc_asym_cipher

A Rust workspace for asymmetric block ciphers after Bouncy Castle: the
contracts an asymmetric engine and a key pair generator implement, RSA with
blinding and key generation, and the encodings and signatures that wrap an
engine. Each crate is published separately and keeps its own README and
changelog.

[![CI](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml/badge.svg)](https://github.com/TomiCheng/tc_asym_cipher/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)
![rustc](https://img.shields.io/badge/rustc-1.85+-blue.svg)

## Crates

| Crate | Version | Description |
| --- | --- | --- |
| [`tc_asym_cipher`](tc_asym_cipher) | [![crates.io](https://img.shields.io/crates/v/tc_asym_cipher.svg)](https://crates.io/crates/tc_asym_cipher) [![docs.rs](https://docs.rs/tc_asym_cipher/badge.svg)](https://docs.rs/tc_asym_cipher) | The `AsymmetricBlockCipher`, `AsymmetricBlockCipherInit`, `AsymmetricKeyParams`, `KeyPairGenerator` and `KeyPairGeneratorInit` contracts, the Rust form of Bouncy Castle's `IAsymmetricBlockCipher` and `IAsymmetricCipherKeyPairGenerator`, and `CipherDirection`. `no_std`, no allocator, no dependencies, no `unsafe`. The traits make no timing promise; each engine states its own. |
| [`tc_rsa`](tc_rsa) | [![crates.io](https://img.shields.io/crates/v/tc_rsa.svg)](https://crates.io/crates/tc_rsa) [![docs.rs](https://docs.rs/tc_rsa/badge.svg)](https://docs.rs/tc_rsa) | RSA after Bouncy Castle over the integers of `tc_bigint`: engines with and without the CRT, fixed-width and padded, the blinded engine, Chaum's blinding for blind signatures, and key pair generation. `no_std`, no `unsafe`; `alloc`, on by default, adds the padded engines, `RsaEngine`, `RsaKey` and key generation, and the default-off `rustcrypto` feature adds engines over the RustCrypto `rsa` crate. Constant time in the input and the private key. |
| [`tc_asym_encoding`](tc_asym_encoding) | [![crates.io](https://img.shields.io/crates/v/tc_asym_encoding.svg)](https://crates.io/crates/tc_asym_encoding) [![docs.rs](https://docs.rs/tc_asym_encoding/badge.svg)](https://docs.rs/tc_asym_encoding) | PKCS#1 v1.5 and OAEP over any asymmetric block cipher, after Bouncy Castle's `crypto/encodings`. `no_std` with `alloc`, no `unsafe`. Constant time in the message and the block, apart from the engine and the digest. |
| [`tc_asym_iso9796`](tc_asym_iso9796) | [![crates.io](https://img.shields.io/crates/v/tc_asym_iso9796.svg)](https://crates.io/crates/tc_asym_iso9796) [![docs.rs](https://docs.rs/tc_asym_iso9796/badge.svg)](https://docs.rs/tc_asym_iso9796) | ISO/IEC 9796-1 signatures with message recovery over the RSA of `tc_rsa`, after Bouncy Castle's `ISO9796d1Encoding`. `no_std` with `alloc`, no `unsafe`. Variable time, for public values. |

## Requirements

Rust 1.85 or later, edition 2024. Every crate builds without `std`.
`tc_asym_cipher` needs no allocator; `tc_rsa` needs none without its default
`alloc` feature, and the encodings always use `alloc`.

Rust 1.85 is the earliest compiler for edition 2024, and it is guaranteed for
every build but one. Besides `tc_*` crates, the libraries depend only on
`num-traits` and `rand_core`, both of which build on 1.85. The exception is the
default-off `rustcrypto` feature of `tc_rsa` and `tc_asym_iso9796`, which
brings in the RustCrypto `rsa` crate, a release candidate pinned exactly, and
follows the Rust version that `rsa` and its dependencies require, which they
may raise in any release; on 1.85, Cargo's MSRV-aware resolver picks releases
that still build there, where there are any. Dev-dependencies used only by
tests and benchmarks are exempt. The workspace lock tracks the latest
dependency releases, so CI on stable tests what a user on a current toolchain
resolves.

## Workspace checks

```text
cargo test --locked
cargo test --locked --all-features
cargo test --locked -p tc_rsa --no-default-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo doc --locked --no-deps --all-features
```

CI additionally runs these on Linux x64, i686 and ARM64, macOS ARM64, and
Windows x64, checks the `wasm32-unknown-unknown` and `aarch64-unknown-none`
targets and each crate's dependency set on each target, checks the build
without `rustcrypto` on Rust 1.85.0, and verifies the package archives. See
[.github/workflows/ci.yml](.github/workflows/ci.yml).

Before a release, check each archive and run publication validation from a
committed checkout:

```text
cargo package -p <crate> --list --locked
cargo publish -p <crate> --dry-run --locked
```

Publish in dependency order: `tc_asym_cipher`, then `tc_rsa`, then
`tc_asym_encoding` and `tc_asym_iso9796`. The archive must include both
license texts, the crate README, the changelog, the source, the integration
tests and, for `tc_rsa`, the benchmark with its results, and no `target/` or
other build artifacts.

## License

Licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

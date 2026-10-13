# Changelog

All notable changes to `tc_asym_cipher` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- The `AsymmetricBlockCipher` contract for the input and output block sizes
  and `process_block` over caller-provided buffers, and
  `AsymmetricBlockCipherInit`, which initializes an engine in a direction from
  a key of type `P`; the Rust form of Bouncy Castle's
  `IAsymmetricBlockCipher`.
- `AsymmetricKeyParams`, through which a key of any algorithm tells whether
  it is private, as Bouncy Castle's `AsymmetricKeyParameter.IsPrivate`.
- The `KeyPairGenerator` contract for `generate_key_pair`, and
  `KeyPairGeneratorInit`, which takes parameters by value so that they can
  carry the random source; the Rust form of Bouncy Castle's
  `IAsymmetricCipherKeyPairGenerator`.
- `CipherDirection`, `Encrypt` or `Decrypt`.
- A doctest that implements the cipher traits on a toy engine.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std`, needs no allocator, has no dependencies and contains no `unsafe`
  code.
- The traits make no timing promise; each engine documents its own.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.

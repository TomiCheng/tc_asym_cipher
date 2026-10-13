# Changelog

All notable changes to `tc_rsa` are documented in this file.

## 0.1.0 - 2026-10-13

Initial release.

### Added

- `FixedRsaCoreEngine` and `FixedRsaCrtCoreEngine`, RSA without and with the
  CRT over `FixedBigUint`, which need no allocator, and, with the `alloc`
  feature, `PaddedRsaCoreEngine` and `PaddedRsaCrtCoreEngine` over
  `PaddedBigUint`, as Bouncy Castle's `RsaCoreEngine` runs a key with or
  without its CRT values. Every engine writes the whole of its output block,
  leading zeros kept, and the CRT engines check each result by raising it back
  to `e`.
- `RsaBlindedEngine` and the `RsaBlinding` trait, which blind the private
  operation with a fresh random factor for each block, as Bouncy Castle's
  `RsaBlindedEngine`.
- With `alloc`, `RsaKey`, a key over `PaddedBigUint` raised by its exponent
  or through the CRT, `RsaEngine`, which runs it on the engine the key and the
  features suit best, and `RsaKeyGenerator`, which generates pairs of it.
- With `alloc`, `RsaKeyPairGenerator`, which generates key pairs into
  integers of the caller's type as Bouncy Castle's `RsaKeyPairGenerator`
  does, and `RsaKeyGenerationParamsOwned` and `RsaKeyGenerationParamsRef`
  behind the `RsaKeyGenerationParams` trait.
- With `alloc`, `RsaBlindingEngine`, `RsaBlindingFactorGenerator` and
  `RsaBlindingParams`, Chaum's blinding for blind signatures, as Bouncy
  Castle's.
- The `RsaKeyParams` and `RsaPrivateCrtKeyParams` traits, which validate a key
  as Bouncy Castle's `RsaKeyParameters` does, and the keys `RsaKeyOwned`,
  `RsaKeyRef`, `RsaPrivateCrtKeyOwned` and `RsaPrivateCrtKeyRef`, held by
  value or borrowed and wiped on drop when owned.
- With the default-off `rustcrypto` feature, `RsaCoreEngineRustCrypto`,
  `RsaCrtCoreEngineRustCrypto`, `RsaKeyPairGeneratorRustCrypto`,
  `RsaKeyRustCrypto` and `RsaPrivateCrtKeyRustCrypto` over the RustCrypto
  `rsa` crate, which `RsaEngine` and `RsaKeyGenerator` then prefer.
- `RsaError`, `#[non_exhaustive]`, and `ALGO_NAME`, the name every engine
  writes through `Display`.
- Tests that every engine runs Wycheproof's first 2048-bit PKCS#1 key to the
  same blocks, that the keys of each generator run on the engines of the
  other, and that every public function and trait implementation documents
  its timing; doctests for the engines, the generators and blinding; and the
  2048-bit benchmark in `BENCHES.md`.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024, except with the
  `rustcrypto` feature, which follows the Rust version of the `rsa` crate and
  its dependencies.
- Depends on `num-traits` 0.2, `rand_core` 0.10, `tc_asym_cipher` 0.1,
  `tc_bigint` 0.1, `tc_modular` 0.1, `tc_prime` 0.1 and `tc_zeroize` 0.1, and,
  with `rustcrypto`, on `rsa` `=0.10.0-rc.19`, a release candidate pinned
  exactly, and `zeroize` 1.8. Contains no `unsafe` code.
- `alloc` is on by default; without it, only the fixed-width engines, the
  blinded engine and the key containers remain.
- The fixed-width and padded engines are constant time in the input and the
  private key; the public exponent and the outcome of the range and key checks
  show. Key generation is variable time.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.

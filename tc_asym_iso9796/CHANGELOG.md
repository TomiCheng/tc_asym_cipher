# Changelog

All notable changes to `tc_asym_iso9796` are documented in this file.

## 0.1.0 - 2026-10-13

Initial release.

### Added

- `Iso9796d1Encoding`, ISO/IEC 9796-1 signatures with message recovery over
  a blinded `RsaEngine` of `tc_rsa`, as Bouncy Castle's `ISO9796d1Encoding`,
  with the pad bits of a message set through `set_pad_bits` and read through
  `pad_bits`. It turns down the moduli, messages and blocks on which Bouncy
  Castle reads out of bounds, cuts short or loops.
- `Iso9796Error`, `#[non_exhaustive]`, which wraps the error of RSA.
- The `rustcrypto` feature, which turns on that of `tc_rsa`.
- Tests with the vectors of Bouncy Castle's `ISO9796Test`, a test that every
  public item and helper documents its timing, and a doctest that signs and
  recovers a hash.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024, except with the
  `rustcrypto` feature, which follows the Rust version of the `rsa` crate and
  its dependencies.
- `no_std`, and needs `alloc`. Depends on `rand_core` 0.10, `tc_asym_cipher`
  0.1, `tc_bigint` 0.1 and `tc_rsa` 0.1. Contains no `unsafe` code.
- Variable time, only for public values. ISO 9796-1 is withdrawn: sign only a
  hash or a random value with it.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.

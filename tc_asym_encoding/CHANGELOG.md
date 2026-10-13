# Changelog

All notable changes to `tc_asym_encoding` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `Pkcs1Encoding`, PKCS#1 v1.5 over any asymmetric block cipher of
  `tc_asym_cipher`, as Bouncy Castle's `Pkcs1Encoding`: block type 2 with a
  public key and type 1 with a private one, and, through
  `with_plaintext_length`, random bytes in place of a bad block against
  Bleichenbacher's attack.
- `OaepEncoding`, OAEP with MGF1 over a `tc_digest` digest, as Bouncy Castle's
  `OaepEncoding`, with an optional label hashed by the same digest or another,
  and one `InvalidBlock` for every failure of a decrypted block.
- `EncodingError`, `#[non_exhaustive]`, which wraps the engine's error and
  writes the engine's message for it.
- Tests over RSA with the vectors of PKCS#1 v2.1 that Bouncy Castle's
  `OaepTest` runs, others worked out apart, and the key, message and bad
  blocks of Bouncy Castle's `RsaTest`; a test that every public item and every
  helper on a secret path documents its timing; and doctests for both
  encodings.

### Compatibility

- Requires Rust 1.85 or later and uses Rust edition 2024.
- `no_std`, and needs `alloc` for its block buffers. Depends on `rand_core`
  0.10, `tc_asym_cipher` 0.1, `tc_digest` 0.1 and `tc_zeroize` 0.1. Contains
  no `unsafe` code.
- Constant time in the message and the block, apart from the engine and the
  digest; whether a decrypted block is good shows through the error.
- Licensed under MIT OR Apache-2.0; both license texts are included in the
  published package.

# Changelog

All notable changes to `tc_elgamal` are documented in this file.

## 0.1.0 - Unreleased

Initial release.

### Added

- `ElGamalEngine`, after Bouncy Castle's `ElGamalEngine`, implementing
  `AsymmetricBlockCipher` and `AsymmetricBlockCipherInit` of `tc_asym_cipher`
  for both keys. It takes its random source when it is constructed, draws a
  new k for each block, and decrypts with the exponent p − 1 − x worked out
  at `init`.
- `ElGamalParameters`, `ElGamalPublicKey` and `ElGamalPrivateKey`, after
  Bouncy Castle's `ElGamalParameters`, `ElGamalPublicKeyParameters` and
  `ElGamalPrivateKeyParameters`. They are containers; `validate` runs the
  checks of `tc_dh_key`'s `DhParameters`. The private key wipes x on drop and
  has no `Debug` or `PartialEq`.
- `ElGamalKeyPairGenerator` with `ElGamalKeyGenerationParams`, after Bouncy
  Castle's `ElGamalKeyPairGenerator`, implementing `KeyPairGenerator` and
  `KeyPairGeneratorInit` over `tc_dh_key`'s `DhKeyPairGenerator`.
- `ElGamalGroupGenerator`, Bouncy Castle's `ElGamalParametersGenerator` under
  the name of `tc_dh_key`'s `DhGroupGenerator`, which it wraps, keeping p and
  g.
- `ElGamalError`, `#[non_exhaustive]`.

### Compatibility

- The block sizes are those of `tc_rsa`: decryption always gives the length
  of p in bytes, leading zeros kept, where Bouncy Castle gives only the
  significant bytes, so that PKCS#1 and OAEP wrap the engine.
- Beyond Bouncy Castle, encryption `init` turns down a public value y outside
  `[2, p - 2]`, with which the ciphertext gives away the message or its sign,
  and encryption turns down a message of 0, whose ciphertext Bouncy Castle's
  decryption turns down as weak.

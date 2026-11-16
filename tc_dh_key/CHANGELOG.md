# Changelog

All notable changes to `tc_dh_key` are documented in this file.

## 0.1.0 - 2026-11-17

Initial release.

### Added

- `DhParameters`, `DhPublicKey`, `DhPrivateKey` and `DhValidationParameters`,
  after Bouncy Castle's `DHParameters`, `DHPublicKeyParameters`,
  `DHPrivateKeyParameters` and `DHValidationParameters`. They are containers;
  `DhParameters::validate` runs the checks of Bouncy Castle's constructor and
  `DhPublicKey::validate` those of `DHPublicKeyParameters.Validate`, with the
  Legendre symbol for a safe prime. The private key wipes x on drop and has no
  `Debug` or `PartialEq`.
- `DhKeyPairGenerator` with `DhKeyGenerationParams`, after Bouncy Castle's
  `DHKeyPairGenerator`, implementing `KeyPairGenerator` and
  `KeyPairGeneratorInit` of `tc_asym_cipher`. It takes its random source when
  it is constructed and raises g^x in Montgomery form, constant time in x.
- `DhGroupGenerator` with `DhGroupGenerationParams`, after Bouncy Castle's
  `DHParametersGenerator`: a safe prime p ≡ 23 (mod 24) with g = 2 and j = 2,
  2048 bits and the certainty 100 by default.
- `standard_groups`, Bouncy Castle's `DHStandardGroups`: the MODP groups of
  RFC 2409 and 3526, the ffdhe groups of RFC 7919, and the RFC 4306 and 5996
  names for the RFC 2409 groups.
- `DhError`, `#[non_exhaustive]`.

### Compatibility

- Beyond Bouncy Castle, `DhParameters::validate` turns down a subgroup order
  below 3, with which the subgroup check of a public key would accept every
  y, and `DhKeyPairGenerator::init` turns down parameters whose private-value
  range is empty, where Bouncy Castle throws only when it generates.
  `DhGroupGenerator::init` turns down a size below 64 bits and a certainty of
  0 likewise.

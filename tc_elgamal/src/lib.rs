//! ElGamal encryption, after Bouncy Castle's `ElGamalEngine`, `ElGamalParameters`,
//! `ElGamalPublicKeyParameters`, `ElGamalPrivateKeyParameters` and their generators. As in
//! Bouncy Castle, generating keys and groups is left to the Diffie-Hellman generators of
//! `tc_dh_key`; the ElGamal ones convert to and from them.
//!
//! [`ElGamalEngine`] implements the asymmetric block cipher traits of `tc_asym_cipher`, with
//! the block sizes of `tc_rsa`, so PKCS#1 or OAEP of `tc_asym_encoding` wraps it directly.
//!
//! ```no_run
//! use tc_asym_cipher::{
//!     AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection, KeyPairGenerator,
//!     KeyPairGeneratorInit,
//! };
//! use tc_dh_key::DhGroupGenerationParams;
//! use tc_elgamal::{
//!     ElGamalEngine, ElGamalGroupGenerator, ElGamalKeyGenerationParams,
//!     ElGamalKeyPairGenerator,
//! };
//!
//! // A 2048-bit safe prime p with g = 2; this takes tens of seconds or minutes.
//! let mut group_generator = ElGamalGroupGenerator::new(rand::rng());
//! group_generator.init(&DhGroupGenerationParams::new())?;
//! let params = group_generator.generate_group()?;
//!
//! // The recipient's key pair.
//! let mut generator = ElGamalKeyPairGenerator::new(rand::rng());
//! generator.init(&ElGamalKeyGenerationParams::new(params))?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//!
//! // The sender encrypts with the public key, and the recipient decrypts with the private one.
//! let mut encryptor = ElGamalEngine::new(rand::rng());
//! encryptor.init(CipherDirection::Encrypt, &public_key)?;
//! let mut ciphertext = vec![0; encryptor.output_block_size()];
//! encryptor.process_block(b"hello", &mut ciphertext)?;
//!
//! let mut decryptor = ElGamalEngine::new(rand::rng());
//! decryptor.init(CipherDirection::Decrypt, &private_key)?;
//! let mut plaintext = vec![0; decryptor.output_block_size()];
//! let length = decryptor.process_block(&ciphertext, &mut plaintext)?;
//! assert!(plaintext[..length].ends_with(b"hello"));
//! # Ok::<(), tc_elgamal::ElGamalError>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod engine;
mod error;
mod group_generator;
mod key_pair_generator;
mod params;

pub use engine::ElGamalEngine;
pub use error::ElGamalError;
pub use group_generator::ElGamalGroupGenerator;
pub use key_pair_generator::ElGamalKeyPairGenerator;
pub use params::{
    ElGamalKeyGenerationParams, ElGamalParameters, ElGamalPrivateKey, ElGamalPublicKey,
};

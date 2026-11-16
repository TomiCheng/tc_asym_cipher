//! Diffie-Hellman domain parameters and keys, after Bouncy Castle's
//! `DHParameters`, `DHPublicKeyParameters`, `DHPrivateKeyParameters`,
//! `DHKeyPairGenerator` and `DHParametersGenerator`. Diffie-Hellman key
//! agreement and ElGamal share this layer. [`standard_groups`] holds Bouncy
//! Castle's `DHStandardGroups`, the groups of RFC 2409, 3526 and 7919.
//!
//! ```no_run
//! use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
//! use tc_dh_key::{
//!     DhGroupGenerationParams, DhGroupGenerator, DhKeyGenerationParams, DhKeyPairGenerator,
//! };
//!
//! // A 2048-bit safe prime p = 2q + 1 with g = 2; this takes tens of seconds
//! // or minutes.
//! let group_params = DhGroupGenerationParams::new();
//! let mut group_generator = DhGroupGenerator::new(rand::rng());
//! group_generator.init(&group_params)?;
//! let group = group_generator.generate_group()?;
//!
//! // A key pair in the group: y goes to the peer, x stays here and is wiped
//! // on drop.
//! let params = DhKeyGenerationParams::new(group);
//! let mut generator = DhKeyPairGenerator::new(rand::rng());
//! generator.init(&params)?;
//! let (public_key, private_key) = generator.generate_key_pair()?;
//! public_key.validate()?;
//! # Ok::<(), tc_dh_key::DhError>(())
//! ```

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
mod group_generator;
mod key_pair_generator;
mod math;
mod params;
mod small_primes;
pub mod standard_groups;

pub use error::DhError;
pub use group_generator::DhGroupGenerator;
pub use key_pair_generator::DhKeyPairGenerator;
pub use params::{
    DhGroupGenerationParams, DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey,
    DhValidationParameters,
};

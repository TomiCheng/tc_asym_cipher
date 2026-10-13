//! Shared contracts for asymmetric block ciphers and key pair generators,
//! after Bouncy Castle's `IAsymmetricBlockCipher` and
//! `IAsymmetricCipherKeyPairGenerator`.
//!
//! This crate defines how to initialize an asymmetric engine, size its
//! blocks and process one, and how to generate a key pair; it implements
//! no algorithm, padding or key format. `tc_rsa` implements the traits for
//! RSA, and `tc_asym_encoding` wraps any engine that implements them in
//! PKCS#1 v1.5 or OAEP.
//!
//! # Using an engine
//!
//! Select a [`CipherDirection`], call [`AsymmetricBlockCipherInit::init`]
//! with a key, then size buffers with
//! [`AsymmetricBlockCipher::input_block_size`] and
//! [`AsymmetricBlockCipher::output_block_size`] and transform one block with
//! [`AsymmetricBlockCipher::process_block`]. Unlike a block cipher's, the
//! input is of any length up to the input block, and the two sizes may
//! differ with the direction and the encoding. A key tells through
//! [`AsymmetricKeyParams`] whether it is private, which an encoding reads
//! to pick its format.
//!
//! A key pair generator takes its parameters, random source included,
//! through [`KeyPairGeneratorInit::init`], and
//! [`KeyPairGenerator::generate_key_pair`] then returns the public and the
//! private key.
//!
//! Accepted keys, the state left by a rejected initialization and every
//! timing guarantee belong to the engine or generator, not to these traits.
//!
//! # Implementing an engine
//!
//! An engine implements [`AsymmetricBlockCipherInit`] for the keys it
//! accepts and [`AsymmetricBlockCipher`] for processing. The toy engine
//! below XORs up to four bytes with the byte its key holds; it shows the
//! contract and is not a cipher.
//!
//! ```
//! use core::fmt;
//! use tc_asym_cipher::{
//!     AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
//! };
//!
//! #[derive(Debug)]
//! struct ToyError;
//!
//! impl fmt::Display for ToyError {
//!     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//!         f.write_str("toy engine failure")
//!     }
//! }
//!
//! impl core::error::Error for ToyError {}
//!
//! struct ToyKey {
//!     private: bool,
//!     mask: u8,
//! }
//!
//! impl AsymmetricKeyParams for ToyKey {
//!     fn is_private_key(&self) -> bool {
//!         self.private
//!     }
//! }
//!
//! struct Toy {
//!     mask: Option<u8>,
//! }
//!
//! impl AsymmetricBlockCipherInit<ToyKey> for Toy {
//!     type Error = ToyError;
//!
//!     fn init(&mut self, _direction: CipherDirection, key: &ToyKey) -> Result<(), ToyError> {
//!         self.mask = Some(key.mask);
//!         Ok(())
//!     }
//! }
//!
//! impl AsymmetricBlockCipher for Toy {
//!     type Error = ToyError;
//!
//!     fn input_block_size(&self) -> usize {
//!         4
//!     }
//!
//!     fn output_block_size(&self) -> usize {
//!         4
//!     }
//!
//!     fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ToyError> {
//!         let mask = self.mask.ok_or(ToyError)?;
//!         if input.len() > self.input_block_size() || output.len() < self.output_block_size() {
//!             return Err(ToyError);
//!         }
//!         for (out, byte) in output.iter_mut().zip(input) {
//!             *out = byte ^ mask;
//!         }
//!         Ok(input.len())
//!     }
//! }
//!
//! let mut engine = Toy { mask: None };
//! let mut output = [0; 4];
//! assert!(engine.process_block(b"abc", &mut output).is_err());
//!
//! let public = ToyKey { private: false, mask: 0x20 };
//! engine.init(CipherDirection::Encrypt, &public)?;
//! assert_eq!(engine.process_block(b"abc", &mut output)?, 3);
//! assert_eq!(&output[..3], b"ABC");
//! # Ok::<(), ToyError>(())
//! ```
//!
//! # Features
//!
//! The crate is `no_std`, needs no allocator and has no features or
//! dependencies.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod cipher_direction;
mod traits;

pub use cipher_direction::CipherDirection;
pub use traits::AsymmetricBlockCipher;
pub use traits::AsymmetricBlockCipherInit;
pub use traits::AsymmetricKeyParams;
pub use traits::KeyPairGenerator;
pub use traits::KeyPairGeneratorInit;

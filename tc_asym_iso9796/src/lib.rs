//! ISO/IEC 9796 digital signatures with message recovery, after Bouncy
//! Castle: part 1, its `ISO9796d1Encoding`, as [`Iso9796d1Encoding`]. It
//! reads the modulus of an RSA key, and so takes RSA in, unlike the
//! encodings of `tc_asym_encoding` that wrap any asymmetric engine. Part 2,
//! Bouncy Castle's `Iso9796d2Signer`, is not implemented yet.

#![no_std]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

mod error;
mod iso9796d1_encoding;

pub use error::Iso9796Error;
pub use iso9796d1_encoding::Iso9796d1Encoding;

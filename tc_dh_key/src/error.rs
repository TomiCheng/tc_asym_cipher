//! The errors of the parameters, keys and generators.

use core::fmt;

/// The parameters and keys Bouncy Castle's DH parameter classes turn down,
/// and the failures of the generators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DhError {
    /// A generator was asked to generate before `init`.
    NotInitialized,
    /// p is not an odd number above 2.
    InvalidModulus,
    /// p is wider than 16384 bits, the default of Bouncy Castle's
    /// `DHMaxSize`.
    ModulusTooLarge,
    /// g is not in `[2, p - 2]`.
    InvalidGenerator,
    /// q is below 3, or has no fewer bits than p and so cannot divide p − 1.
    InvalidSubgroupOrder,
    /// m has no fewer bits than p; or l, when set, has no fewer bits than p
    /// or is below m; or, without l, the range `[2^(m - 1), q - 2]` of the
    /// private value is empty.
    InvalidPrivateValueLength,
    /// The cofactor j is below 2.
    InvalidCofactor,
    /// The public value y is not in `[2, p - 2]`.
    InvalidPublicValue,
    /// The public value y is not in the subgroup of order q.
    PublicValueOutsideSubgroup,
    /// The p to generate is narrower than 64 bits.
    InvalidSize,
    /// The certainty of the primality test is 0.
    InvalidCertainty,
}

impl fmt::Display for DhError {
    /// Writes the message. Constant time; the output takes what the
    /// formatter takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotInitialized => "the generator is not initialized",
            Self::InvalidModulus => "field must be an odd prime",
            Self::ModulusTooLarge => "DH modulus out of range",
            Self::InvalidGenerator => "generator must be in the range [2, p - 2]",
            Self::InvalidSubgroupOrder => "q must be at least 3 and shorter than p",
            Self::InvalidPrivateValueLength => {
                "private value length must be below the bit length of p and l not below m"
            }
            Self::InvalidCofactor => "subgroup factor must be >= 2",
            Self::InvalidPublicValue => "invalid DH public key",
            Self::PublicValueOutsideSubgroup => "value does not appear to be in correct group",
            Self::InvalidSize => "size < 64",
            Self::InvalidCertainty => "certainty must be at least 1",
        })
    }
}

impl core::error::Error for DhError {}

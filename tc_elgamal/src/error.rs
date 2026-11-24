use core::fmt;
use tc_dh_key::DhError;

/// What the ElGamal checks, generators and engine turn down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ElGamalError {
    /// An operation or a generation before `init`.
    NotInitialized,
    /// Parameters, or generator settings, that the Diffie-Hellman checks turn down; the
    /// reason is inside.
    InvalidParameters(DhError),
    /// A private key to encrypt or a public key to decrypt.
    WrongKeyForDirection,
    /// A public value y outside `[2, p - 2]`, or a private value x above p − 2.
    InvalidKey,
    /// A plaintext longer than the input block.
    InputTooLarge,
    /// A plaintext of 0, whose φ would be 0 and turned down as weak on decryption, so it is
    /// turned down on encryption.
    InputTooSmall,
    /// A ciphertext that is not twice the length of p in bytes.
    InvalidCiphertextLength,
    /// A ciphertext whose γ or φ is outside `[2, p - 2]`.
    WeakCiphertext,
    /// An output buffer shorter than the output block.
    OutputTooShort,
}

impl From<DhError> for ElGamalError {
    /// Wraps the reason the Diffie-Hellman checks give. Constant time.
    fn from(error: DhError) -> Self {
        Self::InvalidParameters(error)
    }
}

impl fmt::Display for ElGamalError {
    /// Writes the message of the error. Constant time; the formatter decides how long the
    /// writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInitialized => f.write_str("ElGamal engine not initialised"),
            Self::InvalidParameters(error) => write!(f, "invalid ElGamal parameters: {error}"),
            Self::WrongKeyForDirection => f.write_str(
                "ElGamal needs a public key for encryption and a private key for decryption",
            ),
            Self::InvalidKey => f.write_str("invalid ElGamal key"),
            Self::InputTooLarge => f.write_str("input too large for ElGamal cipher"),
            Self::InputTooSmall => f.write_str("input too small for ElGamal cipher"),
            Self::InvalidCiphertextLength => {
                f.write_str("input is the wrong size for ElGamal cipher")
            }
            Self::WeakCiphertext => f.write_str("ElGamal ciphertext element is weak"),
            Self::OutputTooShort => f.write_str("output buffer too short for ElGamal cipher"),
        }
    }
}

impl core::error::Error for ElGamalError {}

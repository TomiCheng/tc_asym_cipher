//! The data a modulus was generated from.

use alloc::vec::Vec;

/// The seed and counter p was generated from, as Bouncy Castle's
/// `DHValidationParameters` holds them, by which X9.42 verifies where the
/// parameters came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhValidationParameters {
    seed: Vec<u8>,
    counter: u32,
}

impl DhValidationParameters {
    /// Wraps the seed and the counter, unchecked. Constant time.
    pub fn new(seed: Vec<u8>, counter: u32) -> Self {
        Self { seed, counter }
    }

    /// The seed. Constant time.
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// The counter. Constant time.
    pub fn counter(&self) -> u32 {
        self.counter
    }
}

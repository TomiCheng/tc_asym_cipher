//! The parameters of group generation.

// The defaults Bouncy Castle's `RsaKeyPairGenerator` uses: 2048 bits and the
// certainty 100.
const DEFAULT_SIZE: u32 = 2048;
const DEFAULT_CERTAINTY: u32 = 100;

/// What a Diffie-Hellman group is generated to, as Bouncy Castle's
/// `DHParametersGenerator.Init` takes it, without its random source: the size
/// of p in bits and the certainty of the primality test. The random source
/// comes with the generator, so the parameters are data alone. Bouncy Castle
/// has no defaults; these are 2048 bits and the certainty 100. It is a
/// container only: nothing is checked when it is built, and the generator
/// checks it when it is initialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhGroupGenerationParams {
    size: u32,
    certainty: u32,
}

impl DhGroupGenerationParams {
    /// The defaults: a p of 2048 bits, tested to the certainty 100. Constant
    /// time.
    pub const fn new() -> Self {
        Self {
            size: DEFAULT_SIZE,
            certainty: DEFAULT_CERTAINTY,
        }
    }

    /// The parameters with a p of `size` bits. Constant time.
    pub const fn with_size(mut self, size: u32) -> Self {
        self.size = size;
        self
    }

    /// The parameters with the primality test run to `certainty`, so that a
    /// composite passes with a probability of at most 2^-certainty. Constant
    /// time.
    pub const fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }

    /// The size of p in bits. Constant time.
    pub const fn size(&self) -> u32 {
        self.size
    }

    /// The certainty of the primality test. Constant time.
    pub const fn certainty(&self) -> u32 {
        self.certainty
    }
}

/// The defaults of [`new`](DhGroupGenerationParams::new).
impl Default for DhGroupGenerationParams {
    /// As [`new`](Self::new). Constant time.
    fn default() -> Self {
        Self::new()
    }
}

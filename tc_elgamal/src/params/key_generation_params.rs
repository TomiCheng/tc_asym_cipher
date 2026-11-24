use crate::ElGamalParameters;

/// Bouncy Castle's `ElGamalKeyGenerationParameters` without the random source, which the
/// generator takes when it is constructed.
#[derive(Clone)]
pub struct ElGamalKeyGenerationParams {
    pub(crate) params: ElGamalParameters,
}

impl ElGamalKeyGenerationParams {
    /// Holds the parameters, which the generator's `init` checks. Constant time.
    pub fn new(params: ElGamalParameters) -> Self {
        Self { params }
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &ElGamalParameters {
        &self.params
    }

    /// Bouncy Castle's `GetStrength`: l when it is set, the bit length of p otherwise.
    /// Constant time.
    pub fn strength(&self) -> u32 {
        match self.params.l() {
            0 => self.params.p().bits(),
            l => l,
        }
    }
}

//! The parameters of key pair generation.

use crate::DhParameters;

/// What a Diffie-Hellman key pair is generated over, as Bouncy Castle's
/// `DHKeyGenerationParameters` holds it, without its random source, which
/// comes with the generator. It is a container only: the generator checks the
/// parameters when it is initialized.
#[derive(Clone, Debug)]
pub struct DhKeyGenerationParams {
    pub(crate) params: DhParameters,
}

impl DhKeyGenerationParams {
    /// Wraps `params`, unchecked. Constant time.
    pub fn new(params: DhParameters) -> Self {
        Self { params }
    }

    /// The domain parameters. Constant time.
    pub fn params(&self) -> &DhParameters {
        &self.params
    }

    /// Bouncy Castle's `GetStrength`: l when it is set, otherwise the bit
    /// length of p. Constant time.
    pub fn strength(&self) -> u32 {
        match self.params.l() {
            0 => self.params.p().bits(),
            l => l,
        }
    }
}

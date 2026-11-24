use crate::{ElGamalError, ElGamalParameters};
use rand_core::CryptoRng;
use tc_dh_key::{DhGroupGenerationParams, DhGroupGenerator};

/// Bouncy Castle's `ElGamalParametersGenerator`, named after `DhGroupGenerator` of
/// `tc_dh_key`, which it wraps: the safe prime p of Diffie-Hellman with g = 2, keeping p and g
/// alone. Generation is slow; 2048 bits can take tens of seconds or minutes.
pub struct ElGamalGroupGenerator<R> {
    inner: DhGroupGenerator<R>,
}

impl<R> ElGamalGroupGenerator<R> {
    /// A generator that draws from `rng`, before `init`. Constant time.
    pub fn new(rng: R) -> Self {
        Self {
            inner: DhGroupGenerator::new(rng),
        }
    }

    /// Bouncy Castle's `Init`: the bit length of p and the certainty of the primality tests.
    /// A length below 64 bits or a certainty of 0 is an error. Constant time.
    pub fn init(&mut self, params: &DhGroupGenerationParams) -> Result<(), ElGamalError> {
        Ok(self.inner.init(params)?)
    }
}

impl<R: CryptoRng> ElGamalGroupGenerator<R> {
    /// Bouncy Castle's `GenerateParameters`: a safe prime p ≡ 7 (mod 8) with g = 2. Variable
    /// time, only for public values: the group is public.
    pub fn generate_group(&mut self) -> Result<ElGamalParameters, ElGamalError> {
        let group = self.inner.generate_group()?;
        Ok(ElGamalParameters::new(group.p().clone(), group.g().clone()))
    }
}

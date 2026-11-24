use crate::ElGamalError;
use tc_bigint::PaddedBigUint;
use tc_dh_key::DhParameters;

/// Bouncy Castle's `ElGamalParameters`: the modulus p, the generator g, and the bit length l
/// of the private value, 0 when it is not set.
///
/// A container, not checked when it is built; the generators' and the engine's `init` call
/// [`validate`](Self::validate). Equality compares p, g and l, as Bouncy Castle's does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalParameters {
    p: PaddedBigUint,
    g: PaddedBigUint,
    l: u32,
}

impl ElGamalParameters {
    /// Parameters with no length set for the private value. Constant time.
    pub fn new(p: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self { p, g, l: 0 }
    }

    /// Sets the bit length l of the private value. Constant time.
    pub fn with_l(mut self, l: u32) -> Self {
        self.l = l;
        self
    }

    /// The modulus p. Constant time.
    pub fn p(&self) -> &PaddedBigUint {
        &self.p
    }

    /// The generator g. Constant time.
    pub fn g(&self) -> &PaddedBigUint {
        &self.g
    }

    /// The bit length l of the private value; 0 when it is not set. Constant time.
    pub fn l(&self) -> u32 {
        self.l
    }

    /// Checks that p is an odd number above 2, g is in `[2, p - 2]` and l is below the bit
    /// length of p. Bouncy Castle's `ElGamalParameters` checks nothing and leaves the checks
    /// to `DHParameters` when it generates a key; these are the same checks. Variable time,
    /// only for public values: the parameters are public.
    pub fn validate(&self) -> Result<(), ElGamalError> {
        Ok(self.to_dh().validate()?)
    }

    /// The Diffie-Hellman parameters Bouncy Castle's `ElGamalKeyPairGenerator` converts to: no
    /// q, m = 0 and l as set. Constant time.
    pub(crate) fn to_dh(&self) -> DhParameters {
        DhParameters::new(self.p.clone(), self.g.clone())
            .with_m(0)
            .with_l(self.l)
    }
}

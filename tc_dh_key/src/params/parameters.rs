//! Diffie-Hellman domain parameters.

use crate::{DhError, DhValidationParameters};
use tc_bigint::PaddedBigUint;

// Bouncy Castle's `DefaultMinimumLength`: the least bits of a private value
// when m is not set.
const DEFAULT_MINIMUM_LENGTH: u32 = 160;

/// Diffie-Hellman domain parameters, as Bouncy Castle's `DHParameters` holds
/// them: the modulus p, the generator g and, optionally, the subgroup order q,
/// the least bit length m and the set bit length l of a private value, the
/// cofactor j, and the data p was generated from.
///
/// It is a container only: nothing is checked when it is built.
/// [`validate`](Self::validate) runs the checks of Bouncy Castle's
/// constructor; the generators' `init` and the operations over the
/// parameters call it. Equality compares p, g and q alone, as Bouncy Castle's
/// does.
#[derive(Clone, Debug)]
pub struct DhParameters {
    p: PaddedBigUint,
    g: PaddedBigUint,
    q: Option<PaddedBigUint>,
    m: Option<u32>,
    l: u32,
    j: Option<PaddedBigUint>,
    validation: Option<DhValidationParameters>,
}

impl DhParameters {
    /// Parameters of p and g alone. Constant time.
    pub fn new(p: PaddedBigUint, g: PaddedBigUint) -> Self {
        Self {
            p,
            g,
            q: None,
            m: None,
            l: 0,
            j: None,
            validation: None,
        }
    }

    /// The parameters with the subgroup order `q`. Constant time.
    pub fn with_q(mut self, q: PaddedBigUint) -> Self {
        self.q = Some(q);
        self
    }

    /// The parameters with `m` as the least bit length of a private value.
    /// Constant time.
    pub fn with_m(mut self, m: u32) -> Self {
        self.m = Some(m);
        self
    }

    /// The parameters with `l` as the bit length of a private value, or none
    /// for 0. Constant time.
    pub fn with_l(mut self, l: u32) -> Self {
        self.l = l;
        self
    }

    /// The parameters with the cofactor `j`. Constant time.
    pub fn with_j(mut self, j: PaddedBigUint) -> Self {
        self.j = Some(j);
        self
    }

    /// The parameters with the data p was generated from. Constant time.
    pub fn with_validation(mut self, validation: DhValidationParameters) -> Self {
        self.validation = Some(validation);
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

    /// The subgroup order q. Constant time.
    pub fn q(&self) -> Option<&PaddedBigUint> {
        self.q.as_ref()
    }

    /// The least bit length m of a private value; when it is not set, Bouncy
    /// Castle's `GetDefaultMParam`: 160 when l is 0, otherwise the smaller of
    /// l and 160. Constant time.
    pub fn m(&self) -> u32 {
        self.m.unwrap_or(match self.l {
            0 => DEFAULT_MINIMUM_LENGTH,
            l => l.min(DEFAULT_MINIMUM_LENGTH),
        })
    }

    /// The bit length l of a private value, 0 when it is not set. Constant
    /// time.
    pub fn l(&self) -> u32 {
        self.l
    }

    /// The cofactor j. Constant time.
    pub fn j(&self) -> Option<&PaddedBigUint> {
        self.j.as_ref()
    }

    /// The data p was generated from. Constant time.
    pub fn validation(&self) -> Option<&DhValidationParameters> {
        self.validation.as_ref()
    }

    /// The checks of Bouncy Castle's `DHParameters` constructor: p is an odd
    /// number above 2, g is in `[2, p - 2]`, q has fewer bits than p, m is below
    /// the bit length of p, l, when set, is below it and not below m, and j is
    /// at least 2. It also turns down a q below 3, which Bouncy Castle lets
    /// through: with q = 0 the subgroup check of [`DhPublicKey::validate`]
    /// would accept every y. Whether p and q are prime is not checked, as in
    /// Bouncy Castle. Variable time: the parameters are public.
    ///
    /// [`DhPublicKey::validate`]: crate::DhPublicKey::validate
    pub fn validate(&self) -> Result<(), DhError> {
        let two = PaddedBigUint::from(2u8);
        if !self.p.bit(0) || self.p <= two {
            return Err(DhError::InvalidModulus);
        }
        if self.g < two || self.g > &self.p - 2u32 {
            return Err(DhError::InvalidGenerator);
        }
        let p_bits = self.p.bits();
        let three = PaddedBigUint::from(3u8);
        if self
            .q
            .as_ref()
            .is_some_and(|q| *q < three || q.bits() >= p_bits)
        {
            return Err(DhError::InvalidSubgroupOrder);
        }
        let m = self.m();
        if m >= p_bits || (self.l != 0 && (self.l >= p_bits || self.l < m)) {
            return Err(DhError::InvalidPrivateValueLength);
        }
        if self.j.as_ref().is_some_and(|j| *j < two) {
            return Err(DhError::InvalidCofactor);
        }
        Ok(())
    }
}

/// Equality of p, g and q.
impl PartialEq for DhParameters {
    /// Compares p, g and q alone, as Bouncy Castle's `Equals` does. Variable
    /// time: the parameters are public.
    fn eq(&self, other: &Self) -> bool {
        self.p == other.p && self.g == other.g && self.q == other.q
    }
}

impl Eq for DhParameters {}

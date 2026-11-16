//! Diffie-Hellman public keys.

use crate::math::legendre;
use crate::{DhError, DhParameters};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};

// The default of Bouncy Castle's `Properties.DHMaxSize`: the most bits of p.
const MAX_MODULUS_BITS: u32 = 16384;

/// A Diffie-Hellman public key, as Bouncy Castle's `DHPublicKeyParameters`
/// holds it: the public value y = g^x mod p and its parameters.
///
/// It is a container only: nothing is checked when it is built.
/// [`validate`](Self::validate) runs the checks of Bouncy Castle's
/// constructor, and the operations that take a public key call it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DhPublicKey {
    y: PaddedBigUint,
    params: DhParameters,
}

impl DhPublicKey {
    /// Wraps `y` and `params`, unchecked. Constant time.
    pub fn new(y: PaddedBigUint, params: DhParameters) -> Self {
        Self { y, params }
    }

    /// The public value y. Constant time.
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// The domain parameters. Constant time.
    pub fn params(&self) -> &DhParameters {
        &self.params
    }

    /// Bouncy Castle's `DHPublicKeyParameters.Validate`: p has at most 16384
    /// bits and y is in `[2, p - 2]`; with q, y is in the subgroup of order q,
    /// told by the Legendre symbol when p = 2q + 1 and otherwise by whether
    /// y^q mod p is 1. The parameters themselves are checked by
    /// [`DhParameters::validate`]. Variable time: y and the parameters are
    /// public.
    pub fn validate(&self) -> Result<(), DhError> {
        let p = BigUint::from(self.params.p().clone());
        if p.bits() > MAX_MODULUS_BITS {
            return Err(DhError::ModulusTooLarge);
        }
        let y = BigUint::from(self.y.clone());
        let two = BigUint::from(2u8);
        if p <= two || y < two || y > &p - 2u32 {
            return Err(DhError::InvalidPublicValue);
        }
        let Some(q) = self.params.q() else {
            return Ok(());
        };
        let q = BigUint::from(q.clone());
        let in_subgroup = if p.bit(0) && p.bits() - 1 == q.bits() && (&p >> 1) == q {
            legendre(&y, &p) == 1
        } else {
            let modulus = NonZero::new(p).expect("p is above 2");
            y.mod_pow(&q, &modulus) == BigUint::from(1u8)
        };
        if !in_subgroup {
            return Err(DhError::PublicValueOutsideSubgroup);
        }
        Ok(())
    }
}

use crate::ElGamalParameters;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;

/// Bouncy Castle's `ElGamalPublicKeyParameters`: the public value y = g^x mod p with its
/// parameters. A container, not checked when it is built; the engine's `init` for
/// encryption checks it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElGamalPublicKey {
    y: PaddedBigUint,
    params: ElGamalParameters,
}

impl ElGamalPublicKey {
    /// Holds y and the parameters, unchecked. Constant time.
    pub fn new(y: PaddedBigUint, params: ElGamalParameters) -> Self {
        Self { y, params }
    }

    /// The public value y. Constant time.
    pub fn y(&self) -> &PaddedBigUint {
        &self.y
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &ElGamalParameters {
        &self.params
    }
}

impl AsymmetricKeyParams for ElGamalPublicKey {
    /// A public key. Constant time.
    fn is_private_key(&self) -> bool {
        false
    }
}

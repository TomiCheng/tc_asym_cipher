use crate::ElGamalParameters;
use tc_asym_cipher::AsymmetricKeyParams;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// Bouncy Castle's `ElGamalPrivateKeyParameters`: the private value x with its parameters,
/// x wiped on drop. A container, not checked when it is built; the engine's `init` for
/// decryption checks it.
///
/// It has no `Debug` or `PartialEq`, so that x is neither printed nor compared in variable
/// time.
#[derive(Clone)]
pub struct ElGamalPrivateKey {
    x: PaddedBigUint,
    params: ElGamalParameters,
}

impl ElGamalPrivateKey {
    /// Holds x and the parameters, unchecked. Constant time.
    pub fn new(x: PaddedBigUint, params: ElGamalParameters) -> Self {
        Self { x, params }
    }

    /// The private value x. Constant time.
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// The parameters. Constant time.
    pub fn params(&self) -> &ElGamalParameters {
        &self.params
    }
}

impl AsymmetricKeyParams for ElGamalPrivateKey {
    /// A private key. Constant time.
    fn is_private_key(&self) -> bool {
        true
    }
}

impl Drop for ElGamalPrivateKey {
    /// Wipes x. Constant time.
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

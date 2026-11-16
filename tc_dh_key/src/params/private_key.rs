//! Diffie-Hellman private keys.

use crate::DhParameters;
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

/// A Diffie-Hellman private key, as Bouncy Castle's `DHPrivateKeyParameters`
/// holds it: the private value x and its parameters. x is wiped on drop and,
/// as in Bouncy Castle, not checked.
///
/// It has no `Debug` and no `PartialEq`, so that x is neither printed nor
/// compared in variable time.
#[derive(Clone)]
pub struct DhPrivateKey {
    x: PaddedBigUint,
    params: DhParameters,
}

impl DhPrivateKey {
    /// Wraps `x` and `params`, unchecked. Constant time.
    pub fn new(x: PaddedBigUint, params: DhParameters) -> Self {
        Self { x, params }
    }

    /// The private value x. Constant time.
    pub fn x(&self) -> &PaddedBigUint {
        &self.x
    }

    /// The domain parameters. Constant time.
    pub fn params(&self) -> &DhParameters {
        &self.params
    }
}

/// Wiping of the private value.
impl Drop for DhPrivateKey {
    /// Wipes x. Constant time.
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

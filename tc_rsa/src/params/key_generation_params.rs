//! The parameters of RSA key generation.

/// What an RSA key pair is generated to, as Bouncy Castle's
/// `RsaKeyGenerationParameters` holds it, without its random source: the
/// public exponent, the size of the modulus in bits, and the certainty the
/// primes are tested to. The random source comes with the generator, so the
/// parameters are data alone, which can be kept, copied and used again.
///
/// The exponent is a `u32`, where Bouncy Castle takes any integer: it is
/// 65537 all but always, and keys from elsewhere, whose exponent may be
/// wider, come in as [`RsaKeyOwned`](crate::RsaKeyOwned) instead. It is a
/// container only: nothing is checked when it is built, and the generator
/// checks it when it is initialized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsaKeyGenerationParams {
    public_exponent: u32,
    strength: u32,
    certainty: u32,
}

impl RsaKeyGenerationParams {
    /// The defaults: the public exponent 65537, a modulus of 2048 bits, and
    /// primes tested to the certainty 100, as Bouncy Castle's defaults are.
    /// The `with_*` methods change them. Constant time.
    pub const fn new() -> Self {
        Self {
            public_exponent: 65537,
            strength: 2048,
            certainty: 100,
        }
    }

    /// The parameters with the public exponent `e`. Constant time.
    pub const fn with_public_exponent(mut self, e: u32) -> Self {
        self.public_exponent = e;
        self
    }

    /// The parameters with a modulus of `strength` bits. Constant time.
    pub const fn with_strength(mut self, strength: u32) -> Self {
        self.strength = strength;
        self
    }

    /// The parameters with primes tested to `certainty`. Constant time.
    pub const fn with_certainty(mut self, certainty: u32) -> Self {
        self.certainty = certainty;
        self
    }

    /// The public exponent `e`. Constant time.
    pub const fn public_exponent(&self) -> u32 {
        self.public_exponent
    }

    /// The size of the modulus, in bits. Constant time.
    pub const fn strength(&self) -> u32 {
        self.strength
    }

    /// The certainty the primes are tested to. Constant time.
    pub const fn certainty(&self) -> u32 {
        self.certainty
    }
}

/// Through [`new`](RsaKeyGenerationParams::new). Constant time.
impl Default for RsaKeyGenerationParams {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RsaKeyGenerationParams;

    #[test]
    fn the_defaults_are_those_of_bouncy_castle_and_with_changes_one_field() {
        let params = RsaKeyGenerationParams::new();
        assert_eq!(params.public_exponent(), 65537);
        assert_eq!(params.strength(), 2048);
        assert_eq!(params.certainty(), 100);
        assert_eq!(params, RsaKeyGenerationParams::default());

        let changed = params
            .with_public_exponent(3)
            .with_strength(1024)
            .with_certainty(40);
        assert_eq!(
            (
                changed.public_exponent(),
                changed.strength(),
                changed.certainty()
            ),
            (3, 1024, 40)
        );
    }
}

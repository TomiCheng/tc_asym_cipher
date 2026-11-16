//! RSA key pair generation through the RustCrypto `rsa` crate.

use rand_core::CryptoRng;
use rsa::{BoxedUint, RsaPrivateKey, RsaPublicKey};
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

use crate::{RsaError, RsaKeyGenerationParams, RsaKeyRustCrypto, RsaPrivateCrtKeyRustCrypto};

/// The smallest modulus `rsa` generates, in bits.
const MIN_STRENGTH: u32 = 1024;

/// The largest modulus `rsa` takes, in bits, as `RsaPublicKey::MAX_SIZE` is.
const MAX_STRENGTH: u32 = RsaPublicKey::MAX_SIZE as u32;

/// Generates RSA key pairs through the RustCrypto `rsa` crate, as
/// [`RsaKeyRustCrypto`] and [`RsaPrivateCrtKeyRustCrypto`]. It draws from
/// the random source `R` it is constructed with, owned, or borrowed as
/// `&mut R`, which `rsa` takes as it is, as both use `rand_core` 0.10, and
/// takes the [`RsaKeyGenerationParams`] the generator of this crate takes.
/// `rsa` tests its primes as it sees fit, so the certainty of the
/// parameters is checked but not used.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaKeyGenerationParams, RsaKeyPairGeneratorRustCrypto};
///
/// // Drawn from the system's random source, to the defaults: a 2048-bit
/// // modulus and the public exponent 65537; `with_strength` and the other
/// // `with_*` methods change them.
/// let mut generator = RsaKeyPairGeneratorRustCrypto::new(rand::rng());
/// generator.init(&RsaKeyGenerationParams::new())?;
///
/// // The keys of `rsa`, wrapped as the keys of this crate: the public key
/// // holds `n` and `e`, the private one adds `d` and the values of the CRT.
/// let (public, private) = generator.generate_key_pair()?;
/// # Ok::<(), tc_rsa::RsaError>(())
/// ```
pub struct RsaKeyPairGeneratorRustCrypto<R> {
    rng: R,
    params: Option<RsaKeyGenerationParams>,
}

impl<R> RsaKeyPairGeneratorRustCrypto<R> {
    /// A generator drawing from `rng`, to be initialized before it
    /// generates. Constant time.
    pub const fn new(rng: R) -> Self {
        Self { rng, params: None }
    }
}

/// Keeps a copy of the parameters once they are checked: an odd public
/// exponent of at least three, a certainty of at least one, and a modulus
/// of 1024 to 8192 bits, the sizes `rsa` generates and takes. Variable
/// time: only for public values, as the parameters are.
impl<R> KeyPairGeneratorInit<RsaKeyGenerationParams> for RsaKeyPairGeneratorRustCrypto<R> {
    type Error = RsaError;

    fn init(&mut self, params: &RsaKeyGenerationParams) -> Result<(), RsaError> {
        let e = params.public_exponent();
        if e < 3 || e & 1 == 0 {
            return Err(RsaError::InvalidPublicExponent);
        }
        if params.certainty() == 0 {
            return Err(RsaError::InvalidCertainty);
        }
        if !(MIN_STRENGTH..=MAX_STRENGTH).contains(&params.strength()) {
            return Err(RsaError::InvalidStrength);
        }
        self.params = Some(*params);
        Ok(())
    }
}

/// Generates a key pair through `RsaPrivateKey::new_with_exp`. Variable
/// time, as key generation everywhere is: how many candidates `rsa` draws
/// shows in the running time.
impl<R: CryptoRng> KeyPairGenerator for RsaKeyPairGeneratorRustCrypto<R> {
    type PublicKey = RsaKeyRustCrypto;
    type PrivateKey = RsaPrivateCrtKeyRustCrypto;
    type Error = RsaError;

    fn generate_key_pair(
        &mut self,
    ) -> Result<(RsaKeyRustCrypto, RsaPrivateCrtKeyRustCrypto), RsaError> {
        let params = self.params.ok_or(RsaError::NotInitialized)?;
        let (e, strength) = (params.public_exponent(), params.strength());
        // The checks at init leave `rsa` no size or exponent to turn down.
        let key = RsaPrivateKey::new_with_exp(
            &mut self.rng,
            strength as usize,
            BoxedUint::from(u64::from(e)),
        )
        .map_err(|_| RsaError::InvalidStrength)?;
        let public = RsaKeyRustCrypto::new(key.to_public_key());
        Ok((public, RsaPrivateCrtKeyRustCrypto::new(key)?))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

    use super::RsaKeyPairGeneratorRustCrypto;
    use crate::{RsaError, RsaKeyGenerationParams, RsaKeyParams, RsaPrivateCrtKeyParams};

    fn params() -> RsaKeyGenerationParams {
        RsaKeyGenerationParams::new()
    }

    fn generator() -> RsaKeyPairGeneratorRustCrypto<StdRng> {
        RsaKeyPairGeneratorRustCrypto::new(StdRng::seed_from_u64(1))
    }

    #[test]
    fn a_generated_pair_shares_its_modulus_and_exponent() {
        let mut generator = generator();
        generator
            .init(&params().with_strength(1024).with_public_exponent(3))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.exponent(), private.public_exponent());
        assert_eq!(public.modulus().bit_width(), 1024);
    }

    #[test]
    fn init_turns_down_what_rsa_cannot_generate() {
        let init = |params: RsaKeyGenerationParams| generator().init(&params);
        assert_eq!(
            init(params().with_public_exponent(4)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(params().with_certainty(0)),
            Err(RsaError::InvalidCertainty)
        );
        assert_eq!(
            init(params().with_strength(512)),
            Err(RsaError::InvalidStrength)
        );
        assert_eq!(
            init(params().with_strength(8200)),
            Err(RsaError::InvalidStrength)
        );
    }

    #[test]
    fn a_generator_not_yet_initialized_generates_nothing() {
        let mut generator = generator();
        assert_eq!(
            generator.generate_key_pair().err(),
            Some(RsaError::NotInitialized)
        );
    }
}

//! RSA key pair generation, as Bouncy Castle's `RsaKeyPairGenerator` runs
//! it, over `PaddedBigUint`.

use core::marker::PhantomData;

use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::PaddedBigUint;
use tc_zeroize::Zeroize;

use super::generation::{check, generate};
use crate::{RsaError, RsaKeyGenerationParams, RsaKeyOwned, RsaPrivateCrtKeyOwned};

/// Generates RSA key pairs as Bouncy Castle's `RsaKeyPairGenerator` does,
/// the modulus and the exponents as integers of type `T`, the primes and
/// the values modulo them as integers of type `H`. It works in
/// `PaddedBigUint`, which takes `alloc`, and converts the key into `T` and
/// `H` at the end. It draws from the random source `R` it is constructed
/// with, owned, or borrowed as `&mut R`, and is initialized with
/// [`RsaKeyGenerationParams`], which hold data alone.
///
/// ```
/// use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_bigint::{FixedBigUint, Word};
/// use tc_rsa::{RsaKeyGenerationParams, RsaKeyPairGenerator};
///
/// // A 2048-bit modulus, with its primes at half that width, so that the
/// // CRT runs on integers half as wide; the widths follow from the limbs.
/// type U2048 = FixedBigUint<{ 2048 / Word::BITS as usize }>;
/// type U1024 = FixedBigUint<{ 1024 / Word::BITS as usize }>;
///
/// // Drawn from the system's random source, to the defaults: a 2048-bit
/// // modulus and the public exponent 65537; `with_strength` and the other
/// // `with_*` methods change them.
/// let mut generator = RsaKeyPairGenerator::<U2048, U1024, _>::new(rand::rng());
/// generator.init(&RsaKeyGenerationParams::new())?;
///
/// // The public key holds `n` and `e`; the private one adds `d` and the
/// // values of the CRT.
/// let (public, private) = generator.generate_key_pair()?;
/// # Ok::<(), tc_rsa::RsaError>(())
/// ```
pub struct RsaKeyPairGenerator<T, H, R> {
    rng: R,
    params: Option<RsaKeyGenerationParams>,
    integers: PhantomData<(T, H)>,
}

impl<T, H, R> RsaKeyPairGenerator<T, H, R> {
    /// A generator drawing from `rng`, to be initialized before it
    /// generates. Constant time.
    pub const fn new(rng: R) -> Self {
        Self {
            rng,
            params: None,
            integers: PhantomData,
        }
    }
}

/// Keeps a copy of the parameters once they are checked: an odd
/// public exponent of at least three, a certainty of at least one, and a
/// modulus of at least 16 bits that `T` holds, with primes `H` holds.
/// Variable time: only for public values, as the parameters are.
impl<T, H, R> KeyPairGeneratorInit<RsaKeyGenerationParams> for RsaKeyPairGenerator<T, H, R>
where
    T: TryFrom<PaddedBigUint>,
    H: TryFrom<PaddedBigUint>,
{
    type Error = RsaError;

    fn init(&mut self, params: &RsaKeyGenerationParams) -> Result<(), RsaError> {
        check::<T, H>(
            params.public_exponent(),
            params.strength(),
            params.certainty(),
        )?;
        self.params = Some(*params);
        Ok(())
    }
}

/// Draws primes until they make a key, as Bouncy Castle does, in
/// `PaddedBigUint`, then converts the key into `T` and `H`. Variable time,
/// only for a caller that accepts it, as key generation everywhere does:
/// how many candidates are drawn, and which tests turn them down, shows in
/// the running time. The secret values it names are wiped once the key is
/// out; the working values inside the arithmetic of `tc_bigint` and
/// `tc_prime` are not all wiped, nor is the copy a conversion into a
/// fixed-width integer takes and drops.
impl<T, H, R> KeyPairGenerator for RsaKeyPairGenerator<T, H, R>
where
    T: Zeroize + TryFrom<PaddedBigUint>,
    H: Zeroize + TryFrom<PaddedBigUint>,
    R: CryptoRng,
{
    type PublicKey = RsaKeyOwned<T>;
    type PrivateKey = RsaPrivateCrtKeyOwned<T, H>;
    type Error = RsaError;

    fn generate_key_pair(
        &mut self,
    ) -> Result<(RsaKeyOwned<T>, RsaPrivateCrtKeyOwned<T, H>), RsaError> {
        let params = self.params.ok_or(RsaError::NotInitialized)?;
        let key = generate(
            &mut self.rng,
            params.public_exponent(),
            params.strength(),
            params.certainty(),
        );

        // The parameters were checked to fit `T` and `H`.
        let wide = |value: &PaddedBigUint| {
            T::try_from(value.clone()).map_err(|_| RsaError::InvalidStrength)
        };
        let half = |value: &PaddedBigUint| {
            H::try_from(value.clone()).map_err(|_| RsaError::InvalidStrength)
        };
        // The modulus is the product of two primes it drew, so the keys are
        // marked as checked.
        let public = RsaKeyOwned::new(false, wide(&key.n)?, wide(&key.e)?).into_validated();
        let private = RsaPrivateCrtKeyOwned::new(
            wide(&key.n)?,
            wide(&key.e)?,
            wide(&key.d)?,
            half(&key.p)?,
            half(&key.q)?,
            half(&key.dp)?,
            half(&key.dq)?,
            half(&key.q_inv)?,
        )
        .into_validated();
        Ok((public, private))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::AsymmetricKeyParams;
    use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
    use tc_bigint::{BigUint, FixedBigUint, PaddedBigUint};
    use tc_modular::{ModPow, NonZero};

    use crate::{
        RsaError, RsaKeyGenerationParams, RsaKeyPairGenerator, RsaKeyParams, RsaPrivateCrtKeyParams,
    };

    /// Checks a private key, in `BigUint`, whose products need no width:
    /// `n = p · q` of `strength` bits, the CRT values, and a message that
    /// comes back from `e` and `d`.
    fn assert_valid<T, H>(key: &impl RsaPrivateCrtKeyParams<T, H>, strength: u32)
    where
        T: Clone,
        H: Clone,
        BigUint: From<T> + From<H>,
    {
        let wide = |value: &T| BigUint::from(value.clone());
        let half = |value: &H| BigUint::from(value.clone());
        let (n, e, d) = (
            wide(key.modulus()),
            wide(key.public_exponent()),
            wide(key.exponent()),
        );
        let (p, q) = (half(key.p()), half(key.q()));
        let one = BigUint::from(1u8);
        assert_eq!(n.bits(), strength);
        assert_eq!(&p * &q, n);
        assert!(p > q);
        assert_eq!(half(key.dp()), &d % &(&p - 1u32));
        assert_eq!(half(key.dq()), &d % &(&q - 1u32));
        assert_eq!(&half(key.q_inv()) * &q % &p, one);
        let modulus = NonZero::new(n).unwrap();
        let message = BigUint::from(0x1234_5678_u32);
        assert_eq!(message.mod_pow(&e, &modulus).mod_pow(&d, &modulus), message);
    }

    #[test]
    fn a_generated_key_holds_together() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut generator = RsaKeyPairGenerator::<PaddedBigUint, PaddedBigUint, _>::new(&mut rng);
        generator
            .init(&RsaKeyGenerationParams::new().with_strength(256))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.exponent(), &PaddedBigUint::from(65537u32));
        assert!(!public.is_private_key() && private.is_private_key());
        assert_valid(&private, 256);
    }

    #[test]
    fn keys_of_odd_sizes_and_other_exponents_hold_together() {
        let mut rng = StdRng::seed_from_u64(2);
        // 21 is no prime, which takes the gcd of e and p - 1.
        for (strength, e) in [(129, 3), (200, 21), (255, 65539)] {
            let mut generator =
                RsaKeyPairGenerator::<PaddedBigUint, PaddedBigUint, _>::new(&mut rng);
            let params = RsaKeyGenerationParams::new()
                .with_strength(strength)
                .with_public_exponent(e);
            generator.init(&params).unwrap();
            let (_, private) = generator.generate_key_pair().unwrap();
            assert_valid(&private, strength);
            assert_eq!(private.public_exponent(), &PaddedBigUint::from(e));
        }
    }

    #[test]
    fn a_fixed_width_key_holds_its_primes_at_half_its_width() {
        // 256 bits fit eight limbs and 128 bits four, on 32-bit limbs too.
        let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<4>, _>::new(
            StdRng::seed_from_u64(3),
        );
        generator
            .init(&RsaKeyGenerationParams::new().with_strength(256))
            .unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert_eq!(public.modulus(), private.modulus());
        assert_valid(&private, 256);
    }

    #[test]
    fn the_same_seed_generates_the_same_key() {
        let generate = |seed| {
            let mut generator = RsaKeyPairGenerator::<PaddedBigUint, PaddedBigUint, _>::new(
                StdRng::seed_from_u64(seed),
            );
            generator
                .init(&RsaKeyGenerationParams::new().with_strength(128))
                .unwrap();
            generator.generate_key_pair().unwrap().0.modulus().clone()
        };
        assert_eq!(generate(4), generate(4));
        assert_ne!(generate(4), generate(5));
    }

    #[test]
    fn init_turns_down_parameters_that_cannot_make_a_key() {
        let init = |change: fn(RsaKeyGenerationParams) -> RsaKeyGenerationParams| {
            let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<4>, _>::new(
                StdRng::seed_from_u64(6),
            );
            generator.init(&change(RsaKeyGenerationParams::new()))
        };
        assert_eq!(init(|params| params.with_strength(256)), Ok(()));
        assert_eq!(
            init(|params| params.with_strength(256).with_public_exponent(4)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(|params| params.with_strength(256).with_public_exponent(1)),
            Err(RsaError::InvalidPublicExponent)
        );
        assert_eq!(
            init(|params| params.with_strength(256).with_certainty(0)),
            Err(RsaError::InvalidCertainty)
        );
        assert_eq!(
            init(|params| params.with_strength(8)),
            Err(RsaError::InvalidStrength)
        );
        // 2048 bits do not fit eight limbs, of 32 or 64 bits.
        assert_eq!(init(|params| params), Err(RsaError::InvalidStrength));
        // Nor do primes of 128 bits fit one limb.
        let mut generator = RsaKeyPairGenerator::<FixedBigUint<8>, FixedBigUint<1>, _>::new(
            StdRng::seed_from_u64(6),
        );
        let params = RsaKeyGenerationParams::new().with_strength(256);
        assert_eq!(generator.init(&params), Err(RsaError::InvalidStrength));
    }

    #[test]
    fn parameters_are_kept_as_a_copy_and_can_be_used_again() {
        let params = RsaKeyGenerationParams::new()
            .with_strength(128)
            .with_public_exponent(3);
        for seed in [7, 8] {
            let mut generator = RsaKeyPairGenerator::<PaddedBigUint, PaddedBigUint, _>::new(
                StdRng::seed_from_u64(seed),
            );
            generator.init(&params).unwrap();
            let (_, private) = generator.generate_key_pair().unwrap();
            assert_valid(&private, 128);
            assert_eq!(private.public_exponent(), &PaddedBigUint::from(3u8));
        }
    }

    #[test]
    fn a_generator_not_yet_initialized_generates_nothing() {
        let mut generator =
            RsaKeyPairGenerator::<PaddedBigUint, PaddedBigUint, _>::new(StdRng::seed_from_u64(9));
        assert_eq!(
            generator.generate_key_pair().err(),
            Some(RsaError::NotInitialized)
        );
    }
}

//! The generator of [`RsaKey`] pairs, on the safest generator available.

use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};

use crate::{RsaError, RsaKey, RsaKeyGenerationParams};

/// The generator underneath: that of the RustCrypto `rsa` crate when the
/// `rustcrypto` feature is on, and that of this crate otherwise.
#[cfg(feature = "rustcrypto")]
type Inner<R> = crate::RsaKeyPairGeneratorRustCrypto<R>;
#[cfg(not(feature = "rustcrypto"))]
type Inner<R> = crate::RsaKeyPairGenerator<tc_bigint::PaddedBigUint, tc_bigint::PaddedBigUint, R>;

/// Generates pairs of [`RsaKey`], the public one a
/// [`Core`](RsaKey::Core) key and the private one a [`Crt`](RsaKey::Crt)
/// key, as Bouncy Castle's `RsaKeyPairGenerator` does: through the
/// RustCrypto `rsa` crate when the `rustcrypto` feature is on, and through
/// [`RsaKeyPairGenerator`](crate::RsaKeyPairGenerator) over
/// `PaddedBigUint` otherwise. The type and its API are the same either
/// way; only the generator inside changes. It draws from the random source
/// `R` it is constructed with, owned, or borrowed as `&mut R`.
///
/// ```
/// use tc_asym_cipher::{AsymmetricKeyParams, KeyPairGenerator, KeyPairGeneratorInit};
/// use tc_rsa::{RsaKey, RsaKeyGenerationParams, RsaKeyGenerator};
///
/// // A 2048-bit pair, with the public exponent 65537, drawn from the
/// // system's random source.
/// let mut generator = RsaKeyGenerator::new(rand::rng());
/// generator.init(&RsaKeyGenerationParams::new())?;
/// let (public, private) = generator.generate_key_pair()?;
///
/// // The public key is raised by `e`; the private one through the CRT.
/// assert!(matches!(public, RsaKey::Core(_)) && !public.is_private_key());
/// assert!(matches!(private, RsaKey::Crt(_)));
/// # Ok::<(), tc_rsa::RsaError>(())
/// ```
pub struct RsaKeyGenerator<R> {
    inner: Inner<R>,
}

impl<R> RsaKeyGenerator<R> {
    /// A generator drawing from `rng`, to be initialized before it
    /// generates. Constant time.
    pub const fn new(rng: R) -> Self {
        Self {
            inner: Inner::new(rng),
        }
    }
}

/// Keeps a copy of the parameters once the generator underneath checks
/// them. Variable time: only for public values, as the parameters are.
impl<R> KeyPairGeneratorInit<RsaKeyGenerationParams> for RsaKeyGenerator<R> {
    type Error = RsaError;

    fn init(&mut self, params: &RsaKeyGenerationParams) -> Result<(), RsaError> {
        self.inner.init(params)
    }
}

/// A pair from the generator underneath, as [`RsaKey`]. Variable time, as
/// key generation everywhere is: how many candidates are drawn shows in
/// the running time; the generator underneath tells the rest.
impl<R: CryptoRng> KeyPairGenerator for RsaKeyGenerator<R> {
    type PublicKey = RsaKey;
    type PrivateKey = RsaKey;
    type Error = RsaError;

    fn generate_key_pair(&mut self) -> Result<(RsaKey, RsaKey), RsaError> {
        let (public, private) = self.inner.generate_key_pair()?;
        Ok((public.into(), private.into()))
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use tc_asym_cipher::{
        AsymmetricBlockCipher, AsymmetricBlockCipherInit, AsymmetricKeyParams, CipherDirection,
        KeyPairGenerator, KeyPairGeneratorInit,
    };

    use super::RsaKeyGenerator;
    use crate::{PaddedRsaCoreEngine, RsaKey, RsaKeyGenerationParams, RsaKeyParams};

    #[test]
    fn a_generated_pair_is_a_public_core_key_and_a_private_crt_key_of_one_modulus() {
        let mut generator = RsaKeyGenerator::new(StdRng::seed_from_u64(1));
        let params = RsaKeyGenerationParams::new().with_strength(1024);
        generator.init(&params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        assert!(matches!(public, RsaKey::Core(_)) && !public.is_private_key());
        assert!(matches!(private, RsaKey::Crt(_)) && private.is_private_key());
        assert_eq!(public.modulus(), private.modulus());
        assert_eq!(public.modulus().bits(), 1024);
        assert!(public.validate() && private.validate());
    }

    #[test]
    fn a_generated_pair_encrypts_and_decrypts_a_block() {
        let mut generator = RsaKeyGenerator::new(StdRng::seed_from_u64(2));
        let params = RsaKeyGenerationParams::new().with_strength(1024);
        generator.init(&params).unwrap();
        let (public, private) = generator.generate_key_pair().unwrap();
        let message = [0x5a; 127];
        let mut engine = PaddedRsaCoreEngine::new();
        engine.init(CipherDirection::Encrypt, &public).unwrap();
        let mut ciphertext = [0; 128];
        engine.process_block(&message, &mut ciphertext).unwrap();
        engine.init(CipherDirection::Decrypt, &private).unwrap();
        let mut plaintext = [0; 128];
        engine.process_block(&ciphertext, &mut plaintext).unwrap();
        assert_eq!(&plaintext[1..], &message[..]);
    }
}

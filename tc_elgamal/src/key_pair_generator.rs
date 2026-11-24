use crate::{
    ElGamalError, ElGamalKeyGenerationParams, ElGamalParameters, ElGamalPrivateKey,
    ElGamalPublicKey,
};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_dh_key::{DhKeyGenerationParams, DhKeyPairGenerator};

/// Bouncy Castle's `ElGamalKeyPairGenerator`: converts the parameters to Diffie-Hellman ones
/// with no q and m = 0, and has the [`DhKeyPairGenerator`] of `tc_dh_key` draw x and work out
/// y = g^x mod p.
pub struct ElGamalKeyPairGenerator<R> {
    inner: DhKeyPairGenerator<R>,
    params: Option<ElGamalParameters>,
}

impl<R> ElGamalKeyPairGenerator<R> {
    /// A generator that draws from `rng`, before `init`. Constant time.
    pub fn new(rng: R) -> Self {
        Self {
            inner: DhKeyPairGenerator::new(rng),
            params: None,
        }
    }
}

impl<R> KeyPairGeneratorInit<ElGamalKeyGenerationParams> for ElGamalKeyPairGenerator<R> {
    type Error = ElGamalError;

    /// Checks the parameters with the Diffie-Hellman checks. Variable time, only for public
    /// values: the parameters are public.
    fn init(&mut self, params: &ElGamalKeyGenerationParams) -> Result<(), ElGamalError> {
        self.params = None;
        let dh = DhKeyGenerationParams::new(params.params.to_dh());
        self.inner.init(&dh)?;
        self.params = Some(params.params.clone());
        Ok(())
    }
}

impl<R: CryptoRng> KeyPairGenerator for ElGamalKeyPairGenerator<R> {
    type PublicKey = ElGamalPublicKey;
    type PrivateKey = ElGamalPrivateKey;
    type Error = ElGamalError;

    /// x in `[2, p - 2]`, or of l bits, and y = g^x mod p, as for Diffie-Hellman. Constant time
    /// in x; only how many candidates are drawn and discarded shows in the time.
    fn generate_key_pair(&mut self) -> Result<(ElGamalPublicKey, ElGamalPrivateKey), ElGamalError> {
        let params = self.params.as_ref().ok_or(ElGamalError::NotInitialized)?;
        let (public_key, private_key) = self.inner.generate_key_pair()?;
        Ok((
            ElGamalPublicKey::new(public_key.y().clone(), params.clone()),
            ElGamalPrivateKey::new(private_key.x().clone(), params.clone()),
        ))
    }
}

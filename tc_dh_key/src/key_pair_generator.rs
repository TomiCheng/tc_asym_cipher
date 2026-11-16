//! Generation of Diffie-Hellman key pairs.

use crate::math::naf_weight;
use crate::{DhError, DhKeyGenerationParams, DhParameters, DhPrivateKey, DhPublicKey};
use rand_core::CryptoRng;
use tc_asym_cipher::{KeyPairGenerator, KeyPairGeneratorInit};
use tc_bigint::{BigUint, PaddedBigUint, RandomBits, RandomRange};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::Zeroize;

/// Generates Diffie-Hellman key pairs as Bouncy Castle's `DHKeyPairGenerator`
/// does (its `DHBasicKeyPairGenerator`, now obsolete, does the same). `init`
/// checks the parameters and sets up Montgomery parameters for p, which every
/// pair then shares.
pub struct DhKeyPairGenerator<R> {
    rng: R,
    state: Option<State>,
}

/// What `init` sets up for the pairs to come.
struct State {
    params: DhKeyGenerationParams,
    monty: PaddedMontyParams,
}

impl<R> DhKeyPairGenerator<R> {
    /// A generator that draws from `rng`, to be initialized before it
    /// generates. Constant time.
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }
}

/// Initialization from `DhKeyGenerationParams`.
impl<R> KeyPairGeneratorInit<DhKeyGenerationParams> for DhKeyPairGenerator<R> {
    type Error = DhError;

    /// Checks the parameters with [`DhParameters::validate`] and, without l,
    /// that the range of the private value is not empty, and sets up
    /// Montgomery parameters for p. Variable time: the parameters are public.
    fn init(&mut self, params: &DhKeyGenerationParams) -> Result<(), DhError> {
        params.params.validate()?;
        if params.params.l() == 0 {
            private_range(&params.params)?;
        }
        let p = Odd::new(params.params.p().clone()).ok_or(DhError::InvalidModulus)?;
        self.state = Some(State {
            params: params.clone(),
            monty: PaddedMontyParams::new(p),
        });
        Ok(())
    }
}

/// Generation of pairs over the parameters of `init`.
impl<R: CryptoRng> KeyPairGenerator for DhKeyPairGenerator<R> {
    type PublicKey = DhPublicKey;
    type PrivateKey = DhPrivateKey;
    type Error = DhError;

    /// Bouncy Castle's `GenerateKeyPair`: a private value x drawn as
    /// `CalculatePrivate` draws it, and y = g^x mod p. Constant time in x;
    /// only the candidates thrown away show in the time it takes.
    fn generate_key_pair(&mut self) -> Result<(DhPublicKey, DhPrivateKey), DhError> {
        let state = self.state.as_ref().ok_or(DhError::NotInitialized)?;
        let params = &state.params.params;
        let x = private_value(params, &mut self.rng);
        let y = public_value(&state.monty, params.g(), &x);
        Ok((
            DhPublicKey::new(y, params.clone()),
            DhPrivateKey::new(x, params.clone()),
        ))
    }
}

/// Bouncy Castle's `DHKeyGeneratorHelper.CalculatePrivate`. With l set, x is a
/// random value of l bits with the top bit set; otherwise x is drawn uniformly
/// from `[2^(m - 1), q - 2]`, with p where there is no q and 2 as the bound
/// when m is 0. Either way x is drawn again unless its NAF has at least a
/// quarter as many nonzero digits as the bound has bits, so that x is not too
/// sparse.
///
/// Constant time in x: the draws, the comparisons and the NAF weight branch on
/// nothing in x, and the candidates thrown away are wiped; how many draws it
/// takes shows, and that has nothing to do with the x it returns.
fn private_value(params: &DhParameters, rng: &mut dyn CryptoRng) -> PaddedBigUint {
    let l = params.l();
    if l != 0 {
        let min_weight = l >> 2;
        loop {
            let mut x = PaddedBigUint::random_bits(rng, l);
            x.set_bit(l - 1, true);
            if naf_weight(x.as_limbs()) >= min_weight {
                return x;
            }
            x.zeroize();
        }
    }

    let (min, high) = private_range(params).expect("init checks the range");
    let min_weight = (&high - 1u32).bits() >> 2;
    loop {
        let mut x = PaddedBigUint::random_range(rng, &min, &high);
        if naf_weight(x.as_limbs()) >= min_weight {
            return x;
        }
        x.zeroize();
    }
}

/// The range of x without l: Bouncy Castle's `CreateRandomInRange(min, q - 2)`
/// includes its bound, and this returns the half-open `[min, q - 1)`, where
/// min is 2^(m - 1), or 2 when m is 0, and p stands in for a missing q. An
/// empty range, of a q too small or a 2^(m - 1) above q - 2, is
/// [`DhError::InvalidPrivateValueLength`], where Bouncy Castle throws only
/// when it generates. Variable time: only for public values.
fn private_range(params: &DhParameters) -> Result<(PaddedBigUint, PaddedBigUint), DhError> {
    let m = params.m();
    let min = if m != 0 {
        let mut min = BigUint::from(0u8);
        min.set_bit(m - 1, true);
        PaddedBigUint::from(min)
    } else {
        PaddedBigUint::from(2u8)
    };
    let order = params.q().unwrap_or(params.p());
    if *order < &min + 2u32 {
        return Err(DhError::InvalidPrivateValueLength);
    }
    Ok((min, order - 1u32))
}

/// Bouncy Castle's `DHKeyGeneratorHelper.CalculatePublic`: g^x mod p, raised
/// in Montgomery form. Constant time in x: every bit takes one squaring and
/// one multiplication, over a public width. The intermediate value is wiped.
fn public_value(monty: &PaddedMontyParams, g: &PaddedBigUint, x: &PaddedBigUint) -> PaddedBigUint {
    let base = PaddedMontyForm::new(g, monty);
    let mut power = base.pow(x);
    let y = power.retrieve();
    power.zeroize();
    y
}

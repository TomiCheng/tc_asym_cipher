//! Generation of safe-prime Diffie-Hellman groups.

use crate::math::{naf_weight, rem_u32};
use crate::small_primes::{PRIME_LISTS, PRIME_PRODUCTS};
use crate::{DhError, DhGroupGenerationParams, DhParameters};
use alloc::vec;
use rand_core::CryptoRng;
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint};
use tc_modular::{ModPow, NonZero};
use tc_prime::Primality;

/// Generates Diffie-Hellman groups as Bouncy Castle's `DHParametersGenerator`
/// does: a safe prime p = 2q + 1 with g = 2 and the cofactor j = 2. It is
/// slow; 2048 bits can take tens of seconds or minutes.
pub struct DhGroupGenerator<R> {
    rng: R,
    params: Option<DhGroupGenerationParams>,
}

impl<R> DhGroupGenerator<R> {
    /// A generator that draws from `rng`, to be initialized before it
    /// generates. Constant time.
    pub fn new(rng: R) -> Self {
        Self { rng, params: None }
    }

    /// Bouncy Castle's `Init`: sets the size of p in bits and the certainty
    /// of the primality test. A p narrower than 64 bits or a certainty of 0
    /// is an error here, where Bouncy Castle throws only when it generates.
    /// Constant time.
    pub fn init(&mut self, params: &DhGroupGenerationParams) -> Result<(), DhError> {
        if params.size() < 64 {
            return Err(DhError::InvalidSize);
        }
        if params.certainty() == 0 {
            return Err(DhError::InvalidCertainty);
        }
        self.params = Some(*params);
        Ok(())
    }
}

impl<R: CryptoRng> DhGroupGenerator<R> {
    /// Bouncy Castle's `GenerateParameters`: a safe prime p ≡ 7 (mod 8), so
    /// that 2 generates the subgroup of order q, returned with g = 2, q and
    /// j = 2. Variable time: the group is public.
    pub fn generate_group(&mut self) -> Result<DhParameters, DhError> {
        let params = self.params.ok_or(DhError::NotInitialized)?;
        let (p, q) = safe_primes(params.size(), params.certainty(), &mut self.rng, true);
        Ok(
            DhParameters::new(PaddedBigUint::from(p), PaddedBigUint::from(2u8))
                .with_q(PaddedBigUint::from(q))
                .with_j(PaddedBigUint::from(2u8)),
        )
    }
}

/// Bouncy Castle's `DHParametersHelper.GenerateSafePrimes` (Handbook of
/// Applied Cryptography 4.86): primes p and q of `bits` bits with p = 2q + 1.
/// With `for_generator2`, p ≡ 23 (mod 24) and 2 is a quadratic residue mod p;
/// otherwise p ≡ 11 (mod 12).
///
/// From a random start it steps by 12 or 24 at most 256 times: it skips the
/// candidates where p or q has a small factor, runs a Fermat test on p (which
/// proves p prime by Pocklington's criterion once q is prime) and
/// Miller-Rabin on q, and requires the NAF of p to have at least a quarter of
/// its bits nonzero, against the number field sieve for low-weight primes.
/// Variable time: the primes are public.
pub(crate) fn safe_primes(
    bits: u32,
    certainty: u32,
    rng: &mut dyn CryptoRng,
    for_generator2: bool,
) -> (BigUint, BigUint) {
    let (low_bits_set, inc3, step) = if for_generator2 {
        (0x07u8, -8i32, 24u32)
    } else {
        (0x03u8, 4i32, 12u32)
    };
    let min_weight = bits >> 2;
    let byte_length = bits.div_ceil(8) as usize;
    let extra_bits = byte_length as u32 * 8 - bits;
    let two = BigUint::from(2u8);
    let mut bytes = vec![0u8; byte_length];
    loop {
        rng.fill_bytes(&mut bytes);
        // Clear the excess bits and set the top bit and the low bits.
        bytes[0] = (bytes[0] & (0xffu8 >> extra_bits)) | (0x80u8 >> extra_bits);
        bytes[byte_length - 1] |= low_bits_set;
        let mut p = BigUint::from_be(&bytes).expect("bytes always decode");

        // Move to p ≡ 2 (mod 3), which gives p ≡ 11 (mod 12), or p ≡ 23 (mod 24)
        // with for_generator2.
        let p_mod3 = rem_u32(&p, 3);
        if p_mod3 != 2 {
            let delta = (2 - p_mod3 as i32) * inc3;
            p = if delta >= 0 {
                p + delta as u32
            } else {
                p - delta.unsigned_abs()
            };
        }

        let mut count = 0;
        loop {
            count += 1;
            if count > 256 || p.bits() != bits {
                break;
            }
            if !has_any_small_factors_safe(&p) {
                let modulus = NonZero::new(p.clone()).expect("p is odd");
                if two.mod_pow(&p, &modulus) == two {
                    let q = &p >> 1;
                    if q.is_probable_prime(rounds(certainty, q.bits()), rng)
                        && naf_weight(p.as_limbs()) >= min_weight
                    {
                        return (p, q);
                    }
                }
                // Start again from a new random point.
                break;
            }
            p += step;
        }
    }
}

/// Bouncy Castle's `DHParametersHelper.HasAnySmallFactorsSafe`: a remainder
/// of 0 means p has the small prime as a factor, and 1 means p − 1 has it,
/// and so q. Variable time: only for public values.
fn has_any_small_factors_safe(x: &BigUint) -> bool {
    PRIME_LISTS
        .iter()
        .zip(PRIME_PRODUCTS)
        .any(|(primes, product)| {
            let r = rem_u32(x, product);
            primes.iter().any(|&prime| r % prime < 2)
        })
}

/// The Miller-Rabin rounds that test a randomly selected candidate of `bits`
/// bits to `certainty`, as Bouncy Castle's `RabinMillerTest` counts them when
/// `randomlySelected`. Variable time: only for public values.
fn rounds(certainty: u32, bits: u32) -> u32 {
    let rounds = (certainty - 1) / 2 + 1;
    let for_certainty_100 = match bits {
        1024.. => 4,
        512.. => 8,
        256.. => 16,
        _ => 50,
    };
    if certainty < 100 {
        rounds.min(for_certainty_100)
    } else {
        rounds - 50 + for_certainty_100
    }
}

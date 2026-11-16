//! Integer helpers on public and secret values.

use tc_bigint::{BigUint, Limb, Word};

/// Bouncy Castle's `WNafUtilities.GetNafWeight`: the number of nonzero digits
/// in the NAF of k, which is the number of set bits of 3k XOR k, worked out
/// limb by limb with a carry and no wider integer. Constant time: every limb
/// is visited.
pub(crate) fn naf_weight(limbs: &[Limb]) -> u32 {
    let (mut top, mut carry, mut weight): (Word, Word, u32) = (0, 0, 0);
    for limb in limbs {
        let x = limb.to_word();
        let doubled = (x << 1) | top;
        top = x >> (Word::BITS - 1);
        let (sum, low) = doubled.overflowing_add(x);
        let (sum, high) = sum.overflowing_add(carry);
        carry = Word::from(low) + Word::from(high);
        weight += (sum ^ x).count_ones();
    }
    // Past the limbs k is 0, and 3k has only what was carried out.
    weight + (top + carry).count_ones()
}

/// `value mod modulus`, limb by limb from the top. Variable time: only for
/// public values.
pub(crate) fn rem_u32(value: &BigUint, modulus: u32) -> u32 {
    let modulus = u128::from(modulus);
    let mut r = 0u128;
    for limb in value.as_limbs().iter().rev() {
        r = ((r << Word::BITS) | u128::from(limb.to_word())) % modulus;
    }
    r as u32
}

/// Bouncy Castle's `DHPublicKeyParameters.Legendre`: the Jacobi symbol (a / b)
/// of an odd b, as 1, −1 or 0, which is the Legendre symbol when b is prime.
/// It follows Bouncy Castle's binary subtractive version, which needs a below
/// b. Variable time: only for public values.
pub(crate) fn legendre(a: &BigUint, b: &BigUint) -> i32 {
    let low = |v: &BigUint| v.as_limbs().first().map_or(0, |limb| limb.to_word() as u32);
    let (mut a, mut b) = (a.clone(), b.clone());
    let mut r = 0u32;
    loop {
        let Some(shift) = a.trailing_zeros() else {
            // a is 0, which shares b as a factor when b is above 1.
            return 0;
        };
        if shift > 0 {
            a >>= shift;
            let bits = low(&b);
            r ^= (bits ^ (bits >> 1)) & (shift << 1);
        }
        if a == b {
            break;
        }
        if a < b {
            r ^= low(&a) & low(&b);
            core::mem::swap(&mut a, &mut b);
        }
        a -= &b;
    }
    if b == BigUint::from(1u8) {
        1 - (r & 2) as i32
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::{legendre, naf_weight, rem_u32};
    use tc_bigint::BigUint;

    // The symbol by definition: (a / p) ≡ a^((p - 1) / 2) mod p for an odd
    // prime p.
    fn euler(a: u64, p: u64) -> i32 {
        let mut result = 1u128;
        let (mut base, mut exponent) = (u128::from(a % p), (p - 1) / 2);
        while exponent > 0 {
            if exponent & 1 == 1 {
                result = result * base % u128::from(p);
            }
            base = base * base % u128::from(p);
            exponent >>= 1;
        }
        match result {
            0 => 0,
            1 => 1,
            _ => -1,
        }
    }

    #[test]
    fn the_legendre_symbol_matches_euler_s_criterion() {
        for p in [3u64, 5, 7, 11, 13, 23, 47, 1_000_003, 2_147_483_647] {
            for a in 1..p.min(200) {
                assert_eq!(
                    legendre(&BigUint::from(a), &BigUint::from(p)),
                    euler(a, p),
                    "({a} / {p})"
                );
            }
        }
    }

    #[test]
    fn the_naf_weight_counts_the_nonzero_digits() {
        // The NAF of 7 = 8 − 1 has two nonzero digits; 0b101_0101 is its own NAF,
        // with four.
        for (value, weight) in [
            (0u64, 0),
            (1, 1),
            (3, 2),
            (7, 2),
            (0b101_0101, 4),
            (u64::MAX, 2),
        ] {
            assert_eq!(
                naf_weight(BigUint::from(value).as_limbs()),
                weight,
                "{value}"
            );
        }
    }

    #[test]
    fn the_remainder_by_a_small_modulus_matches_u128_arithmetic() {
        let value = u128::MAX - 12_345;
        for modulus in [3u32, 7, 223_092_870, u32::MAX] {
            assert_eq!(
                rem_u32(&BigUint::from(value), modulus),
                (value % u128::from(modulus)) as u32
            );
        }
    }
}

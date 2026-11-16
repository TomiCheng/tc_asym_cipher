//! `DhPublicKey::validate`, with the checks of Bouncy Castle's
//! `DHPublicKeyParameters.Validate`.

mod common;

use common::{group14, n};
use tc_bigint::{BigUint, PaddedBigUint};
use tc_dh_key::{DhError, DhParameters, DhPublicKey};

#[test]
fn the_public_value_must_lie_in_two_to_p_minus_two() {
    let params = DhParameters::new(n(23), n(2)).with_m(0);
    for y in [0, 1, 22, 23, 40] {
        assert_eq!(
            DhPublicKey::new(n(y), params.clone()).validate(),
            Err(DhError::InvalidPublicValue),
            "y = {y}"
        );
    }
    assert_eq!(DhPublicKey::new(n(5), params).validate(), Ok(()));
}

#[test]
fn a_safe_prime_group_accepts_quadratic_residues_only() {
    // 23 = 2·11 + 1: the quadratic residues mod 23 are the subgroup of order 11.
    let params = DhParameters::new(n(23), n(2)).with_m(0).with_q(n(11));
    let residues = [2, 3, 4, 6, 8, 9, 12, 13, 16, 18];
    for y in 2..=21 {
        let result = DhPublicKey::new(n(y), params.clone()).validate();
        if residues.contains(&y) {
            assert_eq!(result, Ok(()), "y = {y}");
        } else {
            assert_eq!(result, Err(DhError::PublicValueOutsideSubgroup), "y = {y}");
        }
    }
}

#[test]
fn a_subgroup_that_is_not_half_of_p_is_checked_by_exponentiation() {
    // 31 − 1 = 2·3·5 and 2 has order 5: the subgroup is {1, 2, 4, 8, 16}.
    let params = DhParameters::new(n(31), n(2)).with_m(0).with_q(n(5));
    for y in 2..=29 {
        let result = DhPublicKey::new(n(y), params.clone()).validate();
        if [2, 4, 8, 16].contains(&y) {
            assert_eq!(result, Ok(()), "y = {y}");
        } else {
            assert_eq!(result, Err(DhError::PublicValueOutsideSubgroup), "y = {y}");
        }
    }
}

#[test]
fn the_rfc_3526_group_rejects_minus_two() {
    // p ≡ 7 (mod 8): 2 is a residue and −1 is not, so p − 2 = −2 is outside the
    // subgroup.
    let params = group14();
    let p_minus_two = PaddedBigUint::from(BigUint::from(params.p().clone()) - 2u32);
    assert_eq!(
        DhPublicKey::new(p_minus_two, params.clone()).validate(),
        Err(DhError::PublicValueOutsideSubgroup)
    );
    assert_eq!(DhPublicKey::new(n(4), params).validate(), Ok(()));
}

#[test]
fn a_modulus_over_16384_bits_is_rejected() {
    let mut p = BigUint::from(1u8);
    p.set_bit(16384, true);
    let params = DhParameters::new(PaddedBigUint::from(p), n(2));
    assert_eq!(
        DhPublicKey::new(n(2), params).validate(),
        Err(DhError::ModulusTooLarge)
    );
}

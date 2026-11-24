use crate::{ElGamalError, ElGamalPrivateKey, ElGamalPublicKey};
use core::fmt;
use rand_core::CryptoRng;
use tc_asym_cipher::{AsymmetricBlockCipher, AsymmetricBlockCipherInit, CipherDirection};
use tc_bigint::{ArrayEncoding, BigUint, PaddedBigUint, RandomBits};
use tc_modular::{Odd, PaddedMontyForm, PaddedMontyParams};
use tc_zeroize::{Zeroize, Zeroizing};

/// Bouncy Castle's `ElGamalEngine`: each encryption draws a new k, and the ciphertext is
/// γ = g^k and φ = y^k · m, each the length of p in bytes; decryption works out
/// m = γ^(p − 1 − x) · φ.
///
/// The block sizes are those of `tc_rsa`. With b the bit length of p, encryption takes at most
/// `(b - 1) / 8` bytes and gives `2 · ⌈b / 8⌉`; decryption takes exactly `2 · ⌈b / 8⌉` and
/// always gives `⌈b / 8⌉` bytes, leading zeros kept. Bouncy Castle's decryption gives only the
/// significant bytes of m; the fixed length lets PKCS#1 and OAEP wrap the engine directly.
///
/// Only encryption draws random numbers; decryption takes a random source too but does not use
/// it.
pub struct ElGamalEngine<R> {
    rng: R,
    state: Option<State>,
}

/// The state after `init`: p, its Montgomery parameters, and the values of the direction.
struct State {
    bits: u32,
    p: PaddedBigUint,
    monty: PaddedMontyParams,
    mode: Mode,
}

enum Mode {
    /// Encryption with a public key: g and y.
    Encrypt { g: PaddedBigUint, y: PaddedBigUint },
    /// Decryption with a private key: the exponent p − 1 − x, worked out at `init` and wiped
    /// on drop.
    Decrypt { exponent: Zeroizing<PaddedBigUint> },
}

impl<R> ElGamalEngine<R> {
    /// An engine that draws k from `rng`, before `init`. Constant time.
    pub fn new(rng: R) -> Self {
        Self { rng, state: None }
    }

    /// The length of p in bytes, ⌈b / 8⌉. Constant time.
    fn half(state: &State) -> usize {
        (state.bits as usize).div_ceil(8)
    }
}

impl<R: Default> Default for ElGamalEngine<R> {
    /// An engine over the default random source, before `init`. Constant time.
    fn default() -> Self {
        Self::new(R::default())
    }
}

impl<R> fmt::Display for ElGamalEngine<R> {
    /// Writes Bouncy Castle's algorithm name, `ElGamal`. Constant time; the formatter decides
    /// how long the writing takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ElGamal")
    }
}

/// Checks the parameters and builds the Montgomery parameters of p. Variable time, only for
/// public values: the parameters are public.
fn prepare(
    params: &crate::ElGamalParameters,
) -> Result<(u32, PaddedBigUint, PaddedMontyParams), ElGamalError> {
    params.validate()?;
    let p = params.p().clone();
    let odd = Odd::new(p.clone()).ok_or(ElGamalError::InvalidKey)?;
    Ok((p.bits(), p, PaddedMontyParams::new(odd)))
}

impl<R> AsymmetricBlockCipherInit<ElGamalPublicKey> for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// Sets the engine up to encrypt with a public key: the direction must be encryption,
    /// the parameters must pass their checks and y must be in `[2, p - 2]`. Bouncy Castle
    /// does not check y, but with y of 1 or p − 1 the ciphertext gives away the message or its
    /// sign. Variable time, only for public values: the public key is public.
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &ElGamalPublicKey,
    ) -> Result<(), ElGamalError> {
        self.state = None;
        if direction != CipherDirection::Encrypt {
            return Err(ElGamalError::WrongKeyForDirection);
        }
        let (bits, p, monty) = prepare(key.params())?;
        let y = BigUint::from(key.y().clone());
        let p_big = BigUint::from(p.clone());
        if y < BigUint::from(2u8) || y > &p_big - 2u32 {
            return Err(ElGamalError::InvalidKey);
        }
        self.state = Some(State {
            bits,
            mode: Mode::Encrypt {
                g: key.params().g().clone(),
                y: key.y().clone(),
            },
            p,
            monty,
        });
        Ok(())
    }
}

impl<R> AsymmetricBlockCipherInit<ElGamalPrivateKey> for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// Sets the engine up to decrypt with a private key: the direction must be decryption,
    /// the parameters must pass their checks and x must not be above p − 2; the exponent
    /// p − 1 − x is worked out here. Constant time in x: neither the comparison nor the
    /// subtraction branches on its value.
    fn init(
        &mut self,
        direction: CipherDirection,
        key: &ElGamalPrivateKey,
    ) -> Result<(), ElGamalError> {
        self.state = None;
        if direction != CipherDirection::Decrypt {
            return Err(ElGamalError::WrongKeyForDirection);
        }
        let (bits, p, monty) = prepare(key.params())?;
        let p_less_one = &p - 1u32;
        if *key.x() >= p_less_one {
            return Err(ElGamalError::InvalidKey);
        }
        let exponent = Zeroizing::new(&p_less_one - key.x());
        self.state = Some(State {
            bits,
            p,
            monty,
            mode: Mode::Decrypt { exponent },
        });
        Ok(())
    }
}

impl<R: CryptoRng> AsymmetricBlockCipher for ElGamalEngine<R> {
    type Error = ElGamalError;

    /// `(b - 1) / 8` to encrypt and `2 · ⌈b / 8⌉` to decrypt; 0 before `init`. Constant time.
    fn input_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) => match state.mode {
                Mode::Encrypt { .. } => (state.bits as usize - 1) / 8,
                Mode::Decrypt { .. } => 2 * Self::half(state),
            },
        }
    }

    /// `2 · ⌈b / 8⌉` to encrypt and `⌈b / 8⌉` to decrypt; 0 before `init`. Constant time.
    fn output_block_size(&self) -> usize {
        match &self.state {
            None => 0,
            Some(state) => match state.mode {
                Mode::Encrypt { .. } => 2 * Self::half(state),
                Mode::Decrypt { .. } => Self::half(state),
            },
        }
    }

    /// Encrypts or decrypts one block into the start of `output` and returns the number of
    /// bytes written. Constant time in m and k to encrypt and in x and m to decrypt; only the
    /// range check of γ and φ before decryption branches on their values, which are public.
    fn process_block(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, ElGamalError> {
        let state = self.state.as_ref().ok_or(ElGamalError::NotInitialized)?;
        let half = Self::half(state);
        match &state.mode {
            Mode::Encrypt { g, y } => {
                if input.len() > (state.bits as usize - 1) / 8 {
                    return Err(ElGamalError::InputTooLarge);
                }
                if output.len() < 2 * half {
                    return Err(ElGamalError::OutputTooShort);
                }
                encrypt(state, g, y, input, &mut self.rng, &mut output[..2 * half])?;
                Ok(2 * half)
            }
            Mode::Decrypt { exponent } => {
                if input.len() != 2 * half {
                    return Err(ElGamalError::InvalidCiphertextLength);
                }
                if output.len() < half {
                    return Err(ElGamalError::OutputTooShort);
                }
                decrypt(state, exponent, input, &mut output[..half])?;
                Ok(half)
            }
        }
    }
}

/// Bouncy Castle's encryption: k is a random value of b bits, drawn again when it is 0 or
/// above p − 2; γ = g^k mod p and φ = y^k · m mod p. An m of 0 is an error: Bouncy Castle
/// encrypts it, but a ciphertext with φ = 0 is turned down on decryption. Constant time in m
/// and k: the exponentiation squares and multiplies at every bit, a discarded k is wiped, and
/// how many are drawn has nothing to do with the k kept; only whether m is 0 shows, through
/// the error.
fn encrypt(
    state: &State,
    g: &PaddedBigUint,
    y: &PaddedBigUint,
    input: &[u8],
    rng: &mut dyn CryptoRng,
    output: &mut [u8],
) -> Result<(), ElGamalError> {
    let half = output.len() / 2;
    let Ok(m) = PaddedBigUint::from_be(input);
    let m = Zeroizing::new(m);
    if m.bits() == 0 {
        return Err(ElGamalError::InputTooSmall);
    }
    let one = PaddedBigUint::from(1u8);
    let p_less_two = &state.p - 2u32;
    let k = loop {
        let mut k = PaddedBigUint::random_bits(rng, state.bits);
        if k >= one && k <= p_less_two {
            break Zeroizing::new(k);
        }
        k.zeroize();
    };

    let gamma = Zeroizing::new(PaddedMontyForm::new(g, &state.monty).pow(&k));
    let mut phi = Zeroizing::new(PaddedMontyForm::new(y, &state.monty).pow(&k));
    *phi *= &*Zeroizing::new(PaddedMontyForm::new(&m, &state.monty));
    write_be(&gamma.retrieve(), &mut output[..half]);
    write_be(&Zeroizing::new(phi.retrieve()), &mut output[half..]);
    Ok(())
}

/// Bouncy Castle's decryption: γ and φ must both be in `[2, p - 2]`, against small-subgroup
/// attacks; m = γ^(p − 1 − x) · φ mod p. The exponentiation and the multiplication are
/// constant time in x and m; the range check branches on the values, but the ciphertext is
/// public.
fn decrypt(
    state: &State,
    exponent: &PaddedBigUint,
    input: &[u8],
    output: &mut [u8],
) -> Result<(), ElGamalError> {
    let half = output.len();
    let Ok(gamma) = PaddedBigUint::from_be(&input[..half]);
    let Ok(phi) = PaddedBigUint::from_be(&input[half..]);
    let p = BigUint::from(state.p.clone());
    let lowest = BigUint::from(2u8);
    let highest = &p - 2u32;
    for value in [&gamma, &phi] {
        let value = BigUint::from(value.clone());
        if value < lowest || value > highest {
            return Err(ElGamalError::WeakCiphertext);
        }
    }

    let mut m = Zeroizing::new(PaddedMontyForm::new(&gamma, &state.monty).pow(exponent));
    *m *= &PaddedMontyForm::new(&phi, &state.monty);
    write_be(&Zeroizing::new(m.retrieve()), output);
    Ok(())
}

/// Writes `value` big-endian over the whole of `output`, with leading zeros; it must fit.
/// Constant time in the value: only the widths decide where it reads and writes.
fn write_be(value: &PaddedBigUint, output: &mut [u8]) {
    let mut bytes = ArrayEncoding::<u8>::to_be(value);
    let length = output.len().min(bytes.len());
    output.fill(0);
    let start = output.len() - length;
    output[start..].copy_from_slice(&bytes[bytes.len() - length..]);
    bytes.zeroize();
}

//! Asymmetric key-pair generation contracts.

/// An initialized generator of asymmetric key pairs.
///
/// A generator that needs randomness takes its random source when it is
/// constructed, as randomized signers and KEM encapsulators do, so the
/// trait names no source: one that draws its entropy elsewhere, such as from
/// a hardware module, takes none. Initialization is provided independently
/// by [`KeyPairGeneratorInit`].
pub trait KeyPairGenerator {
    /// The public key of a generated pair.
    type PublicKey;

    /// The private key of a generated pair.
    type PrivateKey;

    /// The failure type returned while generating a pair.
    type Error: core::error::Error;

    /// Generates a key pair, drawing its randomness from the source the
    /// generator was constructed with.
    fn generate_key_pair(&mut self) -> Result<(Self::PublicKey, Self::PrivateKey), Self::Error>;
}

/// Initializes a key-pair generator from parameters of type `P`.
///
/// This trait is independent of [`KeyPairGenerator`]. Consumers that need
/// both capabilities use `G: KeyPairGenerator + KeyPairGeneratorInit<P>`,
/// as with the cipher traits.
///
/// As the cipher traits do, it takes the parameters by reference: they hold
/// data alone, such as the key size, so they can be kept, cloned and used
/// again, and `P` may be unsized, such as a trait object.
pub trait KeyPairGeneratorInit<P: ?Sized> {
    /// The failure type returned by initialization.
    type Error: core::error::Error;

    /// Initializes the generator, such as with the key size and, for RSA, the
    /// public exponent.
    fn init(&mut self, params: &P) -> Result<(), Self::Error>;
}

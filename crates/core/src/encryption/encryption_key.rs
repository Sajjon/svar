use zeroize::ZeroizeOnDrop;

use crate::prelude::*;

/// A 32 bytes encryption key used for symmetric encryption.
///
/// Zeroizes its contents when dropped.
#[derive(
    ZeroizeOnDrop,
    Zeroize,
    Clone,
    PartialEq,
    Eq,
    derive_more::Display,
    derive_more::Debug,
    derive_more::FromStr,
    Serialize,
    Deserialize,
    Hash,
)]
#[serde(transparent)]
pub struct EncryptionKey(pub Exactly32Bytes);

impl EncryptionKey {
    /// Generates a new `EncryptionKey` using a CSPRNG.
    pub fn generate() -> Self {
        Self::from(Exactly32Bytes::generate())
    }
}

impl From<Exactly32Bytes> for EncryptionKey {
    fn from(value: Exactly32Bytes) -> Self {
        Self(value)
    }
}

impl HasSampleValues for EncryptionKey {
    fn sample() -> Self {
        Self::from(Exactly32Bytes::sample())
    }

    fn sample_other() -> Self {
        Self::from(Exactly32Bytes::sample_other())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Sut = EncryptionKey;

    #[test]
    fn equality() {
        assert_eq!(Sut::sample(), Sut::sample());
        assert_eq!(Sut::sample_other(), Sut::sample_other());
    }

    #[test]
    fn inequality() {
        assert_ne!(Sut::sample(), Sut::sample_other());
    }
}

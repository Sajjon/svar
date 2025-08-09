use crate::prelude::*;

/// The cipher of an AES GCM encryption alongside the nonce used. The cipher contains
/// the encrypted payload and the authentication tag.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct AesGcmSealedBox {
    /// Nonce is 12 bytes
    pub(super) nonce: Exactly12Bytes,

    /// Auth tag and encrypted payload
    pub(super) cipher_text: Vec<u8>,
}

/// The length of the authentication tag.
pub const AUTH_TAG_LEN: usize = 16;

/// The length of the nonce used in AES GCM.
pub const NONCE_LEN: usize = 12;

impl AesGcmSealedBox {
    /// At least 1 byte cipher. VERY much LOWER bound
    pub const LOWER_BOUND_LEN: usize = AUTH_TAG_LEN + NONCE_LEN + 1;

    pub(super) fn combined(self) -> Vec<u8> {
        let mut combined = Vec::<u8>::new();
        let mut nonce = self.nonce.to_vec();
        let mut cipher_text = self.cipher_text;
        combined.append(&mut nonce);
        combined.append(&mut cipher_text);
        assert!(combined.len() >= Self::LOWER_BOUND_LEN);
        combined
    }
}

impl TryFrom<&[u8]> for AesGcmSealedBox {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < Self::LOWER_BOUND_LEN {
            return Err(Error::InvalidAESBytesTooShort {
                expected_at_least: Self::LOWER_BOUND_LEN,
                found: bytes.len(),
            });
        }

        let nonce_bytes = &bytes[..NONCE_LEN];
        let nonce = Exactly12Bytes::try_from(nonce_bytes).unwrap();
        let cipher_text = &bytes[NONCE_LEN..];
        Ok(Self {
            nonce,
            cipher_text: cipher_text.to_owned(),
        })
    }
}

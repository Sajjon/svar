use crate::prelude::*;

/// Versioning of encryption algorithms.
pub trait VersionedEncryption: VersionOfAlgorithm {
    fn encrypt(
        &self,
        plaintext: impl AsRef<[u8]>,
        encryption_key: EncryptionKey,
    ) -> Vec<u8>;

    fn decrypt(
        &self,
        cipher_text: impl AsRef<[u8]>,
        decryption_key: EncryptionKey,
    ) -> Result<Vec<u8>>;
}

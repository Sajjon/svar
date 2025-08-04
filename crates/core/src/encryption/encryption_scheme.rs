use serde::{Deserializer, Serializer, de, ser::SerializeStruct};

use crate::prelude::*;

/// A versioned encryption scheme.
#[derive(Clone, PartialEq, Eq, Hash, derive_more::Debug)]
pub enum EncryptionScheme {
    /// AES GCM 256 encryption
    Version1(AesGcm256),
}

impl HasSampleValues for EncryptionScheme {
    fn sample() -> Self {
        Self::version1()
    }

    fn sample_other() -> Self {
        Self::version1()
    }
}

impl std::fmt::Display for EncryptionScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EncryptionScheme: {} ({})",
            self.version(),
            self.description()
        )
    }
}

impl Serialize for EncryptionScheme {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EncryptionScheme", 2)?;
        state.serialize_field("description", &self.description())?;
        state.serialize_field("version", &self.version())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EncryptionScheme {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize, Serialize)]
        struct Wrapper {
            version: EncryptionSchemeVersion,
        }
        Wrapper::deserialize(deserializer)
            .and_then(|w| Self::try_from(w.version).map_err(de::Error::custom))
    }
}

impl EncryptionScheme {
    pub fn version1() -> Self {
        Self::Version1(AesGcm256::default())
    }
}

impl Default for EncryptionScheme {
    fn default() -> Self {
        Self::version1()
    }
}

impl VersionedEncryption for EncryptionScheme {
    /// Encrypts `plaintext` using `encryption_key` using
    /// the `self` `EncryptionScheme`, returning the cipher text as Vec<u8>.
    fn encrypt(&self, plaintext: impl AsRef<[u8]>, encryption_key: EncryptionKey) -> Vec<u8> {
        match self {
            EncryptionScheme::Version1(scheme) => scheme.encrypt(plaintext, encryption_key),
        }
    }

    /// Tries to decrypt the `cipher_text` using the `decryption_key` according
    /// to the `self` `EncryptionScheme`, returning the plaintext if operation
    /// was successful.
    fn decrypt(
        &self,
        cipher_text: impl AsRef<[u8]>,
        decryption_key: EncryptionKey,
    ) -> Result<Vec<u8>> {
        match self {
            EncryptionScheme::Version1(scheme) => scheme.decrypt(cipher_text, decryption_key),
        }
    }
}

impl TryFrom<EncryptionSchemeVersion> for EncryptionScheme {
    type Error = Error;

    fn try_from(value: EncryptionSchemeVersion) -> Result<Self> {
        match value {
            EncryptionSchemeVersion::Version1 => Ok(Self::version1()),
        }
    }
}

impl VersionOfAlgorithm for EncryptionScheme {
    type Version = EncryptionSchemeVersion;

    fn version(&self) -> Self::Version {
        match self {
            Self::Version1(scheme) => scheme.version(),
        }
    }

    fn description(&self) -> String {
        match self {
            EncryptionScheme::Version1(scheme) => scheme.description(),
        }
    }
}

#[cfg(test)]
mod tests {
    use insta::{assert_json_snapshot, assert_snapshot};

    use super::*;

    type Sut = EncryptionScheme;

    #[test]
    fn display() {
        assert_snapshot!(Sut::default())
    }

    #[test]
    fn json_snapshot() {
        assert_json_snapshot!(Sut::default())
    }

    #[test]
    fn encryption_roundtrip() {
        let sut = Sut::default();
        let encryption_key = EncryptionKey::generate();
        let decryption_key = encryption_key.clone();
        let msg = "open zesame";
        let msg_bytes: Vec<u8> = msg.bytes().collect();

        let encrypted = sut.encrypt(&msg_bytes, encryption_key);
        let decrypted_bytes = sut.decrypt(encrypted, decryption_key).unwrap();

        let decrypted = String::from_utf8(decrypted_bytes).unwrap();
        assert_eq!(msg, decrypted);
    }

    #[test]
    fn decrypt_known() {
        let sut = Sut::default();
        let test = |encrypted_hex: &str, key_hex: &str, expected_plaintext: &str| {
            let decryption_key = EncryptionKey::from_str(key_hex).unwrap();
            let encrypted = hex_decode(encrypted_hex).unwrap();
            let decrypted = sut.decrypt(encrypted, decryption_key).unwrap();
            assert_eq!(hex::encode(decrypted), expected_plaintext);
        };

        test(
            "4c2266de48fd17a4bb52d5883751d054258755ce004154ea204a73a4c35e",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "abba",
        );
    }

    #[test]
    fn decrypt_invalid_sealed_box_is_err() {
        let sut = Sut::default();
        assert_eq!(
            sut.decrypt(Vec::new(), EncryptionKey::sample()),
            Err(Error::InvalidAESBytesTooShort {
                expected_at_least: AesGcmSealedBox::LOWER_BOUND_LEN,
                found: 0
            })
        );
    }
}

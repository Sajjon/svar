use serde::{Deserializer, Serializer, de, ser::SerializeStruct};

use crate::prelude::*;

/// A versioned encryption scheme for secure data encryption.
///
/// This enum represents different encryption algorithms and their versions that
/// can be used to encrypt and decrypt sensitive data. The versioning allows for
/// algorithm upgrades while maintaining backwards compatibility with older
/// encrypted data.
///
/// Currently, only AES-256-GCM is supported, but the versioned design allows
/// for future algorithm additions without breaking existing implementations.
///
/// # Supported Algorithms
///
/// - **Version 1**: AES-256-GCM with 96-bit IV and 128-bit authentication tag
///
/// # Examples
///
/// ## Basic Usage
///
/// ```
/// use svar_core::*;
///
/// let scheme = EncryptionScheme::default();
/// let key = EncryptionKey::generate();
/// let plaintext = b"Hello, World!";
///
/// let encrypted = scheme.encrypt(plaintext, key.clone());
/// let decrypted = scheme.decrypt(&encrypted, key)?;
///
/// assert_eq!(plaintext, &decrypted[..]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// ## Explicit Version Selection
///
/// ```
/// use svar_core::*;
///
/// let scheme_v1 = EncryptionScheme::version1();
/// assert_eq!(scheme_v1.version(), EncryptionSchemeVersion::Version1);
/// ```
///
/// ## Version Comparison
///
/// ```
/// use svar_core::*;
///
/// let scheme1 = EncryptionScheme::version1();
/// let scheme2 = EncryptionScheme::default();
///
/// assert_eq!(scheme1, scheme2); // Default is currently version 1
/// assert_eq!(scheme1.version(), scheme2.version());
/// ```
///
/// # Serialization
///
/// The scheme serializes with version information for proper deserialization:
///
/// ```
/// use svar_core::*;
///
/// let scheme = EncryptionScheme::default();
/// let json = serde_json::to_string(&scheme)?;
///
/// // JSON contains version information
/// assert!(json.contains("version"));
/// assert!(json.contains("description"));
///
/// let restored: EncryptionScheme = serde_json::from_str(&json)?;
/// assert_eq!(scheme, restored);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Algorithm Details
///
/// ## AES-256-GCM (Version 1)
/// - **Key Size**: 256 bits (32 bytes)
/// - **IV Size**: 96 bits (12 bytes) - randomly generated per encryption
/// - **Tag Size**: 128 bits (16 bytes) - provides authentication
/// - **Security**: Provides both confidentiality and authenticity
/// - **Performance**: Hardware-accelerated on most modern processors
///
/// # Security Considerations
///
/// - Each encryption operation uses a fresh random IV
/// - Authentication tag prevents tampering and ensures data integrity
/// - Keys should be derived using strong key derivation functions
/// - Never reuse IV with the same key (automatically prevented)
///
/// # Future Extensibility
///
/// The versioned design allows for:
/// - Algorithm upgrades (e.g., post-quantum cryptography)
/// - Parameter changes (e.g., larger key sizes)
/// - New authentication modes
/// - Backwards compatibility with existing encrypted data
#[derive(Clone, PartialEq, Eq, Hash, derive_more::Debug)]
pub enum EncryptionScheme {
    /// AES-256-GCM encryption (Version 1).
    ///
    /// Uses AES in Galois/Counter Mode with:
    /// - 256-bit key size for strong security
    /// - 96-bit initialization vector (IV)
    /// - 128-bit authentication tag
    /// - AEAD (Authenticated Encryption with Associated Data) properties
    Version1(AesGcm256),
}

/// Display implementation for `EncryptionScheme`.
///
/// Formats the encryption scheme with its version and description for
/// human-readable output.
///
/// # Format
///
/// `EncryptionScheme: {version} ({description})`
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// let scheme = EncryptionScheme::default();
/// let display = format!("{}", scheme);
///
/// // Example output format
/// assert!(display.starts_with("EncryptionScheme:"));
/// assert!(display.contains("Version1"));
/// ```
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
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        #[derive(Deserialize, Serialize)]
        struct Wrapper {
            version: EncryptionSchemeVersion,
        }
        Wrapper::deserialize(deserializer)
            .and_then(|w| Self::try_from(w.version).map_err(de::Error::custom))
    }
}

impl EncryptionScheme {
    /// Creates a Version 1 encryption scheme using AES-256-GCM.
    ///
    /// This method explicitly creates a Version 1 encryption scheme, which uses
    /// AES-256-GCM for authenticated encryption. This is currently the only
    /// supported version but is explicitly versioned for future extensibility.
    ///
    /// # Returns
    ///
    /// A new `EncryptionScheme::Version1` instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let scheme = EncryptionScheme::version1();
    /// assert_eq!(scheme.version(), EncryptionSchemeVersion::Version1);
    ///
    /// // Can be used for encryption
    /// let key = EncryptionKey::generate();
    /// let encrypted = scheme.encrypt(b"test data", key.clone());
    /// assert!(!encrypted.is_empty());
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Algorithm Details
    ///
    /// Version 1 uses AES-256-GCM with:
    /// - 256-bit (32-byte) encryption key
    /// - 96-bit (12-byte) initialization vector per encryption
    /// - 128-bit (16-byte) authentication tag
    /// - Authenticated Encryption with Associated Data (AEAD)
    pub fn version1() -> Self {
        Self::Version1(AesGcm256)
    }
}

/// Default implementation for `EncryptionScheme`.
///
/// Returns the current recommended encryption scheme, which is Version 1
/// (AES-256-GCM). This provides a stable default while allowing for future
/// algorithm upgrades.
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// let default_scheme = EncryptionScheme::default();
/// let explicit_v1 = EncryptionScheme::version1();
///
/// assert_eq!(default_scheme, explicit_v1);
/// assert_eq!(default_scheme.version(), EncryptionSchemeVersion::Version1);
/// ```
///
/// # Stability
///
/// The default may change in future versions as new algorithms are added,
/// but existing encrypted data will remain decryptable using the appropriate
/// versioned scheme.
impl Default for EncryptionScheme {
    fn default() -> Self {
        Self::version1()
    }
}

impl VersionedEncryption for EncryptionScheme {
    /// Encrypts `plaintext` using `encryption_key` using
    /// the `self` `EncryptionScheme`, returning the cipher text as `Vec<u8>`.
    fn encrypt(
        &self,
        plaintext: impl AsRef<[u8]>,
        encryption_key: EncryptionKey,
    ) -> Vec<u8> {
        match self {
            EncryptionScheme::Version1(scheme) => {
                scheme.encrypt(plaintext, encryption_key)
            }
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
            EncryptionScheme::Version1(scheme) => {
                scheme.decrypt(cipher_text, decryption_key)
            }
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
        let test =
            |encrypted_hex: &str, key_hex: &str, expected_plaintext: &str| {
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

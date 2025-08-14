/// A trait for types that can be treated as secrets in the svar encryption
/// system.
///
/// This trait enables any type to be encrypted and decrypted using security
/// questions. Types implementing this trait must be able to convert themselves
/// to and from bytes, as the encryption process operates on byte arrays.
///
/// # Security Considerations
///
/// When implementing this trait:
/// - Ensure the byte representation preserves all necessary information
/// - For sensitive data like mnemonics, use entropy bytes rather than the
///   human-readable form
/// - Consider implementing [`Zeroize`] for the type to clear sensitive data
///   from memory
///
/// # Examples
///
/// ## Basic Implementation for Custom Type
///
/// ```
/// use serde::{Deserialize, Serialize};
/// use svar_core::IsSecret;
///
/// #[derive(Serialize, Deserialize, Clone)]
/// struct MySecret {
///     data: String,
///     number: u64,
/// }
///
/// impl IsSecret for MySecret {
///     fn to_bytes(
///         &self,
///     ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
///         let json = serde_json::to_string(self)?;
///         Ok(json.into_bytes())
///     }
///
///     fn from_bytes(
///         bytes: Vec<u8>,
///     ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
///         let json = String::from_utf8(bytes)?;
///         let secret: MySecret = serde_json::from_str(&json)?;
///         Ok(secret)
///     }
/// }
///
/// // Now you can use MySecret with the encryption system
/// use svar_core::*;
///
/// let secret = MySecret {
///     data: "sensitive info".to_string(),
///     number: 42,
/// };
/// let questions = SecurityQuestionsAnswersAndSalts::sample();
/// let sealed =
///     SecurityQuestionsSealed::<MySecret, 6, 4>::seal(secret, questions)
///         .unwrap();
/// ```
///
/// ## Usage with Built-in Types
///
/// ```
/// use svar_core::*;
///
/// // String secrets
/// let secret = "my secret password".to_string();
/// let questions = SecurityQuestionsAnswersAndSalts::sample();
/// let sealed =
///     SecurityQuestionsSealed::<String, 6, 4>::seal(secret, questions)
///         .unwrap();
///
/// // Byte array secrets
/// let secret = vec![1, 2, 3, 4, 5];
/// let questions = SecurityQuestionsAnswersAndSalts::sample();
/// let sealed =
///     SecurityQuestionsSealed::<Vec<u8>, 6, 4>::seal(secret, questions)
///         .unwrap();
/// ```
///
/// # Error Handling
///
/// Both methods return `Result` types and may fail for various reasons:
/// - [`to_bytes`](IsSecret::to_bytes): Serialization errors, encoding issues
/// - [`from_bytes`](IsSecret::from_bytes): Deserialization errors, invalid data
///   format
///
/// When encryption fails due to secret conversion errors, a
/// [`FailedToConvertSecretToBytes`](crate::Error::FailedToConvertSecretToBytes)
/// or
/// [`FailedToConvertBytesToSecret`](crate::Error::FailedToConvertBytesToSecret)
/// error will be returned.
pub trait IsSecret: Sized {
    /// Convert the secret from its byte representation.
    ///
    /// This method is called during decryption to reconstruct the original
    /// secret from the decrypted byte array.
    ///
    /// # Parameters
    ///
    /// - `bytes`: The byte array representing the secret
    ///
    /// # Returns
    ///
    /// - `Ok(Self)`: Successfully reconstructed secret
    /// - `Err(Box<dyn std::error::Error>)`: Conversion failed
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::IsSecret;
    ///
    /// let original = "hello world".to_string();
    /// let bytes = original.to_bytes().unwrap();
    /// let reconstructed = String::from_bytes(bytes).unwrap();
    /// assert_eq!(original, reconstructed);
    /// ```
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>>;

    /// Convert the secret to its byte representation.
    ///
    /// This method is called during encryption to convert the secret into
    /// a byte array that can be encrypted.
    ///
    /// # Returns
    ///
    /// - `Ok(Vec<u8>)`: Successfully converted to bytes
    /// - `Err(Box<dyn std::error::Error>)`: Conversion failed
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::IsSecret;
    ///
    /// let secret = "hello world".to_string();
    /// let bytes = secret.to_bytes().unwrap();
    /// assert_eq!(bytes, b"hello world");
    /// ```
    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>;
}

/// Implementation of [`IsSecret`] for [`String`].
///
/// Strings are converted to/from bytes using UTF-8 encoding.
/// This is suitable for text-based secrets like passwords, passphrases, or JSON
/// data.
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// let secret = "my secret password".to_string();
/// let questions = SecurityQuestionsAnswersAndSalts::sample();
///
/// // Encrypt the string secret
/// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
///     secret.clone(),
///     questions.clone(),
/// )
/// .unwrap();
///
/// // Decrypt it back
/// let decrypted: String = sealed.decrypt(questions).unwrap();
/// assert_eq!(secret, decrypted);
/// ```
///
/// # Errors
///
/// - [`from_bytes`](IsSecret::from_bytes): Fails if bytes are not valid UTF-8
/// - [`to_bytes`](IsSecret::to_bytes): Never fails for valid strings
impl IsSecret for String {
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        String::from_utf8(bytes).map_err(|e| e.into())
    }

    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.as_bytes().to_vec())
    }
}

/// Implementation of [`IsSecret`] for [`Vec<u8>`].
///
/// Byte vectors are used directly without any conversion.
/// This is suitable for binary secrets like encryption keys, hashes, or
/// arbitrary binary data.
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// let secret = vec![0x01, 0x02, 0x03, 0x04, 0xAB, 0xCD, 0xEF];
/// let questions = SecurityQuestionsAnswersAndSalts::sample();
///
/// // Encrypt the binary secret
/// let sealed = SecurityQuestionsSealed::<Vec<u8>, 6, 4>::seal(
///     secret.clone(),
///     questions.clone(),
/// )
/// .unwrap();
///
/// // Decrypt it back
/// let decrypted: Vec<u8> = sealed.decrypt(questions).unwrap();
/// assert_eq!(secret, decrypted);
/// ```
///
/// # Errors
///
/// - [`from_bytes`](IsSecret::from_bytes): Never fails
/// - [`to_bytes`](IsSecret::to_bytes): Never fails
impl IsSecret for Vec<u8> {
    fn from_bytes(
        bytes: Vec<u8>,
    ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        Ok(bytes)
    }

    fn to_bytes(
        &self,
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    #[test]
    fn vec8() {
        let secret = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let bytes = secret.to_bytes().expect("to_bytes failed");
        let secret_from_bytes =
            Vec::<u8>::from_bytes(bytes).expect("from_bytes failed");
        assert_eq!(secret, secret_from_bytes);
    }
}

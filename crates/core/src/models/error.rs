/// Result type alias for operations that may fail with a `svar-core` error.
///
/// This is a convenience type alias that defaults the error type to [`Error`].
///
/// # Examples
///
/// ```
/// use svar_core::Result;
///
/// fn example_function() -> Result<String> {
///     Ok("success".to_string())
/// }
/// ```
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors that can occur when using the svar-core library.
///
/// This enum represents all possible error conditions that can arise
/// during security question operations, including validation errors,
/// encryption/decryption failures, and format errors.
///
/// # Examples
///
/// ```
/// use svar_core::HasSampleValues;
/// use svar_core::*;
///
/// let result = SecurityQuestionsAnswersAndSalts::<3>::try_from_iter([
///     SecurityQuestionAnswerAndSalt::sample(),
///     SecurityQuestionAnswerAndSalt::sample_other(),
/// ]);
///
/// match result {
///     Err(Error::InvalidQuestionsAndAnswersCount { expected, found }) => {
///         assert_eq!(expected, 3);
///         assert_eq!(found, 2);
///     }
///     _ => panic!("Expected count mismatch error"),
/// }
/// ```
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The number of questions and answers provided does not match the expected
    /// count.
    ///
    /// This error occurs when trying to create a collection of security
    /// questions and answers with a different number of items than required
    /// by the type parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::{
    ///     Error, HasSampleValues, SecurityQuestionAnswerAndSalt,
    ///     SecurityQuestionsAnswersAndSalts,
    /// };
    ///
    /// // Try to create a collection expecting 6 items with only 2
    /// let items = vec![
    ///     SecurityQuestionAnswerAndSalt::sample(),
    ///     SecurityQuestionAnswerAndSalt::sample_other(),
    /// ];
    /// let result: Result<SecurityQuestionsAnswersAndSalts<6>, _> =
    ///     SecurityQuestionsAnswersAndSalts::try_from_iter(items);
    ///
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::InvalidQuestionsAndAnswersCount {
    ///         expected: 6,
    ///         found: 2
    ///     })
    /// ));
    /// ```
    #[error(
        "Invalid questions and answers count: expected {expected}, found {found}"
    )]
    InvalidQuestionsAndAnswersCount { expected: usize, found: usize },

    /// The number of questions and salts provided does not match the expected
    /// count.
    ///
    /// This error occurs when trying to create a collection of security
    /// questions and salts with a different number of items than required.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::{
    ///     Error, HasSampleValues, SecurityQuestionAndSalt,
    ///     SecurityQuestionsAndSalts,
    /// };
    ///
    /// // Try to create a collection expecting 6 items with only 1
    /// let items = vec![SecurityQuestionAndSalt::sample()];
    /// let result: Result<SecurityQuestionsAndSalts<6>, _> =
    ///     SecurityQuestionsAndSalts::try_from_iter(items);
    ///
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::InvalidQuestionsAndSaltCount {
    ///         expected: 6,
    ///         found: 1
    ///     })
    /// ));
    /// ```
    #[error(
        "Invalid questions and salt count: expected {expected}, found {found}"
    )]
    InvalidQuestionsAndSaltCount { expected: usize, found: usize },

    /// An answer was provided for a question that is not part of the security
    /// questions.
    ///
    /// This error occurs during decryption when the provided answers include
    /// a question that was not part of the original set of security questions
    /// used during encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let sealed = SecurityQuestionsSealed::<String>::sample();
    /// let wrong_answers = SecurityQuestionsAnswersAndSalts::sample_other();
    ///
    /// let result = sealed.decrypt(wrong_answers);
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::UnrelatedQuestionProvided { .. })
    /// ));
    /// ```
    #[error(
        "You provided an answer for a question that is not part of the security questions: {question}"
    )]
    UnrelatedQuestionProvided { question: String },

    /// The number of questions must be greater than or equal to the required
    /// answers.
    ///
    /// This error occurs when trying to create an encryption scheme where
    /// more correct answers are required than there are total questions.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// use svar_core::*;
    ///
    /// fn create_invalid_type() {
    ///     // This should fail at compile time when trying to use the type
    ///     let _: SecurityQuestionsSealed<String, 3, 5> =
    ///         SecurityQuestionsSealed::seal("secret".to_string(),
    ///             SecurityQuestionsAnswersAndSalts::<3>::sample()).unwrap();
    /// }
    /// ```
    #[error(
        "Questions must be greater than or equal to answers: {questions} < {answers}"
    )]
    QuestionsMustBeGreaterThanOrEqualAnswers {
        questions: usize,
        answers: usize,
    },

    /// Invalid byte count for a fixed-size byte array.
    ///
    /// This error occurs when trying to create a fixed-size byte array
    /// (like [`Exactly32Bytes`](crate::Exactly32Bytes)) with the wrong number
    /// of bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::{Error, Exactly32Bytes};
    ///
    /// let result = Exactly32Bytes::try_from(vec![1, 2, 3]); // Only 3 bytes
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::InvalidByteCount {
    ///         expected: 32,
    ///         found: 3
    ///     })
    /// ));
    /// ```
    #[error("Invalid byte count: expected {expected}, found {found}")]
    InvalidByteCount { expected: usize, found: usize },

    /// AES decryption operation failed.
    ///
    /// This error occurs when the AES decryption algorithm fails,
    /// typically due to incorrect keys or corrupted ciphertext.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let scheme = EncryptionScheme::default();
    /// let key = Exactly32Bytes::generate();
    /// let invalid_ciphertext = vec![1, 2, 3]; // Too short for valid AES data
    ///
    /// let result = scheme.decrypt(&invalid_ciphertext, EncryptionKey(key));
    /// assert!(result.is_err());
    /// ```
    #[error("AES Decryption failed: {underlying}")]
    AESDecryptionFailed { underlying: String },

    /// Invalid mnemonic phrase format or content.
    ///
    /// This error occurs when trying to parse or use a mnemonic phrase
    /// that doesn't conform to the expected format or contains invalid words.
    #[error("Invalid mnemonic phrase: {underlying}")]
    InvalidMnemonicPhrase { underlying: String },

    /// Failed to convert a secret to its byte representation.
    ///
    /// This error occurs when a type implementing [`IsSecret`](crate::IsSecret)
    /// fails to serialize itself to bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// struct FailingSecret;
    /// impl IsSecret for FailingSecret {
    ///     fn to_bytes(
    ///         &self,
    ///     ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    ///         Err("conversion failed".into())
    ///     }
    ///     fn from_bytes(
    ///         _: Vec<u8>,
    ///     ) -> std::result::Result<Self, Box<dyn std::error::Error>> {
    ///         unreachable!()
    ///     }
    /// }
    ///
    /// let secret = FailingSecret;
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let result =
    ///     SecurityQuestionsSealed::<FailingSecret, 6, 4>::seal(secret, questions);
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::FailedToConvertSecretToBytes { .. })
    /// ));
    /// ```
    #[error("Failed to convert secret to bytes: {underlying}")]
    FailedToConvertSecretToBytes { underlying: String },

    /// Failed to convert bytes back to a secret.
    ///
    /// This error occurs when a type implementing [`IsSecret`](crate::IsSecret)
    /// fails to deserialize itself from bytes during decryption.
    #[error("Failed to convert bytes to secret: {underlying}")]
    FailedToConvertBytesToSecret { underlying: String },

    /// Invalid hexadecimal string format.
    ///
    /// This error occurs when trying to parse a string as hexadecimal
    /// but it contains invalid characters or has an invalid length.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    /// use svar_core::{Error, HexBytes};
    ///
    /// let result = HexBytes::from_str("invalid_hex");
    /// assert!(matches!(result, Err(Error::InvalidHex { .. })));
    /// ```
    #[error("Invalid hex: {underlying}")]
    InvalidHex { underlying: String },

    /// Failed to decrypt a sealed secret.
    ///
    /// This error occurs when none of the provided answers result in
    /// successful decryption, typically because too many answers are incorrect
    /// or the sealed secret is corrupted.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let sealed = SecurityQuestionsSealed::<String>::sample();
    /// let wrong_answers = SecurityQuestionsAnswersAndSalts::sample_other();
    ///
    /// let result = sealed.decrypt(wrong_answers);
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::UnrelatedQuestionProvided { .. })
    /// ));
    /// ```
    #[error("Failed to decrypt sealed secret")]
    FailedToDecryptSealedSecret,

    /// AES ciphertext is too short to be valid.
    ///
    /// This error occurs when the provided ciphertext doesn't contain
    /// enough bytes to include the required AES components (IV, tag, etc.).
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let scheme = EncryptionScheme::default();
    /// let key = Exactly32Bytes::generate();
    /// let too_short = vec![1, 2]; // Much too short for AES-GCM
    ///
    /// let result = scheme.decrypt(&too_short, EncryptionKey(key));
    /// assert!(result.is_err());
    /// ```
    #[error(
        "Invalid AES bytes too short: expected at least {expected_at_least}, found {found}"
    )]
    InvalidAESBytesTooShort {
        expected_at_least: usize,
        found: usize,
    },

    /// Answers to security questions cannot be empty.
    ///
    /// This error occurs when trying to provide an empty answer to a security
    /// question, which is not allowed as it would provide no entropy for
    /// the encryption.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::sample();
    /// let result = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    ///     question,
    ///     |_, _| "".to_string(), // Empty answer
    /// );
    /// assert_eq!(result, Err(Error::AnswersToSecurityQuestionsCannotBeEmpty));
    /// ```
    #[error("Answers to security questions cannot be empty")]
    AnswersToSecurityQuestionsCannotBeEmpty,
}

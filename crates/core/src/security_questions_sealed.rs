use crate::prelude::*;

/// Default number of security questions used in the encryption scheme.
///
/// This constant defines the recommended number of security questions
/// for a good balance between security and usability.
pub const DEFAULT_QUESTION_COUNT: usize = 6;

/// Default minimum number of correct answers required for decryption.
///
/// This constant defines the recommended threshold for successful decryption,
/// allowing some questions to be answered incorrectly while still maintaining
/// security.
pub const DEFAULT_MIN_CORRECT_ANSWERS: usize = 4;

/// A secret encrypted using security questions and their answers.
///
/// This is the main type in the svar-core library. It represents a secret that
/// has been encrypted using answers to security questions, allowing for
/// fault-tolerant decryption where some answers can be incorrect.
///
/// # Type Parameters
///
/// - `Secret`: The type of secret being encrypted (must implement [`IsSecret`])
/// - `QUESTION_COUNT`: The total number of security questions (default: 6)
/// - `MIN_CORRECT_ANSWERS`: Minimum correct answers needed for decryption
///   (default: 4)
///
/// # Security Model
///
/// The security is based on the entropy of the security question answers
/// combined with cryptographic salts. The system:
/// - Derives multiple encryption keys from different combinations of
///   question/answer pairs
/// - Encrypts the secret with each derived key
/// - Requires at least `MIN_CORRECT_ANSWERS` correct answers for successful
///   decryption
///
/// # Examples
///
/// ## Basic Usage
///
/// ```
/// use svar_core::*;
///
/// // Create questions and answers
/// let questions_and_answers = SecurityQuestionsAnswersAndSalts::sample();
///
/// // Encrypt a secret
/// let secret = "my secret data".to_string();
/// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
///     secret.clone(),
///     questions_and_answers.clone(),
/// )?;
///
/// // Decrypt the secret
/// let decrypted: String = sealed.decrypt(questions_and_answers)?;
/// assert_eq!(secret, decrypted);
/// # Ok::<(), svar_core::Error>(())
/// ```
///
/// ## Fault Tolerance
///
/// Works even if some answers are incorrect
/// ```
/// use svar_core::*;
/// const Q: usize = 4;
/// const A: usize = 3;
///
/// // The secret the user wants to protect
/// let user_secret = "user's super sensitive secret".to_owned();
///
/// let q0 = SecurityQuestion::first_concert();
/// let q1 = SecurityQuestion::math_teacher_highschool();
/// let q2 = SecurityQuestion::stuffed_animal();
/// let q3 = SecurityQuestion::teacher_grade3();
///
/// // Prompt user for answers to the questions
/// let qas0 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     q0.clone(),
///     |_q, _format| "Queen, Wembly Stadium, 1985".to_owned(),
/// )
/// .unwrap();
///
/// let qas1 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     q1.clone(),
///     |_q, _format| "Smith, Sara".to_owned(),
/// )
/// .unwrap();
///
/// let qas2 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     q2.clone(),
///     |_q, _format| "Fluffy McSnuggles".to_owned(),
/// )
/// .unwrap();
///
/// let qas3 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     q3.clone(),
///     |_q, _format| "Thompson, Margot".to_owned(),
/// )
/// .unwrap();
///
/// // Create the security questions answers and salts
/// // (We clone so that we can use them later for decryption)
/// let qas = SecurityQuestionsAnswersAndSalts::<Q>::from([
///     qas0.clone(),
///     qas1.clone(),
///     qas2.clone(),
///     qas3.clone(),
/// ]);
///
/// // Encrypt secret with the security questions answers and salts
/// // The generic argument 0: the type of secret - just a String in this case
/// // The generic argument 1: the number of questions - 4 in this case
/// // The generic argument 2: the minimum number of correct answers required
/// // to decrypt - 3 in this case
/// //
/// // Later, when the user wants to decrypt the secret, they can answer the
/// // questions with some of the answers being incorrect
/// let sealed_secret =
///     SecurityQuestionsSealed::<String, Q, A>::seal(user_secret.clone(), qas)
///         .unwrap();
///
/// // Define incorrect answer for question 0 - we will use it later to
/// // demonstrate that we can still decrypt the secret with 3 correct answers
/// // and 1 incorrect answer
/// let qas0_incorrect = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     q0.clone(),
///     |_q, _format| "Incorrect answer for Q0".to_owned(),
/// )
/// .unwrap();
///
/// let qas_q0_incorrect = SecurityQuestionsAnswersAndSalts::<Q>::from([
///     qas0_incorrect.clone(),
///     qas1.clone(),
///     qas2.clone(),
///     qas3.clone(),
/// ]);
///
/// // Decrypt the secret with the security questions answers and salts - this
/// // works even thought we provided one incorrect answer
/// let decrypted_secret = sealed_secret.decrypt(qas_q0_incorrect).unwrap();
/// assert_eq!(decrypted_secret, user_secret);
/// ```
///
/// ## Wrong Questions and answers
/// ```
/// use svar_core::*;
///
/// // Encrypt with default parameters (6 questions, 4 minimum correct)
/// let questions_and_answers = SecurityQuestionsAnswersAndSalts::sample();
/// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
///     "secret".to_string(),
///     questions_and_answers.clone(),
/// )?;
///
/// // Use different answers - this would fail if too many are wrong
/// let other_answers = SecurityQuestionsAnswersAndSalts::sample_other();
///
/// // This will fail because the answers are completely different
/// assert!(sealed.decrypt(other_answers).is_err());
/// # Ok::<(), svar_core::Error>(())
/// ```
///
/// # Serialization
///
/// `SecurityQuestionsSealed` implements [`Serialize`] and [`Deserialize`],
/// making it easy to store and transmit encrypted secrets:
///
/// ```
/// use svar_core::*;
///
/// let sealed = SecurityQuestionsSealed::<String>::sample();
///
/// // Serialize to JSON
/// let json = serde_json::to_string(&sealed)?;
///
/// // Deserialize from JSON
/// let restored: SecurityQuestionsSealed<String> =
///     serde_json::from_str(&json)?;
/// assert_eq!(sealed, restored);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Security Considerations
///
/// - **Question Quality**: The security depends heavily on the entropy of the
///   questions and answers
/// - **Salt Storage**: The security questions and salts are stored with the
///   encrypted secret
/// - **Answer Validation**: Consider implementing answer normalization (case,
///   whitespace, etc.)
/// - **Backup**: Store multiple encrypted copies or use additional recovery
///   methods
///
/// # Error Conditions
///
/// Encryption can fail with:
/// - [`FailedToConvertSecretToBytes`](Error::FailedToConvertSecretToBytes):
///   Secret serialization failed
/// - [`InvalidQuestionsAndAnswersCount`](Error::InvalidQuestionsAndAnswersCount): Wrong number of questions
///
/// Decryption can fail with:
/// - [`FailedToDecryptSealedSecret`](Error::FailedToDecryptSealedSecret): Too
///   many wrong answers
/// - [`UnrelatedQuestionProvided`](Error::UnrelatedQuestionProvided): Question
///   not in original set
/// - [`FailedToConvertBytesToSecret`](Error::FailedToConvertBytesToSecret):
///   Secret deserialization failed
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SecurityQuestionsSealed<
    Secret: IsSecret,
    const QUESTION_COUNT: usize = DEFAULT_QUESTION_COUNT,
    const MIN_CORRECT_ANSWERS: usize = DEFAULT_MIN_CORRECT_ANSWERS,
> {
    /// Holds the type of the secret, used for serialization
    #[serde(skip)]
    phantom: std::marker::PhantomData<Secret>,

    /// The security questions and their cryptographic salts.
    ///
    /// These are stored with the encrypted secret so that during decryption,
    /// the system knows which questions to expect answers for and can use
    /// the same salts that were used during encryption.
    pub security_questions_and_salts: SecurityQuestionsAndSalts<QUESTION_COUNT>,

    /// The Key Derivation Function (KDF) algorithm configuration.
    ///
    /// This determines how encryption keys are derived from the combination
    /// of security questions, answers, and salts. The scheme is versioned
    /// to allow for future cryptographic upgrades.
    pub kdf_scheme: SecurityQuestionsKdfScheme,

    /// The encryption algorithm configuration.
    ///
    /// This specifies which encryption algorithm (e.g., AES-256-GCM) is used
    /// to encrypt the secret with the keys derived from the KDF.
    pub encryption_scheme: EncryptionScheme,

    /// The encrypted secret data.
    ///
    /// Contains multiple encrypted versions of the same secret, each encrypted
    /// with a different key derived from various combinations of question
    /// answers. This redundancy enables fault-tolerant decryption.
    pub encryptions: IndexSet<HexBytes>,
}

impl<
    Secret: IsSecret,
    const QUESTION_COUNT: usize,
    const MIN_CORRECT_ANSWERS: usize,
> SecurityQuestionsSealed<Secret, QUESTION_COUNT, MIN_CORRECT_ANSWERS>
{
    /// Encrypts a secret using security questions and their answers with
    /// default schemes.
    ///
    /// This is the primary method for creating a new `SecurityQuestionsSealed`.
    /// It encrypts the provided secret using answers to security questions
    /// with default cryptographic schemes (Argon2id for key derivation and
    /// AES-256-GCM for encryption).
    ///
    /// The encryption process generates multiple encryption keys from different
    /// combinations of question/answer pairs, providing redundancy for
    /// fault-tolerant decryption where some answers can be incorrect.
    ///
    /// # Parameters
    ///
    /// - `secret`: The secret to encrypt (must implement [`IsSecret`])
    /// - `with`: The security questions, answers, and salts
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the encrypted secret or an error if
    /// encryption fails.
    ///
    /// # Examples
    ///
    /// ## Basic Encryption
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let secret = "my confidential data".to_string();
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    ///
    /// let sealed =
    ///     SecurityQuestionsSealed::<String, 6, 4>::seal(secret, questions)?;
    /// assert!(!sealed.encryptions.is_empty());
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Encrypting Binary Data
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let secret_bytes = vec![0x42, 0x43, 0x44, 0x45];
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    ///
    /// let sealed = SecurityQuestionsSealed::<Vec<u8>, 6, 4>::seal(
    ///     secret_bytes,
    ///     questions,
    /// )?;
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - [`InvalidQuestionsAndAnswersCount`](Error::InvalidQuestionsAndAnswersCount):
    ///   Wrong number of questions provided
    /// - [`FailedToConvertSecretToBytes`](Error::FailedToConvertSecretToBytes):
    ///   Secret serialization failed
    /// - Cryptographic operations fail during key derivation or encryption
    ///
    /// # Security Notes
    ///
    /// - Each question/answer pair contributes to the overall security
    /// - The same secret encrypted with different questions will produce
    ///   different ciphertexts
    /// - Salts ensure that identical answers produce different encryption keys
    ///   across encryptions
    pub fn seal(
        secret: Secret,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Self> {
        Self::with_schemes(
            secret,
            with,
            SecurityQuestionsKdfScheme::default(),
            EncryptionScheme::default(),
        )
    }

    /// Just an alias for `seal` method. See [`seal`](Self::seal) for details.
    pub fn encrypt(
        secret: Secret,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Self> {
        Self::seal(secret, with)
    }

    /// Encrypts a secret using security questions with custom cryptographic
    /// schemes.
    ///
    /// This method provides full control over the cryptographic algorithms used
    /// for key derivation and encryption. It's useful when you need to use
    /// specific cryptographic schemes or when upgrading encryption
    /// parameters.
    ///
    /// # Parameters
    ///
    /// - `secret`: The secret to encrypt (must implement [`IsSecret`])
    /// - `with`: The security questions, answers, and salts
    /// - `kdf_scheme`: The key derivation function scheme to use
    /// - `encryption_scheme`: The encryption algorithm scheme to use
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the encrypted secret or an error if
    /// encryption fails.
    ///
    /// # Errors
    ///
    /// Returns the same errors as `seal`, plus any errors specific
    /// to the custom cryptographic schemes provided.
    ///
    /// # Security Notes
    ///
    /// - Choose KDF parameters based on your security requirements and
    ///   performance constraints
    /// - Higher memory/time costs provide better security against brute force
    ///   attacks
    /// - Ensure the encryption scheme is appropriate for your security model
    fn with_schemes(
        secret: Secret,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
        kdf_scheme: SecurityQuestionsKdfScheme,
        encryption_scheme: EncryptionScheme,
    ) -> Result<Self> {
        let questions_answers_and_salts = with;

        // Clone the security questions from the answers and salts, we need to
        // store them in the sealed secret
        let security_questions_and_salts = questions_answers_and_salts
            .iter()
            .map(|qa| qa.question_and_salt())
            .collect::<IndexSet<SecurityQuestionAndSalt>>();

        let security_questions_and_salts =
            SecurityQuestionsAndSalts::<QUESTION_COUNT>::try_from_iter(
                security_questions_and_salts,
            )?;

        // Derive the encryption keys from the questions, answers and salts
        let encryption_keys = kdf_scheme
            .derive_encryption_keys_from_questions_answers_and_salts::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>(questions_answers_and_salts)?;

        let secret_bytes = secret.to_bytes().map_err(|e| {
            Error::FailedToConvertSecretToBytes {
                underlying: e.to_string(),
            }
        })?;

        // Encrypt the secret with each of the derived encryption keys
        let encryptions = encryption_keys
            .into_iter()
            .map(|encryption_key| {
                encryption_scheme.encrypt(&secret_bytes, encryption_key)
            })
            .map(HexBytes::from)
            .collect::<IndexSet<HexBytes>>();

        // Create the sealed secret with the security questions, encryptions,
        // KDF scheme and encryption scheme
        let sealed = Self {
            phantom: std::marker::PhantomData,
            security_questions_and_salts,
            encryptions,
            kdf_scheme,
            encryption_scheme,
        };

        Ok(sealed)
    }

    /// Checks if the provided answers to security questions are relevant by
    /// checking if they answer the questions that were used to encrypt the
    /// secret.
    fn are_all_answers_relevant(
        &self,
        answers_to_question: &SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<()> {
        let irrelevant_question = answers_to_question.iter().find(|qa| {
            !self
                .security_questions_and_salts
                .iter()
                .any(|saved| saved.question == qa.question)
        });

        if let Some(qa) = irrelevant_question {
            return Err(Error::UnrelatedQuestionProvided {
                question: qa.question.to_string(),
            });
        }

        Ok(())
    }

    /// Decrypts the sealed secret using answers to security questions.
    ///
    /// This method attempts to decrypt the sealed secret by trying different
    /// combinations of the provided answers. It requires at least
    /// `MIN_CORRECT_ANSWERS` correct answers to succeed, allowing for some
    /// fault tolerance in the decryption process.
    ///
    /// # Parameters
    ///
    /// - `with`: The security questions and their answers (must match the
    ///   original questions)
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the decrypted secret or an error if
    /// decryption fails.
    ///
    /// # Examples
    ///
    /// ## Successful Decryption
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let secret = "my secret".to_string();
    ///
    /// // Encrypt the secret
    /// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
    ///     secret.clone(),
    ///     questions.clone(),
    /// )?;
    ///
    /// // Decrypt with the same answers
    /// let decrypted: String = sealed.decrypt(questions)?;
    /// assert_eq!(secret, decrypted);
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Fault Tolerance
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// // Assume we have 6 questions requiring 4 correct answers
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
    ///     "secret".to_string(),
    ///     questions.clone(),
    /// )?;
    ///
    /// // In practice, if 4 out of 6 answers are correct, decryption succeeds
    /// // For this example, we use the same questions (all correct)
    /// let decrypted: String = sealed.decrypt(questions)?;
    /// assert_eq!(decrypted, "secret");
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Different Secret Types
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// // Decrypt binary data
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let secret_bytes = vec![0x42, 0x43, 0x44];
    ///
    /// let sealed = SecurityQuestionsSealed::<Vec<u8>, 6, 4>::seal(
    ///     secret_bytes.clone(),
    ///     questions.clone(),
    /// )?;
    /// let decrypted: Vec<u8> = sealed.decrypt(questions)?;
    /// assert_eq!(secret_bytes, decrypted);
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Error Examples
    ///
    /// ## Too Many Wrong Answers
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let correct_questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
    ///     "secret".to_string(),
    ///     correct_questions.clone(),
    /// )?;
    ///
    /// // Create wrong answers but with same questions
    /// let mut wrong_answers = correct_questions.clone();
    /// for answer_and_salt in wrong_answers.iter_mut() {
    ///     answer_and_salt.answer = "wrong answer".to_string();
    /// }
    ///
    /// match sealed.decrypt(wrong_answers) {
    ///     Err(Error::FailedToDecryptSealedSecret) => {
    ///         // Expected - too many wrong answers
    ///     }
    ///     _ => panic!("Should have failed with too many wrong answers"),
    /// }
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Unrelated Questions
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let questions1 = SecurityQuestionsAnswersAndSalts::sample();
    /// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
    ///     "secret".to_string(),
    ///     questions1,
    /// )?;
    ///
    /// // Use completely different questions
    /// let questions2 = SecurityQuestionsAnswersAndSalts::sample_other();
    ///
    /// match sealed.decrypt(questions2) {
    ///     Err(Error::UnrelatedQuestionProvided { question }) => {
    ///         // Expected - question not in original set
    ///     }
    ///     _ => panic!("Should have failed with unrelated question"),
    /// }
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Example with Different Questions
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let questions1 = SecurityQuestionsAnswersAndSalts::sample();
    /// let sealed = SecurityQuestionsSealed::<String, 6, 4>::seal(
    ///     "secret".to_string(),
    ///     questions1,
    /// )?;
    ///
    /// // Use completely different questions
    /// let questions2 = SecurityQuestionsAnswersAndSalts::sample_other();
    ///
    /// match sealed.decrypt(questions2) {
    ///     Err(Error::UnrelatedQuestionProvided { question }) => {
    ///         // Expected - question not in original set
    ///     }
    ///     _ => panic!("Should have failed with unrelated question"),
    /// }
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// This method can return the following errors:
    ///
    /// * UnrelatedQuestionProvided: One or more questions do not match the
    ///   original questions used for encryption
    /// * FailedToDecryptSealedSecret: Too many incorrect answers provided
    ///   (fewer than MIN_CORRECT_ANSWERS correct)
    /// * FailedToConvertBytesToSecret: Decryption succeeded but secret
    ///   deserialization failed
    ///
    /// # Algorithm Details
    ///
    /// The decryption process:
    /// 1. Validates that all provided questions match the original questions
    /// 2. Derives decryption keys from all possible combinations of answers
    /// 3. Attempts to decrypt each encrypted version with each derived key
    /// 4. Returns the first successful decryption and deserialization
    ///
    /// # Security Notes
    ///
    /// - The method reveals no information about which specific answers are
    ///   correct
    /// - Failed decryption attempts do not indicate which questions were
    ///   answered incorrectly
    /// - The fault tolerance threshold (MIN_CORRECT_ANSWERS) provides a balance
    ///   between security and usability
    pub fn open(
        &self,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Secret> {
        let answers_to_question = with;

        self.are_all_answers_relevant(&answers_to_question)?;

        let decryption_keys = self
            .kdf_scheme
            .derive_encryption_keys_from_questions_answers_and_salts::<
                QUESTION_COUNT,
                MIN_CORRECT_ANSWERS
            >(answers_to_question)?;

        let decryption_scheme = &self.encryption_scheme;

        let mut successful_decryption_failure_deserializing: Option<Error> =
            None;

        for decryption_key in decryption_keys.into_iter() {
            for encrypted in self.encryptions.iter() {
                if let Ok(decrypted) = decryption_scheme
                    .decrypt(encrypted.as_ref(), decryption_key.clone())
                {
                    match Secret::from_bytes(decrypted) {
                        Ok(secret) => return Ok(secret),
                        Err(deserialize_fail) => {
                            successful_decryption_failure_deserializing =
                                Some(Error::FailedToConvertBytesToSecret {
                                    underlying: deserialize_fail.to_string(),
                                });
                        }
                    }
                }
                // Else continue to the next encrypted/key combination
            }
        }

        // Failure
        if let Some(deserialize_err) =
            successful_decryption_failure_deserializing
        {
            // We actual did successful **decrypt** at least one combination,
            // but we failed to deserialize the bytes into the Secret type,
            // so instead of throwing a generic `FailedToDecryptSealedSecret`
            // error we throw the deserialization one.
            Err(deserialize_err)
        } else {
            Err(Error::FailedToDecryptSealedSecret)
        }
    }

    /// Just an alias for `open` method. See [`open`](Self::open) for details.
    pub fn decrypt(
        &self,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Secret> {
        self.open(with)
    }
}

/// Sample implementation for `SecurityQuestionsSealed<String, 6, 4>`.
///
/// Provides sample instances for testing and demonstration purposes. These
/// samples use predefined mnemonic phrases and security questions to create
/// reproducible test data.
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// // Create a sample sealed secret
/// let sample = SecurityQuestionsSealed::<String, 6, 4>::sample();
/// assert!(!sample.encryptions.is_empty());
///
/// // Create an alternative sample
/// let other_sample = SecurityQuestionsSealed::<String, 6, 4>::sample_other();
/// assert_ne!(sample, other_sample);
/// ```
impl HasSampleValues for SecurityQuestionsSealed<String, 6, 4> {
    /// Creates a sample sealed secret using a standard test mnemonic.
    ///
    /// Uses the mnemonic phrase "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo
    /// wrong" with sample security questions and answers. This provides a
    /// consistent test case for development and testing.
    ///
    /// # Returns
    ///
    /// A `SecurityQuestionsSealed` instance with the sample mnemonic encrypted
    /// using default cryptographic schemes.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let sample = SecurityQuestionsSealed::<String, 6, 4>::sample();
    ///
    /// // Can be decrypted with the matching sample questions
    /// let questions = SecurityQuestionsAnswersAndSalts::sample();
    /// let decrypted: String = sample.decrypt(questions)?;
    /// assert_eq!(
    ///     decrypted,
    ///     "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
    /// );
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the sample data is invalid, which should never happen in
    /// practice.
    fn sample() -> Self {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample();
        let kdf_scheme = SecurityQuestionsKdfScheme::default();
        let encryption_scheme = EncryptionScheme::default();
        Self::with_schemes(
            mnemonic.to_string(),
            questions_answers_and_salts,
            kdf_scheme,
            encryption_scheme,
        )
        .expect("Should have been able to create a sample")
    }

    /// Creates an alternative sample sealed secret using a different test
    /// mnemonic.
    ///
    /// Uses the mnemonic phrase "abandon abandon abandon abandon abandon
    /// abandon abandon abandon abandon abandon abandon about" with
    /// different sample security questions and answers. This provides a
    /// second consistent test case.
    ///
    /// # Returns
    ///
    /// A `SecurityQuestionsSealed` instance with the alternative sample
    /// mnemonic encrypted using default cryptographic schemes.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let sample = SecurityQuestionsSealed::<String, 6, 4>::sample_other();
    ///
    /// // Can be decrypted with the matching alternative sample questions
    /// let questions = SecurityQuestionsAnswersAndSalts::sample_other();
    /// let decrypted: String = sample.decrypt(questions)?;
    /// assert_eq!(decrypted, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if the sample data is invalid, which should never happen in
    /// practice.
    fn sample_other() -> Self {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample_other();
        let kdf_scheme = SecurityQuestionsKdfScheme::default();
        let encryption_scheme = EncryptionScheme::default();
        Self::with_schemes(
            mnemonic.to_string(),
            questions_answers_and_salts,
            kdf_scheme,
            encryption_scheme,
        )
        .expect("Should have been able to create a sample")
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type Sut = SecurityQuestionsSealed<String>;

    #[test]
    fn serialize() {
        let json = include_str!(
            "fixtures/svar_core__security_questions_sealed__tests__serialize.json"
        );
        let sut: Sut =
            serde_json::from_str(json).expect("Failed to deserialize");
        let decrypted: String = sut
            .open(SecurityQuestionsAnswersAndSalts::sample())
            .unwrap();
        assert_eq!(
            decrypted,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }

    #[test]
    fn equality() {
        let json = include_str!(
            "fixtures/svar_core__security_questions_sealed__tests__serialize.json"
        );
        let sut: Sut =
            serde_json::from_str(json).expect("Failed to deserialize");
        assert_eq!(sut, sut);
    }

    #[test]
    fn inequality() {
        assert_ne!(Sut::sample(), Sut::sample_other());
    }

    #[test]
    fn decryption_fails_too_many_incorrect_answers() {
        let sealed = Sut::sample();
        let answers = SecurityQuestionsAnswersAndSalts::sample_wrong_answers();
        let result = sealed.open(answers);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::FailedToDecryptSealedSecret);
    }

    #[test]
    fn unrelated_question_provided() {
        let sealed = Sut::sample();
        let answers = SecurityQuestionsAnswersAndSalts::sample_other();
        let result = sealed.open(answers);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::UnrelatedQuestionProvided {
                question: SecurityQuestion::child_middle_name().to_string()
            }
        );
    }

    #[test]
    fn seal_open_roundtrip() {
        let secret = "such secret much wow".to_owned();
        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample();
        let sealed =
            Sut::seal(secret.clone(), questions_answers_and_salts.clone())
                .unwrap();
        let decrypted = sealed.open(questions_answers_and_salts).unwrap();
        assert_eq!(decrypted, secret);
    }

    #[test]
    fn seal_secret_type_fails_to_serialize_to_bytes() {
        #[derive(Debug)]
        struct Secret;
        impl IsSecret for Secret {
            fn to_bytes(
                &self,
            ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>
            {
                Err("meant to fail for test".into())
            }

            fn from_bytes(
                _: Vec<u8>,
            ) -> std::result::Result<Self, Box<dyn std::error::Error>>
            {
                unreachable!()
            }
        }
        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample();
        let result = SecurityQuestionsSealed::<Secret>::seal(
            Secret,
            questions_answers_and_salts,
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::FailedToConvertSecretToBytes {
                underlying: "meant to fail for test".to_owned()
            }
        );
    }

    #[test]
    fn open_sealed_secret_type_fails_to_deserialize_from_bytes() {
        #[derive(Debug)]
        struct Secret;
        impl IsSecret for Secret {
            fn to_bytes(
                &self,
            ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>>
            {
                Ok(vec![0xde, 0xad, 0xbe, 0xef])
            }

            fn from_bytes(
                _: Vec<u8>,
            ) -> std::result::Result<Self, Box<dyn std::error::Error>>
            {
                Err("meant to fail for test".into())
            }
        }
        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample();
        let sealed = SecurityQuestionsSealed::<Secret>::seal(
            Secret,
            questions_answers_and_salts.clone(),
        )
        .unwrap();
        let result = sealed.open(questions_answers_and_salts);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::FailedToConvertBytesToSecret {
                underlying: "meant to fail for test".to_owned()
            }
        );
    }

    #[test]
    fn decryption_works_even_one_answer_is_wrong() {
        const Q: usize = 4;
        const A: usize = 3;

        // The secret the user wants to protect
        let user_secret = "user's super sensitive secret".to_owned();

        let q0 = SecurityQuestion::first_concert();
        let q1 = SecurityQuestion::math_teacher_highschool();
        let q2 = SecurityQuestion::stuffed_animal();
        let q3 = SecurityQuestion::teacher_grade3();

        // Prompt user for answers to the questions
        let qas0 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            q0.clone(),
            |_q, _format| "Queen, Wembly Stadium, 1985".to_owned(),
        )
        .unwrap();

        let qas1 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            q1.clone(),
            |_q, _format| "Smith, Sara".to_owned(),
        )
        .unwrap();

        let qas2 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            q2.clone(),
            |_q, _format| "Fluffy McSnuggles".to_owned(),
        )
        .unwrap();

        let qas3 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            q3.clone(),
            |_q, _format| "Thompson, Margot".to_owned(),
        )
        .unwrap();

        // Create the security questions answers and salts
        // (We clone so that we can use them later for decryption)
        let qas = SecurityQuestionsAnswersAndSalts::<Q>::from([
            qas0.clone(),
            qas1.clone(),
            qas2.clone(),
            qas3.clone(),
        ]);

        // Encrypt secret with the security questions answers and salts
        // The generic argument 0: the type of secret - just a String in this
        // case The generic argument 1: the number of questions - 4 in
        // this case The generic argument 2: the minimum number of
        // correct answers required to decrypt - 3 in this case
        //
        // Later, when the user wants to decrypt the secret, they can answer the
        // questions with some of the answers being incorrect
        let sealed_secret = SecurityQuestionsSealed::<String, Q, A>::seal(
            user_secret.clone(),
            qas,
        )
        .unwrap();

        // Define incorrect answer for question 0 - we will use it later to
        // demonstrate that we can still decrypt the secret with 3 correct
        // answers and 1 incorrect answer
        let qas0_incorrect =
            SecurityQuestionAnswerAndSalt::by_answering_freeform(
                q0.clone(),
                |_q, _format| "Incorrect answer for Q0".to_owned(),
            )
            .unwrap();

        let qas_q0_incorrect = SecurityQuestionsAnswersAndSalts::<Q>::from([
            qas0_incorrect.clone(),
            qas1.clone(),
            qas2.clone(),
            qas3.clone(),
        ]);

        // Decrypt the secret with the security questions answers and salts -
        // this works even thought we provided one incorrect answer
        let decrypted_secret = sealed_secret.open(qas_q0_incorrect).unwrap();

        assert_eq!(decrypted_secret, user_secret);
    }

    #[test]
    fn test_that_encrypt_is_just_an_alias_for_seal() {
        let secret = "such secret much wow".to_owned();
        let questions_answers_and_salts =
            SecurityQuestionsAnswersAndSalts::sample();
        let sealed_by_encrypt =
            Sut::encrypt(secret.clone(), questions_answers_and_salts.clone())
                .unwrap();
        let sealed_by_seal: SecurityQuestionsSealed<String, 6, 4> =
            Sut::seal(secret.clone(), questions_answers_and_salts.clone())
                .unwrap();

        let decrypted_by_open = sealed_by_encrypt
            .open(questions_answers_and_salts.clone())
            .unwrap();
        let decrypted_by_decrypt = sealed_by_seal
            .decrypt(questions_answers_and_salts.clone())
            .unwrap();
        assert_eq!(decrypted_by_open, secret);
        assert_eq!(decrypted_by_decrypt, secret);
        assert_eq!(decrypted_by_decrypt, decrypted_by_open);
    }
}

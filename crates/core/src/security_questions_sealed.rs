use crate::prelude::*;

pub const DEFAULT_QUESTION_COUNT: usize = 6;
pub const DEFAULT_MIN_CORRECT_ANSWERS: usize = 4;

/// A secret encrypted by answers to security questions
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SecurityQuestionsSealed<
    Secret: IsSecret,
    const QUESTION_COUNT: usize = DEFAULT_QUESTION_COUNT,
    const MIN_CORRECT_ANSWERS: usize = DEFAULT_MIN_CORRECT_ANSWERS,
> {
    /// Holds the type of the secret, used for serialization
    #[serde(skip)]
    phantom: std::marker::PhantomData<Secret>,

    /// The security questions used to derive the keys
    /// used to encrypt the secret.
    pub security_questions: SecurityQuestions,

    /// A versioned Key Derivation Function (KDF) algorithm used to produce a
    /// set of Encryption keys from a set of security questions and answers
    pub kdf_scheme: SecurityQuestionsKdfScheme,

    /// The scheme used to encrypt the Security Questions factor source
    /// secret using one combination of answers to questions, one of many.
    pub encryption_scheme: EncryptionScheme,

    /// The N many encryptions of the secret, where N corresponds to the number
    /// of derived keys from the `keyDerivationScheme`
    pub encryptions: IndexSet<HexBytes>,
}

impl<
    Secret: IsSecret,
    const QUESTION_COUNT: usize,
    const MIN_CORRECT_ANSWERS: usize,
> SecurityQuestionsSealed<Secret, QUESTION_COUNT, MIN_CORRECT_ANSWERS>
{
    /// Creates a new sealed secret by encrypting the provided secret with the
    /// provided security questions, answers and salts, using the provided KDF
    /// scheme and encryption scheme.
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

    /// Creates a new sealed secret by encrypting the provided secret with the
    /// provided security questions, answers and salts, using the provided KDF
    /// scheme and encryption scheme.
    pub fn with_schemes(
        secret: Secret,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
        kdf_scheme: SecurityQuestionsKdfScheme,
        encryption_scheme: EncryptionScheme,
    ) -> Result<Self> {
        let questions_answers_and_salts = with;

        // Validate that we have the correct number of questions and answers
        if questions_answers_and_salts.len() != QUESTION_COUNT {
            return Err(Error::InvalidQuestionsAndAnswersCount {
                expected: QUESTION_COUNT,
                found: questions_answers_and_salts.len(),
            });
        }

        // Clone the security questions from the answers and salts, we need to
        // store them in the sealed secret
        let security_questions = questions_answers_and_salts
            .iter()
            .map(|qa| qa.question.clone())
            .collect::<SecurityQuestions>();

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
            security_questions,
            encryptions,
            kdf_scheme,
            encryption_scheme,
        };

        Ok(sealed)
    }

    fn are_all_answers_relevant(
        &self,
        answers_to_question: &SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<()> {
        let irrelevant_question = answers_to_question
            .iter()
            .find(|qa| !self.security_questions.contains(&qa.question));

        if let Some(qa) = irrelevant_question {
            return Err(Error::UnrelatedQuestionProvided {
                question: qa.question.to_string(),
            });
        }

        Ok(())
    }

    pub fn decrypt(
        &self,
        with: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Secret> {
        let answers_to_question = with;

        self.are_all_answers_relevant(&answers_to_question)?;

        let decryption_keys = self
            .kdf_scheme
            .derive_encryption_keys_from_questions_answers_and_salts::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>(answers_to_question)?;

        for decryption_key in decryption_keys.into_iter() {
            for encrypted in self.encryptions.iter() {
                if let Ok(decrypted_bytes) = self
                    .encryption_scheme
                    .decrypt(encrypted.as_ref(), decryption_key.clone())
                {
                    if let Ok(secret) = Secret::from_bytes(decrypted_bytes) {
                        return Ok(secret);
                    }
                }
                // Else continue to the next encrypted/decryption_key
                // combination
            }
        }

        // Failure
        Err(Error::FailedToDecryptSealedSecret)
    }
}

impl HasSampleValues for SecurityQuestionsSealed<String, 6, 3> {
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
            .decrypt(SecurityQuestionsAnswersAndSalts::sample())
            .unwrap();
        assert_eq!(
            decrypted,
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong"
        );
    }
}

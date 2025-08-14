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

    /// The security questions used to derive the keys used to encrypt the
    /// secret.
    pub security_questions_and_salts: SecurityQuestionsAndSalts<QUESTION_COUNT>,

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

    pub fn decrypt(
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
}

impl HasSampleValues for SecurityQuestionsSealed<String, 6, 4> {
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
        let result = sealed.decrypt(answers);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::FailedToDecryptSealedSecret);
    }

    #[test]
    fn unrelated_question_provided() {
        let sealed = Sut::sample();
        let answers = SecurityQuestionsAnswersAndSalts::sample_other();
        let result = sealed.decrypt(answers);
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
        let decrypted = sealed.decrypt(questions_answers_and_salts).unwrap();
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
        let result = sealed.decrypt(questions_answers_and_salts);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::FailedToConvertBytesToSecret {
                underlying: "meant to fail for test".to_owned()
            }
        );
    }
}

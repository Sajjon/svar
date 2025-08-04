use crate::prelude::*;

/// A secret encrypted by answers to security questions
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct SecurityQuestionsSealed {
    pub security_questions: SecurityQuestions,

    /// A versioned Key Derivation Function (KDF) algorithm used to produce a set
    /// of Encryption keys from a set of security questions and answers
    pub kdf_scheme: SecurityQuestionsKDFScheme,

    /// The scheme used to encrypt the Security Questions factor source
    /// secret using one combination of answers to questions, one of many.
    pub encryption_scheme: EncryptionScheme,

    /// The N many encryptions of the secret, where N corresponds to the number of derived keys
    /// from the `keyDerivationScheme`
    pub encryptions: Vec<Exactly60Bytes>, // FIXME: Set?
}

impl SecurityQuestionsSealed {
    pub const QUESTION_COUNT: usize = 6;

    pub fn new_by_encrypting<Secret: AsRef<[u8]>>(
        secret: Secret,
        with: SecurityQuestionsAnswersAndSalts,
        kdf_scheme: SecurityQuestionsKDFScheme,
        encryption_scheme: EncryptionScheme,
    ) -> Result<Self> {
        let questions_answers_and_salts = with;
        if questions_answers_and_salts.len() != Self::QUESTION_COUNT {
            return Err(Error::InvalidQuestionsAndAnswersCount {
                expected: Self::QUESTION_COUNT,
                found: questions_answers_and_salts.len(),
            });
        }
        let security_questions = questions_answers_and_salts
            .iter()
            .map(|qa| qa.question.clone())
            .collect::<SecurityQuestions>();

        let secret_binary = secret.as_ref();

        let encryption_keys = kdf_scheme
            .derive_encryption_keys_from_questions_answers_and_salts(questions_answers_and_salts)
            .expect("TODO validate that answer is non-empty BEFORE passing it here.");

        let encryptions = encryption_keys
            .into_iter()
            .map(|k| encryption_scheme.encrypt(secret_binary, &mut k.clone()))
            .map(|vec| Exactly60Bytes::try_from(vec).expect("Should have been 60 bytes"))
            .collect_vec();

        Ok(Self {
            security_questions,
            encryptions,
            kdf_scheme,
            encryption_scheme,
        })
    }

    pub fn decrypt<Secret: TryFrom<Vec<u8>>>(
        &self,
        with: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Secret> {
        let answers_to_question = with;

        let decryption_keys = self
            .kdf_scheme
            .derive_encryption_keys_from_questions_answers_and_salts(answers_to_question)?;

        for decryption_key in decryption_keys {
            for encrypted in self.encryptions.iter() {
                if let Ok(decrypted_bytes) = self
                    .encryption_scheme
                    .decrypt(encrypted.bytes(), &mut decryption_key.clone())
                {
                    if let Ok(secret) = Secret::try_from(decrypted_bytes) {
                        return Ok(secret);
                    }
                }
                // Else continue to the next encrypted/decryption_key combination
            }
        }

        // Failure
        Err(Error::FailedToDecryptSealedSecret)
    }
}

impl HasSampleValues for SecurityQuestionsSealed {
    fn sample() -> Self {
        let mnemonic = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

        let questions_answers_and_salts = SecurityQuestionsAnswersAndSalts::sample();
        let kdf_scheme = SecurityQuestionsKDFScheme::default();
        let encryption_scheme = EncryptionScheme::default();
        Self::new_by_encrypting(
            mnemonic,
            questions_answers_and_salts,
            kdf_scheme,
            encryption_scheme,
        )
        .expect("Should have been able to create a sample")
    }

    fn sample_other() -> Self {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let questions_answers_and_salts = SecurityQuestionsAnswersAndSalts::sample_other();
        let kdf_scheme = SecurityQuestionsKDFScheme::default();
        let encryption_scheme = EncryptionScheme::default();
        Self::new_by_encrypting(
            mnemonic,
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

    #[allow(clippy::upper_case_acronyms)]
    type SUT = SecurityQuestionsSealed;

    #[test]
    fn throws_if_incorrect_count() {
        let too_few =
            SecurityQuestionsAnswersAndSalts::from_iter([SecurityQuestionAnswerAndSalt::sample()]);
        let res = SUT::new_by_encrypting(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            too_few,
            SecurityQuestionsKDFScheme::default(),
            EncryptionScheme::default(),
        );
        assert_eq!(
            res,
            Err(Error::InvalidQuestionsAndAnswersCount {
                expected: 6,
                found: 1
            })
        );
    }
}

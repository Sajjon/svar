use crate::prelude::*;

/// The KDF algorithm used to derive the decryption key from a combination of answers to security questions.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SecurityQuestionsKdfScheme {
    /// First iteration of KDF for SecurityQuestions
    Version1(SecurityQuestionsKDFSchemeVersion1),
}

impl Default for SecurityQuestionsKdfScheme {
    fn default() -> Self {
        Self::Version1(SecurityQuestionsKDFSchemeVersion1::default())
    }
}

impl IsSecurityQuestionsKdfScheme for SecurityQuestionsKdfScheme {
    fn derive_encryption_keys_from_questions_answers_and_salts(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Vec<EncryptionKey>> {
        match self {
            Self::Version1(kdf) => kdf.derive_encryption_keys_from_questions_answers_and_salts(
                questions_answers_and_salts,
            ),
        }
    }
}

/// Version1 of SecurityQuestions KDF, derives encryption keys from security
/// questions and answers, using two "sub-KDFs".
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionsKDFSchemeVersion1 {
    pub entropies_from_questions_answer_and_salt:
        SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8,
    pub kdf_encryption_keys_from_key_exchange_keys: SecurityQuestionsEncryptionKeysByXorEntropies,
}

impl Default for SecurityQuestionsKDFSchemeVersion1 {
    fn default() -> Self {
        Self {
            entropies_from_questions_answer_and_salt:
                SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8,
            kdf_encryption_keys_from_key_exchange_keys:
                SecurityQuestionsEncryptionKeysByXorEntropies,
        }
    }
}

impl IsSecurityQuestionsKdfScheme for SecurityQuestionsKDFSchemeVersion1 {
    fn derive_encryption_keys_from_questions_answers_and_salts(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Vec<EncryptionKey>> {
        let enropies_from_qas = &self.entropies_from_questions_answer_and_salt;
        let encryption_keys_kdf = &self.kdf_encryption_keys_from_key_exchange_keys;

        let entropies = questions_answers_and_salts
            .iter()
            .map(|qas| enropies_from_qas.derive_entropies_from_question_answer_and_salt(qas))
            .collect::<Result<_>>()?;

        Ok(encryption_keys_kdf.derive_encryption_keys_from(entropies))
    }
}

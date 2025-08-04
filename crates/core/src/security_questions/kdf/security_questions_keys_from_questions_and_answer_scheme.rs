use crate::prelude::*;

/// The KDF algorithm used to derive the decryption key from a combination of answers to security questions.
///
/// N.B. Not to be confused with the much simpler password based Key Derivation used
/// to encrypt Profile part of manual file export.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub enum SecurityQuestionsKDFScheme {
    /// First iteration of KDF for SecurityQuestions
    Version1(SecurityQuestionsKDFSchemeVersion1),
}

impl Default for SecurityQuestionsKDFScheme {
    fn default() -> Self {
        Self::Version1(SecurityQuestionsKDFSchemeVersion1::default())
    }
}

impl IsSecurityQuestionsKDFScheme for SecurityQuestionsKDFScheme {
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

impl HasSampleValues for SecurityQuestionsKDFSchemeVersion1 {
    fn sample() -> Self {
        Self {
            entropies_from_questions_answer_and_salt:
                SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8::sample(),
            kdf_encryption_keys_from_key_exchange_keys:
                SecurityQuestionsEncryptionKeysByXorEntropies::sample(),
        }
    }

    fn sample_other() -> Self {
        Self {
            entropies_from_questions_answer_and_salt:
                SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8::sample_other(),
            kdf_encryption_keys_from_key_exchange_keys:
                SecurityQuestionsEncryptionKeysByXorEntropies::sample_other(),
        }
    }
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

impl IsSecurityQuestionsKDFScheme for SecurityQuestionsKDFSchemeVersion1 {
    fn derive_encryption_keys_from_questions_answers_and_salts(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Vec<EncryptionKey>> {
        let ent_from_qas = &self.entropies_from_questions_answer_and_salt;
        let kdf_enc = &self.kdf_encryption_keys_from_key_exchange_keys;

        let kek = questions_answers_and_salts
            .iter()
            .map(|qas| ent_from_qas.derive_entropies_from_question_answer_and_salt(&qas))
            .collect::<Result<_>>()?;

        Ok(kdf_enc.derive_encryption_keys_from(kek))
    }
}

impl HasSampleValues for SecurityQuestionsKDFScheme {
    fn sample() -> Self {
        Self::Version1(SecurityQuestionsKDFSchemeVersion1::sample())
    }

    fn sample_other() -> Self {
        Self::Version1(SecurityQuestionsKDFSchemeVersion1::sample_other())
    }
}

use crate::prelude::*;

pub trait IsSecurityQuestionsKDFScheme {
    fn derive_encryption_keys_from_questions_answers_and_salts(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Vec<EncryptionKey>>;
}

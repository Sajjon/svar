use crate::prelude::*;

pub trait IsSecurityQuestionsKdfScheme {
    fn derive_encryption_keys_from_questions_answers_and_salts(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts,
    ) -> Result<Vec<EncryptionKey>>;
}

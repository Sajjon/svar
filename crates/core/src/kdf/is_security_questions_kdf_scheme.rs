use crate::prelude::*;

pub trait IsSecurityQuestionsKdfScheme {
    fn derive_encryption_keys_from_questions_answers_and_salts<const QUESTION_COUNT: usize, const MIN_CORRECT_ANSWERS: usize>(
        &self,
        questions_answers_and_salts: SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>,
    ) -> Result<Vec<EncryptionKey>>;
}

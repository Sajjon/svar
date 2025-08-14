use crate::prelude::*;

/// A pair of security question and salt
#[derive(
    Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug,
)]
#[display("SecurityQuestionAndSalt(question: {question})")]
pub struct SecurityQuestionAndSalt {
    pub question: SecurityQuestion,
    pub salt: Exactly32Bytes,
}

impl SecurityQuestionAndSalt {
    pub fn generate_salt(question: SecurityQuestion) -> Self {
        Self {
            question,
            salt: Exactly32Bytes::generate(),
        }
    }
}

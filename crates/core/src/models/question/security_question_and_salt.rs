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

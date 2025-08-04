use crate::prelude::*;

/// A pair of security question and answer
#[derive(Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[display("SecurityQuestionAnswerAndSalt(question: {question}, answer: {answer})")]
pub struct SecurityQuestionAnswerAndSalt {
    pub question: SecurityQuestion,
    pub answer: String,
    pub salt: Exactly32Bytes,
}

impl HasSampleValues for SecurityQuestionAnswerAndSalt {
    fn sample() -> Self {
        Self {
            question: SecurityQuestion::first_concert(),
            answer: "Jean-Michel Jarre, Paris La Défense, 1990".to_owned(),
            salt: Exactly32Bytes::sample_aced(),
        }
    }

    fn sample_other() -> Self {
        Self {
            question: SecurityQuestion::stuffed_animal(),
            answer: "Oinky piggy pig".to_owned(),
            salt: Exactly32Bytes::sample_babe(),
        }
    }
}

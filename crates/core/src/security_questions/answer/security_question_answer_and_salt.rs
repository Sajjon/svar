use crate::prelude::*;

/// A pair of security question and answer
#[derive(Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug, Builder, Getters)]
#[display("SecurityQuestionAnswerAndSalt(question: {question}, answer: {answer})")]
pub struct SecurityQuestionAnswerAndSalt {
    #[getset(get = "pub")]
    question: SecurityQuestion,
    #[getset(get = "pub")]
    answer: String,
    #[getset(get = "pub")]
    salt: Exactly32Bytes,
}

impl HasSampleValues for SecurityQuestionAnswerAndSalt {
    fn sample() -> Self {
        Self::builder()
            .question(SecurityQuestion::first_concert())
            .answer("Jean-Michel Jarre, Paris La Défense, 1990".to_owned())
            .salt(Exactly32Bytes::sample_aced())
            .build()
    }

    fn sample_other() -> Self {
        Self::builder()
            .question(SecurityQuestion::stuffed_animal())
            .answer("Oinky piggy pig".to_owned())
            .salt(Exactly32Bytes::sample_babe())
            .build()
    }
}

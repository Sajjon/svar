use crate::prelude::*;

/// A pair of security question and answer
#[derive(Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
#[display("SecurityQuestionAndAnswer(question: {question}, answer: {answer})")]
pub struct SecurityQuestionAndAnswer {
    pub question: SecurityQuestion,
    pub answer: String,
}

impl SecurityQuestionAndAnswer {
    pub fn new(question: SecurityQuestion, answer: impl AsRef<str>) -> Self {
        Self {
            question,
            answer: answer.as_ref().to_owned(),
        }
    }
}

impl HasSampleValues for SecurityQuestionAndAnswer {
    fn sample() -> Self {
        Self::new(
            SecurityQuestion::first_concert(),
            "Jean-Michel Jarre, Paris La Défense, 1990",
        )
    }

    fn sample_other() -> Self {
        Self::new(SecurityQuestion::stuffed_animal(), "Oinky piggy pig")
    }
}

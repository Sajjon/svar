use crate::prelude::*;

/// A pair of security question and answer
#[derive(
    Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug,
)]
#[display(
    "SecurityQuestionAnswerAndSalt(question: {question}, answer: {answer})"
)]
pub struct SecurityQuestionAnswerAndSalt {
    pub question: SecurityQuestion,
    pub answer: String,
    pub salt: Exactly32Bytes,
}

impl SecurityQuestionAnswerAndSalt {
    /// Creates a new `SecurityQuestionAnswerAndSalt` by answering a freeform question.
    ///
    /// A salt is generated from a cryptographically secure random number generator.
    ///
    /// # Errors
    /// Returns an error if the question is not of kind `Freeform`.
    pub fn by_answering_freeform(
        question: SecurityQuestion,
        provide_answer: impl FnOnce(
            String,
            SecurityQuestionExpectedAnswerFormat,
        ) -> String,
    ) -> Result<Self> {
        if question.kind != SecurityQuestionKind::Freeform {
            return Err(Error::InvalidSecurityQuestionKind {
                expected: SecurityQuestionKind::Freeform,
                found: question.kind,
            });
        }
        let answer = provide_answer(
            question.question.clone(),
            question.expected_answer_format.clone(),
        );
        Ok(Self {
            question,
            answer,
            salt: Exactly32Bytes::generate(),
        })
    }
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

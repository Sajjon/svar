use crate::prelude::*;

/// A pair of security question and answer
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionAndAnswerAsBytes {
    pub question: SecurityQuestion,
    pub answer: SecurityQuestionAnswerAsBytes,
}

impl SecurityQuestionAndAnswerAsBytes {
    pub fn answer_to_question(
        freeform: impl AsRef<str>,
        question: SecurityQuestion,
    ) -> Result<Self> {
        let answer =
            SecurityQuestionAnswerAsBytes::validate_conversion_to_bytes_of(freeform.as_ref())?;
        Ok(Self { question, answer })
    }
}

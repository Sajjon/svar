use crate::prelude::*;

/// An answer **as bytes** to some security question, being the output of some
/// set of functions mapping answer -> bytes.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionAnswerAsBytes {
    pub bytes: BagOfBytes,
}

impl SecurityQuestionAnswerAsBytes {
    fn bytes_from_trimmed_answer(freeform_answer: TrimmedAnswer) -> BagOfBytes {
        BagOfBytes::from(freeform_answer.trimmed_answer.into_bytes())
    }

    pub fn validate_conversion_to_bytes_of(answer: impl AsRef<str>) -> Result<Self> {
        let answer = answer.as_ref().to_owned();
        if answer.is_empty() {
            return Err(Error::AnswersToSecurityQuestionsCannotBeEmpty);
        }
        let trimmed = TrimmedAnswer::new(answer)?;
        let bytes = Self::bytes_from_trimmed_answer(trimmed);
        Ok(Self { bytes })
    }
}

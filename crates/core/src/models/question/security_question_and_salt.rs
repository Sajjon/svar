use crate::prelude::*;

/// A pair of security question and salt
#[derive(
    Serialize,
    Display,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Debug,
    getset::Getters,
)]
#[display("SecurityQuestionAndSalt(question: {question})")]
pub struct SecurityQuestionAndSalt {
    #[getset(get = "pub")]
    question: SecurityQuestion,
    #[getset(get = "pub")]
    salt: Exactly32Bytes,
}

#[bon::bon]
impl SecurityQuestionAndSalt {
    #[builder]
    pub fn new(question: SecurityQuestion, salt: Exactly32Bytes) -> Self {
        Self { question, salt }
    }

    pub fn generate_salt(question: SecurityQuestion) -> Self {
        Self::builder()
            .question(question)
            .salt(Exactly32Bytes::generate())
            .build()
    }

    pub fn into_parts(self) -> (SecurityQuestion, Exactly32Bytes) {
        (self.question, self.salt)
    }
}

impl HasSampleValues for SecurityQuestionAndSalt {
    fn sample() -> Self {
        Self::builder()
            .question(SecurityQuestion::sample())
            .salt(Exactly32Bytes::sample_aced())
            .build()
    }

    fn sample_other() -> Self {
        Self::builder()
            .question(SecurityQuestion::sample_other())
            .salt(Exactly32Bytes::sample_babe())
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    type Sut = SecurityQuestionAndSalt;

    #[test]
    fn equality() {
        assert_eq!(Sut::sample(), Sut::sample());
        assert_eq!(Sut::sample_other(), Sut::sample_other());
    }

    #[test]
    fn inequality() {
        assert_ne!(Sut::sample(), Sut::sample_other());
    }

    #[test]
    fn generate_salt() {
        let question = SecurityQuestion::first_concert();
        let gen0 = SecurityQuestionAndSalt::generate_salt(question.clone());
        let gen1 = SecurityQuestionAndSalt::generate_salt(question.clone());
        assert_ne!(gen0, gen1);
        assert_ne!(gen0.salt(), gen1.salt());
        assert_eq!(gen0.question(), gen1.question());
    }

    #[test]
    fn into_parts_preserves_question_and_salt() {
        let question_and_salt = Sut::sample();
        let expected_question = question_and_salt.question().clone();
        let expected_salt = *question_and_salt.salt();

        let (question, salt) = question_and_salt.into_parts();

        assert_eq!(question, expected_question);
        assert_eq!(salt, expected_salt);
    }
}

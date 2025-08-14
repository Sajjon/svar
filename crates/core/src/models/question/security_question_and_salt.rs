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

impl HasSampleValues for SecurityQuestionAndSalt {
    fn sample() -> Self {
        Self {
            question: SecurityQuestion::sample(),
            salt: Exactly32Bytes::sample_aced(),
        }
    }

    fn sample_other() -> Self {
        Self {
            question: SecurityQuestion::sample_other(),
            salt: Exactly32Bytes::sample_babe(),
        }
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
        assert_ne!(gen0.salt, gen1.salt);
        assert_eq!(gen0.question, gen1.question);
    }
}

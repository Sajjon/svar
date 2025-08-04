use crate::prelude::*;

#[derive(
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    derive_more::Debug,
    derive_more::Display,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::From,
)]
#[display("SecurityQuestionsAnswersAndSalts({})", self.0.len())]
#[serde(transparent)]
pub struct SecurityQuestionsAnswersAndSalts(IndexSet<SecurityQuestionAnswerAndSalt>);

impl FromIterator<SecurityQuestionAnswerAndSalt> for SecurityQuestionsAnswersAndSalts {
    fn from_iter<T: IntoIterator<Item = SecurityQuestionAnswerAndSalt>>(iter: T) -> Self {
        Self(IndexSet::from_iter(iter))
    }
}

impl HasSampleValues for SecurityQuestionsAnswersAndSalts {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAnswerAndSalt;
        Self::from_iter([
            QA {
                question: Q::failed_exam(),
                answer: "MIT, year 4, Python".to_owned(),
                salt: Exactly32Bytes::sample_aced(),
            },
            QA {
                question: Q::parents_met(),
                answer: "London, 1973".to_owned(),
                salt: Exactly32Bytes::sample_babe(),
            },
            QA {
                question: Q::first_concert(),
                answer: "Jean-Michel Jarre, Paris La Défense, 1990".to_owned(),
                salt: Exactly32Bytes::sample_cafe(),
            },
            QA {
                question: Q::first_kiss_whom(),
                answer: "John Doe".to_owned(),
                salt: Exactly32Bytes::sample_dead(),
            },
            QA {
                question: Q::first_kiss_location(),
                answer: "Behind the shed in the oak tree forrest.".to_owned(),
                salt: Exactly32Bytes::sample_ecad(),
            },
            QA {
                question: Q::spouse_met(),
                answer: "Tokyo, 1989".to_owned(),
                salt: Exactly32Bytes::sample_fade(),
            },
        ])
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAnswerAndSalt;
        Self::from_iter([
            QA {
                question: Q::child_middle_name(),
                answer: "Joe".to_owned(),
                salt: Exactly32Bytes::sample_aced(),
            },
            QA {
                question: Q::stuffed_animal(),
                answer: "Bobby".to_owned(),
                salt: Exactly32Bytes::sample_babe(),
            },
            QA {
                question: Q::oldest_cousin(),
                answer: "Roxanne".to_owned(),
                salt: Exactly32Bytes::sample_cafe(),
            },
            QA {
                question: Q::teacher_grade3(),
                answer: "Ali".to_owned(),
                salt: Exactly32Bytes::sample_dead(),
            },
            QA {
                question: Q::applied_uni_no_attend(),
                answer: "Oxford".to_owned(),
                salt: Exactly32Bytes::sample_ecad(),
            },
            QA {
                question: Q::first_school(),
                answer: "Hogwartz".to_owned(),
                salt: Exactly32Bytes::sample_fade(),
            },
        ])
    }
}

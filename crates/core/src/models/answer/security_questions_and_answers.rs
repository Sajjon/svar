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
#[display("SecurityQuestionsAndAnswers({})", self.0.len())]
#[serde(transparent)]
pub struct SecurityQuestionsAndAnswers(IndexSet<SecurityQuestionAndAnswer>);

impl FromIterator<SecurityQuestionAndAnswer> for SecurityQuestionsAndAnswers {
    fn from_iter<T: IntoIterator<Item = SecurityQuestionAndAnswer>>(iter: T) -> Self {
        Self(IndexSet::from_iter(iter))
    }
}

impl HasSampleValues for SecurityQuestionsAndAnswers {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAndAnswer;
        Self::from_iter([
            QA::new(Q::failed_exam(), "MIT, year 4, Python"),
            QA::new(Q::parents_met(), "London, 1973"),
            QA::new(
                Q::first_concert(),
                "Jean-Michel Jarre, Paris La Défense, 1990",
            ),
            QA::new(Q::first_kiss_whom(), "John Doe"),
            QA::new(
                Q::first_kiss_location(),
                "Behind the shed in the oak tree forrest.",
            ),
            QA::new(Q::spouse_met(), "Tokyo, 1989"),
        ])
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAndAnswer;
        Self::from_iter([
            QA::new(Q::child_middle_name(), "Joe"),
            QA::new(Q::stuffed_animal(), "Bobby"),
            QA::new(Q::oldest_cousin(), "Roxanne"),
            QA::new(Q::teacher_grade3(), "Ali"),
            QA::new(Q::applied_uni_no_attend(), "Oxford"),
            QA::new(Q::first_school(), "Hogwartz"),
        ])
    }
}

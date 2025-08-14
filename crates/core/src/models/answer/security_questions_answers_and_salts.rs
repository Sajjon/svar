use crate::prelude::*;

#[derive(
    Clone,
    PartialEq,
    Eq,
    derive_more::Debug,
    derive_more::Display,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::From,
)]
#[display("SecurityQuestionsAnswersAndSalts({})", self.0.len())]
pub struct SecurityQuestionsAnswersAndSalts<const QUESTION_COUNT: usize>(
    [SecurityQuestionAnswerAndSalt; QUESTION_COUNT],
);

impl<const QUESTION_COUNT: usize>
    SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>
{
    pub fn try_from_iter(
        qas: impl IntoIterator<Item = SecurityQuestionAnswerAndSalt>,
    ) -> Result<Self> {
        let qas = qas.into_iter().collect::<IndexSet<_>>();
        let len = qas.len();
        let arr: [SecurityQuestionAnswerAndSalt; QUESTION_COUNT] = qas
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::InvalidQuestionsAndAnswersCount {
                expected: QUESTION_COUNT,
                found: len,
            })?;

        Ok(Self(arr))
    }
}

#[cfg(test)]
impl SecurityQuestionsAnswersAndSalts<6> {
    pub(crate) fn sample_wrong_answers() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAnswerAndSalt;
        Self::try_from_iter([
            QA {
                question: Q::failed_exam(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_aced(),
            },
            QA {
                question: Q::parents_met(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_babe(),
            },
            QA {
                question: Q::first_concert(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_cafe(),
            },
            QA {
                question: Q::first_kiss_whom(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_dead(),
            },
            QA {
                question: Q::first_kiss_location(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_ecad(),
            },
            QA {
                question: Q::spouse_met(),
                answer: "Wrong answer".to_owned(),
                salt: Exactly32Bytes::sample_fade(),
            },
        ])
        .expect("Should have been 6 questions and answers")
    }
}

impl HasSampleValues for SecurityQuestionsAnswersAndSalts<6> {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAnswerAndSalt;
        Self::try_from_iter([
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
        .expect("Should have been 6 questions and answers")
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        type QA = SecurityQuestionAnswerAndSalt;
        Self::try_from_iter([
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
        .expect("Should have been 6 questions and answers")
    }
}

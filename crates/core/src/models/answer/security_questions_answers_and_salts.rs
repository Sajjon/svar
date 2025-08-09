use crate::prelude::*;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
};
use std::fmt;

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

impl<const QUESTION_COUNT: usize> SecurityQuestionsAnswersAndSalts<QUESTION_COUNT> {
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

impl<const QUESTION_COUNT: usize> Serialize for SecurityQuestionsAnswersAndSalts<QUESTION_COUNT> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(QUESTION_COUNT))?;
        for item in &self.0 {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de, const QUESTION_COUNT: usize> Deserialize<'de>
    for SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
            type Value = [SecurityQuestionAnswerAndSalt; N];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length {}", N)
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> Result<[SecurityQuestionAnswerAndSalt; N], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(N);

                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }

                SecurityQuestionsAnswersAndSalts::try_from_iter(items)
                    .map(|s| s.0)
                    .map_err(serde::de::Error::custom)
            }
        }

        let arr = deserializer.deserialize_tuple(QUESTION_COUNT, ArrayVisitor::<QUESTION_COUNT>)?;
        Ok(SecurityQuestionsAnswersAndSalts(arr))
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

#[cfg(test)]
mod tests {
    use insta::assert_json_snapshot;

    use super::*;

    type Sut = SecurityQuestionsAnswersAndSalts<6>;

    #[test]
    fn serialize() {
        assert_json_snapshot!(Sut::sample());
    }
}

use crate::prelude::*;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
};
use std::fmt;

/// A collection of security questions and their salts, the salts are needed to
/// derive the encryption keys used to encrypt the secret.
///
/// The questions are in case of user forgets the questions.
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
#[display("SecurityQuestionsAndSalts({})", self.0.len())]
pub struct SecurityQuestionsAndSalts<const QUESTION_COUNT: usize>(
    [SecurityQuestionAndSalt; QUESTION_COUNT],
);

impl<const QUESTION_COUNT: usize> SecurityQuestionsAndSalts<QUESTION_COUNT> {
    pub fn try_from_iter(
        qas: impl IntoIterator<Item = SecurityQuestionAndSalt>,
    ) -> Result<Self> {
        let qas = qas.into_iter().collect::<IndexSet<_>>();
        let len = qas.len();
        let arr: [SecurityQuestionAndSalt; QUESTION_COUNT] = qas
            .into_iter()
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::InvalidQuestionsAndSaltCount {
                expected: QUESTION_COUNT,
                found: len,
            })?;

        Ok(Self(arr))
    }
}

impl<const QUESTION_COUNT: usize> Serialize
    for SecurityQuestionsAndSalts<QUESTION_COUNT>
{
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
    for SecurityQuestionsAndSalts<QUESTION_COUNT>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for ArrayVisitor<N> {
            type Value = [SecurityQuestionAndSalt; N];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "an array of length {}", N)
            }

            fn visit_seq<A>(
                self,
                mut seq: A,
            ) -> Result<[SecurityQuestionAndSalt; N], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut items = Vec::with_capacity(N);

                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }

                SecurityQuestionsAndSalts::try_from_iter(items)
                    .map(|s| s.0)
                    .map_err(serde::de::Error::custom)
            }
        }

        let arr = deserializer.deserialize_tuple(
            QUESTION_COUNT,
            ArrayVisitor::<QUESTION_COUNT>,
        )?;
        Ok(SecurityQuestionsAndSalts(arr))
    }
}

impl HasSampleValues for SecurityQuestionsAndSalts<6> {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        type QS = SecurityQuestionAndSalt;
        Self::try_from_iter([
            QS {
                question: Q::failed_exam(),
                salt: Exactly32Bytes::sample_aced(),
            },
            QS {
                question: Q::parents_met(),
                salt: Exactly32Bytes::sample_babe(),
            },
            QS {
                question: Q::first_concert(),
                salt: Exactly32Bytes::sample_cafe(),
            },
            QS {
                question: Q::first_kiss_whom(),
                salt: Exactly32Bytes::sample_dead(),
            },
            QS {
                question: Q::first_kiss_location(),
                salt: Exactly32Bytes::sample_ecad(),
            },
            QS {
                question: Q::spouse_met(),
                salt: Exactly32Bytes::sample_fade(),
            },
        ])
        .expect("Should have been 6 questions and salts")
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        type QS = SecurityQuestionAndSalt;
        Self::try_from_iter([
            QS {
                question: Q::child_middle_name(),
                salt: Exactly32Bytes::sample_aced(),
            },
            QS {
                question: Q::stuffed_animal(),
                salt: Exactly32Bytes::sample_babe(),
            },
            QS {
                question: Q::oldest_cousin(),
                salt: Exactly32Bytes::sample_cafe(),
            },
            QS {
                question: Q::teacher_grade3(),
                salt: Exactly32Bytes::sample_dead(),
            },
            QS {
                question: Q::applied_uni_no_attend(),
                salt: Exactly32Bytes::sample_ecad(),
            },
            QS {
                question: Q::first_school(),
                salt: Exactly32Bytes::sample_fade(),
            },
        ])
        .expect("Should have been 6 questions and salts")
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_json_snapshot;

    use super::*;

    type Sut = SecurityQuestionsAndSalts<6>;

    #[test]
    fn serialize() {
        assert_json_snapshot!(Sut::sample());
    }
}

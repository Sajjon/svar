use crate::prelude::*;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer, ser::SerializeSeq,
};

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
        let items: Vec<SecurityQuestionAndSalt> =
            Vec::deserialize(deserializer)?;
        Self::try_from_iter(items).map_err(serde::de::Error::custom)
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

    #[test]
    fn json_roundtrip() {
        let original = Sut::sample();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Sut = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn deserialize_fails_when_wrong_count() {
        let json = r#"[
            {
              "question": {
                "id": 0,
                "version": 1,
                "kind": "Freeform",
                "question": "What was the first exam you failed",
                "expected_answer_format": {
                  "answer_structure": "<SCHOOL>, <SCHOOL_GRADE>, <SUBJECT>",
                  "example_answer": "MIT, year 4, Python",
                  "unsafe_answers": []
                }
              },
              "salt": "acedacedacedacedacedacedacedacedacedacedacedacedacedacedacedaced"
            },
            {
              "question": {
                "id": 1,
                "version": 1,
                "kind": "Freeform",
                "question": "In which city and which year did your parents meet?",
                "expected_answer_format": {
                  "answer_structure": "<CITY>, <YEAR>",
                  "example_answer": "Berlin, 1976",
                  "unsafe_answers": []
                }
              },
              "salt": "babebabebabebabebabebabebabebabebabebabebabebabebabebabebabebabe"
            }
        ]"#;

        let result: Result<Sut, _> = serde_json::from_str(json);
        assert!(result.is_err());
        let error_message = result.unwrap_err().to_string();
        assert!(
            error_message.contains(
                "Invalid questions and salt count: expected 6, found 2"
            )
        );
    }

    #[test]
    fn deserialize_success() {
        let json = r#"[
            {
              "question": {
                "id": 0,
                "version": 1,
                "kind": "Freeform",
                "question": "What was the first exam you failed",
                "expected_answer_format": {
                  "answer_structure": "<SCHOOL>, <SCHOOL_GRADE>, <SUBJECT>",
                  "example_answer": "MIT, year 4, Python",
                  "unsafe_answers": []
                }
              },
              "salt": "acedacedacedacedacedacedacedacedacedacedacedacedacedacedacedaced"
            }
        ]"#;
        let result: Result<SecurityQuestionsAndSalts<1>, _> =
            serde_json::from_str(json);
        assert!(result.is_ok());
        let security_questions_and_salts = result.unwrap();
        assert_eq!(security_questions_and_salts.0.len(), 1);
    }

    #[test]
    fn try_from_iter_err_wrong_count() {
        let result = Sut::try_from_iter([
            SecurityQuestionAndSalt::sample(),
            SecurityQuestionAndSalt::sample_other(),
        ]);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            Error::InvalidQuestionsAndSaltCount {
                expected: 6,
                found: 2
            }
        );
    }

    #[test]
    fn equality() {
        assert_eq!(Sut::sample(), Sut::sample());
        assert_eq!(Sut::sample_other(), Sut::sample_other());
    }

    #[test]
    fn inequality() {
        assert_ne!(Sut::sample(), Sut::sample_other());
    }
}

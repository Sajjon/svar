use crate::prelude::*;

/// A set of encryption keys of length N choose M, where N is the number of security questions
/// and M is the minimum number of correct answers required to decrypt a secret.
#[derive(Clone, PartialEq, Eq, derive_more::Debug, derive_more::Display)]
#[display("EncryptionKeys({})", self.0.len())]
pub struct EncryptionKeys<const QUESTION_COUNT: usize, const MIN_CORRECT_ANSWERS: usize>(
    IndexSet<EncryptionKey>,
);

/// Performs N choose M calculation to determine the number of encryption keys
/// that can be derived from a set of security questions and answers.
/// This is used to validate the number of keys in `EncryptionKeys`.
///
/// # Error
/// Returns the number of combinations or an error if the inputs are invalid:
/// if `answers` is greater than `questions`.
fn n_choose_m<const N: usize, const M: usize>() -> Result<usize> {
    let questions = N;
    let answers = M;
    if answers > questions {
        return Err(Error::QuestionsMustBeGreaterThanOrEqualAnswers { questions, answers });
    } else {
        Ok((0..M).fold(1, |acc, i| acc * (N - i) / (i + 1)))
    }
}

impl<const QUESTION_COUNT: usize, const MIN_CORRECT_ANSWERS: usize>
    EncryptionKeys<QUESTION_COUNT, MIN_CORRECT_ANSWERS>
{
    pub fn new(keys: impl IntoIterator<Item = EncryptionKey>) -> Result<Self> {
        let keys = keys.into_iter().collect::<IndexSet<_>>();
        let len = keys.len();
        let expected_len = n_choose_m::<QUESTION_COUNT, MIN_CORRECT_ANSWERS>()?;
        if len != expected_len {
            return Err(Error::InvalidQuestionsAndAnswersCount {
                expected: expected_len,
                found: len,
            });
        }
        Ok(Self(keys))
    }

    pub fn into_iter(self) -> impl Iterator<Item = EncryptionKey> {
        self.0.into_iter()
    }
}

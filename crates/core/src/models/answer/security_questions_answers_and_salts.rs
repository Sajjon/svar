use crate::prelude::*;

/// A collection of security questions with their answers and cryptographic
/// salts.
///
/// This type represents a fixed-size array of security question-answer pairs,
/// each with its associated cryptographic salt. It's the primary input for
/// encrypting secrets and is used during decryption to derive the necessary
/// encryption keys.
///
/// # Type Parameters
///
/// - `QUESTION_COUNT`: The number of security questions (compile-time constant)
///
/// # Structure
///
/// Each element contains:
/// - A security question
/// - The user's answer to that question
/// - A cryptographic salt for key derivation
///
/// # Examples
///
/// ## Creating from Iterator
///
/// ```
/// use svar_core::*;
///
/// let questions_and_answers =
///     SecurityQuestionsAnswersAndSalts::<3>::try_from_iter([
///         SecurityQuestionAnswerAndSalt::sample(),
///         SecurityQuestionAnswerAndSalt::sample_other(),
///         SecurityQuestionAnswerAndSalt::builder()
///             .question(SecurityQuestion::sample())
///             .answer("My custom answer")
///             .salt(Exactly32Bytes::sample())
///             .build(),
///     ])?;
///
/// assert_eq!(questions_and_answers.len(), 3);
/// # Ok::<(), svar_core::Error>(())
/// ```
///
/// ## Using Sample Data
///
/// ```
/// use svar_core::*;
///
/// // Default sample with 6 questions
/// let sample = SecurityQuestionsAnswersAndSalts::sample();
/// assert_eq!(sample.len(), 6);
///
/// // Alternative sample
/// let other_sample = SecurityQuestionsAnswersAndSalts::sample_other();
/// assert_ne!(sample, other_sample);
/// ```
///
/// ## Accessing Individual Elements
///
/// ```
/// use svar_core::*;
///
/// let qa_set = SecurityQuestionsAnswersAndSalts::sample();
///
/// // Access via indexing (implements Deref)
/// let first_qa = &qa_set[0];
/// println!("Question: {}", first_qa.question().question());
/// println!("Answer: {}", first_qa.answer());
///
/// // Iterate over all questions and answers
/// for qa in qa_set.iter() {
///     println!("Q: {} A: {}", qa.question().question(), qa.answer());
/// }
/// ```
///
/// # Error Handling
///
/// Creation fails if the number of provided questions doesn't match
/// `QUESTION_COUNT`:
///
/// ```
/// use svar_core::*;
///
/// // This will fail - trying to create 3 questions but only providing 2
/// let result = SecurityQuestionsAnswersAndSalts::<3>::try_from_iter([
///     SecurityQuestionAnswerAndSalt::sample(),
///     SecurityQuestionAnswerAndSalt::sample_other(),
/// ]);
///
/// match result {
///     Err(Error::InvalidQuestionsAndAnswersCount { expected, found }) => {
///         assert_eq!(expected, 3);
///         assert_eq!(found, 2);
///     }
///     _ => panic!("Expected count mismatch error"),
/// }
/// ```
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

fn answer_and_salt(
    question: SecurityQuestion,
    answer: impl Into<String>,
    salt: Exactly32Bytes,
) -> SecurityQuestionAnswerAndSalt {
    SecurityQuestionAnswerAndSalt::builder()
        .question(question)
        .answer(answer)
        .salt(salt)
        .build()
}

impl<const QUESTION_COUNT: usize>
    SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>
{
    /// Creates a new collection from an iterator of question-answer-salt
    /// triplets.
    ///
    /// This method validates that exactly `QUESTION_COUNT` items are provided
    /// and converts them into a fixed-size array. The questions are
    /// deduplicated using an `IndexSet` to ensure no duplicate questions
    /// are included.
    ///
    /// # Parameters
    ///
    /// - `qas`: An iterator of [`SecurityQuestionAnswerAndSalt`] items
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the collection or an error if the count is
    /// wrong.
    ///
    /// # Examples
    ///
    /// ## Successful Creation
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let qa1 = SecurityQuestionAnswerAndSalt::sample();
    /// let qa2 = SecurityQuestionAnswerAndSalt::sample_other();
    ///
    /// let collection =
    ///     SecurityQuestionsAnswersAndSalts::<2>::try_from_iter([qa1, qa2])?;
    /// assert_eq!(collection.len(), 2);
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Error Cases
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// // Too few items
    /// let result = SecurityQuestionsAnswersAndSalts::<3>::try_from_iter([
    ///     SecurityQuestionAnswerAndSalt::sample(),
    /// ]);
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::InvalidQuestionsAndAnswersCount { .. })
    /// ));
    ///
    /// // Too many items
    /// let result = SecurityQuestionsAnswersAndSalts::<1>::try_from_iter([
    ///     SecurityQuestionAnswerAndSalt::sample(),
    ///     SecurityQuestionAnswerAndSalt::sample_other(),
    /// ]);
    /// assert!(matches!(
    ///     result,
    ///     Err(Error::InvalidQuestionsAndAnswersCount { .. })
    /// ));
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`InvalidQuestionsAndAnswersCount`](Error::InvalidQuestionsAndAnswersCount)
    /// if the number of provided items doesn't exactly match `QUESTION_COUNT`.
    ///
    /// # Deduplication
    ///
    /// Duplicate questions (based on equality) are automatically removed. If
    /// this results in fewer than `QUESTION_COUNT` unique questions, an
    /// error is returned.
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
    /// Creates a sample collection with intentionally wrong answers for
    /// testing.
    ///
    /// This method is used in tests to verify that the system correctly rejects
    /// decryption attempts when too many answers are incorrect. All answers are
    /// set to "Wrong answer" or similar incorrect values.
    ///
    /// # Returns
    ///
    /// A collection of 6 security questions with incorrect answers.
    ///
    /// # Examples
    ///
    /// ```
    /// # #[cfg(test)]
    /// # {
    /// use svar_core::*;
    ///
    /// let wrong_answers =
    ///     SecurityQuestionsAnswersAndSalts::sample_wrong_answers();
    ///
    /// // This should fail when used for decryption
    /// let correct_answers = SecurityQuestionsAnswersAndSalts::sample();
    /// let sealed =
    ///     SecurityQuestionsSealed::seal("secret".to_string(), correct_answers)?;
    ///
    /// assert!(sealed.decrypt(wrong_answers).is_err());
    /// # }
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Note
    ///
    /// This method is only available in test builds (`#[cfg(test)]`) and is
    /// intended for testing the fault tolerance and error handling of the
    /// encryption system.
    pub(crate) fn sample_wrong_answers() -> Self {
        type Q = SecurityQuestion;
        Self::try_from_iter([
            answer_and_salt(
                Q::failed_exam(),
                "Wrong answer",
                Exactly32Bytes::sample_aced(),
            ),
            answer_and_salt(
                Q::parents_met(),
                "Wrong answer",
                Exactly32Bytes::sample_babe(),
            ),
            answer_and_salt(
                Q::first_concert(),
                "Wrong answer",
                Exactly32Bytes::sample_cafe(),
            ),
            answer_and_salt(
                Q::first_kiss_whom(),
                "Wrong answer",
                Exactly32Bytes::sample_dead(),
            ),
            answer_and_salt(
                Q::first_kiss_location(),
                "Wrong answer",
                Exactly32Bytes::sample_ecad(),
            ),
            answer_and_salt(
                Q::spouse_met(),
                "Wrong answer",
                Exactly32Bytes::sample_fade(),
            ),
        ])
        .expect("Should have been 6 questions and answers")
    }
}

impl HasSampleValues for SecurityQuestionsAnswersAndSalts<6> {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        Self::try_from_iter([
            answer_and_salt(
                Q::failed_exam(),
                "MIT, year 4, Python",
                Exactly32Bytes::sample_aced(),
            ),
            answer_and_salt(
                Q::parents_met(),
                "London, 1973",
                Exactly32Bytes::sample_babe(),
            ),
            answer_and_salt(
                Q::first_concert(),
                "Jean-Michel Jarre, Paris La Défense, 1990",
                Exactly32Bytes::sample_cafe(),
            ),
            answer_and_salt(
                Q::first_kiss_whom(),
                "John Doe",
                Exactly32Bytes::sample_dead(),
            ),
            answer_and_salt(
                Q::first_kiss_location(),
                "Behind the shed in the oak tree forrest.",
                Exactly32Bytes::sample_ecad(),
            ),
            answer_and_salt(
                Q::spouse_met(),
                "Tokyo, 1989",
                Exactly32Bytes::sample_fade(),
            ),
        ])
        .expect("Should have been 6 questions and answers")
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        Self::try_from_iter([
            answer_and_salt(
                Q::child_middle_name(),
                "Joe",
                Exactly32Bytes::sample_aced(),
            ),
            answer_and_salt(
                Q::stuffed_animal(),
                "Bobby",
                Exactly32Bytes::sample_babe(),
            ),
            answer_and_salt(
                Q::oldest_cousin(),
                "Roxanne",
                Exactly32Bytes::sample_cafe(),
            ),
            answer_and_salt(
                Q::teacher_grade3(),
                "Ali",
                Exactly32Bytes::sample_dead(),
            ),
            answer_and_salt(
                Q::applied_uni_no_attend(),
                "Oxford",
                Exactly32Bytes::sample_ecad(),
            ),
            answer_and_salt(
                Q::first_school(),
                "Hogwartz",
                Exactly32Bytes::sample_fade(),
            ),
        ])
        .expect("Should have been 6 questions and answers")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    type Sut = SecurityQuestionsAnswersAndSalts<6>;

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
    fn sample_wrong_answers() {
        let wrong = Sut::sample_wrong_answers();
        assert_eq!(wrong.0.len(), 6);
        for qa in &wrong.0 {
            assert_eq!(qa.answer(), "Wrong answer");
        }
    }

    #[test]
    fn try_from_iter_success() {
        let questions_answers =
            SecurityQuestionsAnswersAndSalts::<2>::try_from_iter([
                SecurityQuestionAnswerAndSalt::sample(),
                SecurityQuestionAnswerAndSalt::sample_other(),
            ])
            .expect("Should have been able to create from iterator");
        assert_eq!(questions_answers.0.len(), 2);
    }

    #[test]
    fn try_from_iter_fail_invalid_count() {
        let questions_answers =
            SecurityQuestionsAnswersAndSalts::<3>::try_from_iter([
                SecurityQuestionAnswerAndSalt::sample(),
                SecurityQuestionAnswerAndSalt::sample_other(),
            ]);
        assert!(questions_answers.is_err());
        assert_eq!(
            questions_answers.unwrap_err(),
            Error::InvalidQuestionsAndAnswersCount {
                expected: 3,
                found: 2
            }
        );
    }
}

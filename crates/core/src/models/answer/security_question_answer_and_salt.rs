use crate::prelude::*;

/// A security question paired with its answer and cryptographic salt.
///
/// This type represents a complete triplet needed for cryptographic operations:
/// a security question, the user's answer to that question, and a cryptographic
/// salt for key derivation. It's the fundamental building block for creating
/// security question-based encryption.
///
/// # Structure
///
/// Contains:
/// - **Question**: The security question being answered
/// - **Answer**: The user's response to the question
/// - **Salt**: A cryptographic salt for key derivation uniqueness
///
/// # Examples
///
/// ## Creating with Freeform Question
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::sample();
///
/// let qa_salt = SecurityQuestionAnswerAndSalt::by_answering_freeform(
///     question.clone(),
///     |question_text, _format| {
///         // Simulate user providing an answer
///         format!("Answer to: {}", question_text)
///     },
/// )?;
///
/// assert_eq!(qa_salt.question, question);
/// assert!(qa_salt.answer.starts_with("Answer to:"));
/// assert_eq!(qa_salt.salt.0.len(), 32); // Salt is always 32 bytes
///
/// # Ok::<(), svar_core::Error>(())
/// ```
///
/// ## Manual Construction
///
/// ```
/// use svar_core::*;
///
/// let qa_salt = SecurityQuestionAnswerAndSalt {
///     question: SecurityQuestion::sample(),
///     answer: "My pet's name was Fluffy".to_string(),
///     salt: Exactly32Bytes::generate(),
/// };
///
/// println!("Question: {}", qa_salt.question.question);
/// println!("Answer: {}", qa_salt.answer);
/// ```
///
/// ## Using Sample Data
///
/// ```
/// use svar_core::*;
///
/// let sample = SecurityQuestionAnswerAndSalt::sample();
/// let other_sample = SecurityQuestionAnswerAndSalt::sample_other();
///
/// assert_ne!(sample, other_sample);
/// assert_ne!(sample.salt, other_sample.salt);
/// ```
///
/// # Serialization
///
/// Implements [`Serialize`] and [`Deserialize`] for storage:
///
/// ```
/// use svar_core::*;
///
/// let qa_salt = SecurityQuestionAnswerAndSalt::sample();
/// let json = serde_json::to_string(&qa_salt)?;
/// let restored: SecurityQuestionAnswerAndSalt = serde_json::from_str(&json)?;
/// assert_eq!(qa_salt, restored);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Display Format
///
/// The [`Display`] implementation shows the question and answer (but not the
/// salt):
///
/// ```
/// use svar_core::*;
///
/// let qa_salt = SecurityQuestionAnswerAndSalt::sample();
/// let display = format!("{}", qa_salt);
/// assert!(display.contains("SecurityQuestionAnswerAndSalt"));
/// assert!(display.contains("question:"));
/// assert!(display.contains("answer:"));
/// // Salt is not included in display for security
/// ```
#[derive(
    Serialize, Display, Deserialize, Clone, PartialEq, Eq, Hash, Debug,
)]
#[display(
    "SecurityQuestionAnswerAndSalt(question: {question}, answer: {answer})"
)]
pub struct SecurityQuestionAnswerAndSalt {
    /// The security question being answered.
    ///
    /// Contains all metadata about the question including its ID, version,
    /// category, text, and expected answer format.
    pub question: SecurityQuestion,

    /// The user's answer to the security question.
    ///
    /// This is the actual response provided by the user. The answer is used
    /// in combination with the question and salt to derive encryption keys.
    /// Should be stored and retrieved exactly as provided for consistent
    /// key derivation.
    pub answer: String,

    /// Cryptographic salt for key derivation.
    ///
    /// A 32-byte random value used to ensure that identical question/answer
    /// pairs produce different encryption keys across different encryptions.
    /// Generated using a cryptographically secure random number generator.
    pub salt: Exactly32Bytes,
}

impl SecurityQuestionAnswerAndSalt {
    /// Creates a new instance by answering a freeform security question.
    ///
    /// This method provides a structured way to create a question-answer-salt
    /// triplet by providing a closure that generates the answer based on the
    /// question text and expected format. A cryptographic salt is automatically
    /// generated.
    ///
    /// # Parameters
    ///
    /// - `question`: The security question to be answered (must be freeform)
    /// - `provide_answer`: Closure that receives the question text and format,
    ///   and returns the user's answer
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the new instance or an error if the
    /// question is not of the freeform kind.
    ///
    /// # Examples
    ///
    /// ## Interactive Answer Collection
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::sample();
    ///
    /// let qa_salt = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    ///     question.clone(),
    ///     |question_text, format| {
    ///         println!("Question: {}", question_text);
    ///         println!("Expected format: {:?}", format);
    ///         // In a real application, you'd prompt the user
    ///         "My answer".to_string()
    ///     },
    /// )?;
    ///
    /// assert_eq!(qa_salt.answer, "My answer");
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// ## Conditional Answer Based on Format
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::sample();
    ///
    /// let qa_salt = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    ///     question,
    ///     |_question_text, format| {
    ///         if format.answer_structure.contains("DATE") {
    ///             "1990-01-01".to_string()
    ///         } else {
    ///             "My answer".to_string()
    ///         }
    ///     },
    /// )?;
    /// # Ok::<(), svar_core::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the question is not of kind
    /// [`SecurityQuestionKind::Freeform`]. Currently, this method only
    /// supports freeform questions.
    ///
    /// # Security Notes
    ///
    /// - The salt is automatically generated using a cryptographically secure
    ///   RNG
    /// - Each call produces a unique salt, ensuring key derivation uniqueness
    /// - The answer should be consistent for reliable decryption
    pub fn by_answering_freeform(
        question: SecurityQuestion,
        provide_answer: impl FnOnce(
            String,
            SecurityQuestionExpectedAnswerFormat,
        ) -> String,
    ) -> Result<Self> {
        assert_eq!(question.kind, SecurityQuestionKind::Freeform); // unfailable
        let answer = provide_answer(
            question.question.clone(),
            question.expected_answer_format.clone(),
        );

        if answer.is_empty() {
            return Err(Error::AnswersToSecurityQuestionsCannotBeEmpty);
        }

        Ok(Self {
            question,
            answer,
            salt: Exactly32Bytes::generate(),
        })
    }
}

impl SecurityQuestionAnswerAndSalt {
    /// Extracts the question and salt components without the answer.
    ///
    /// This method creates a [`SecurityQuestionAndSalt`] which contains only
    /// the question and salt, omitting the answer. This is used when we are
    /// creating the [`SecurityQuestionsSealed`] which stores the questions
    /// and their salts, without the answers (of course...).
    ///
    /// # Returns
    ///
    /// A new [`SecurityQuestionAndSalt`] containing the question and salt.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let qa_salt = SecurityQuestionAnswerAndSalt::sample();
    /// let question_and_salt = qa_salt.question_and_salt();
    ///
    /// assert_eq!(question_and_salt.question, qa_salt.question);
    /// assert_eq!(question_and_salt.salt, qa_salt.salt);
    /// // Answer is not included in the result
    /// ```
    ///
    /// ## Use Case: Storing Questions for Later
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let qa_salt = SecurityQuestionAnswerAndSalt::sample();
    ///
    /// // Store only question and salt (without sensitive answer)
    /// let storable = qa_salt.question_and_salt();
    ///
    /// // Later, when user provides answer again:
    /// let reconstructed = SecurityQuestionAnswerAndSalt {
    ///     question: storable.question,
    ///     answer: "user provided answer".to_string(),
    ///     salt: storable.salt,
    /// };
    /// ```
    ///
    /// # Security Notes
    ///
    /// This method helps separate sensitive (answer) from non-sensitive
    /// (question, salt) data, allowing for secure storage patterns where
    /// answers are never persisted.
    pub fn question_and_salt(&self) -> SecurityQuestionAndSalt {
        SecurityQuestionAndSalt {
            question: self.question.clone(),
            salt: self.salt,
        }
    }
}

impl HasSampleValues for SecurityQuestionAnswerAndSalt {
    fn sample() -> Self {
        Self {
            question: SecurityQuestion::first_concert(),
            answer: "Jean-Michel Jarre, Paris La Défense, 1990".to_owned(),
            salt: Exactly32Bytes::sample_aced(),
        }
    }

    fn sample_other() -> Self {
        Self {
            question: SecurityQuestion::stuffed_animal(),
            answer: "Oinky piggy pig".to_owned(),
            salt: Exactly32Bytes::sample_babe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    type Sut = SecurityQuestionAnswerAndSalt;

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
    fn test_by_answering_freeform() {
        let question = SecurityQuestion::first_concert();
        let answer = "Jean-Michel Jarre, Paris La Défense, 1990".to_owned();
        let qa = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            question.clone(),
            |_, _| answer.clone(),
        )
        .expect("Should have been able to answer freeform question");
        assert_eq!(qa.question, question);
        assert_eq!(qa.answer, answer);

        let second = SecurityQuestionAnswerAndSalt::by_answering_freeform(
            question.clone(),
            |_, _| answer.clone(),
        )
        .expect("Should have been able to answer freeform question");
        assert_ne!(qa, second);
        assert_eq!(qa.question, second.question);
        assert_eq!(qa.answer, second.answer);
        assert_ne!(qa.salt, second.salt);
    }
}

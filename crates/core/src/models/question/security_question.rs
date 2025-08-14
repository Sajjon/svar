use crate::prelude::*;

/// A security question used for encrypting and decrypting secrets.
///
/// A security question represents a question that can be asked to a user, along
/// with metadata about the expected answer format and categorization. Security
/// questions are used as part of the key derivation process for encrypting
/// secrets.
///
/// # Structure
///
/// Each security question contains:
/// - A unique identifier and version for tracking
/// - A categorization of the question type
/// - The actual question text
/// - Expected answer format constraints
///
/// # Examples
///
/// ## Creating a Security Question
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::with_details(
///     1,                                    // id
///     1,                                    // version
///     SecurityQuestionKind::Freeform,       // kind
///     "What is your mother's maiden name?", // question
///     SecurityQuestionExpectedAnswerFormat::with_details(
///         "Last name",
///         "Smith",
///         [],
///     ), // format
/// );
///
/// assert_eq!(question.id, 1);
/// assert_eq!(question.question, "What is your mother's maiden name?");
/// ```
///
/// ## Using Sample Questions
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::sample();
/// println!("Question: {}", question.question);
///
/// let other_question = SecurityQuestion::sample_other();
/// assert_ne!(question, other_question);
/// ```
///
/// ## Question as String Reference
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::sample();
/// let question_text: &str = question.as_ref();
/// assert_eq!(question_text, &question.question);
/// ```
///
/// # Security Considerations
///
/// - **Question Quality**: Choose questions with high entropy and consistent
///   answers
/// - **Answer Stability**: Questions should have answers that don't change over
///   time
/// - **Cultural Sensitivity**: Consider cultural differences in question
///   interpretation
/// - **Format Constraints**: Use appropriate answer format constraints to
///   ensure consistency
///
/// # Serialization
///
/// Security questions implement [`Serialize`] and [`Deserialize`] for storage
/// and transmission:
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::sample();
/// let json = serde_json::to_string(&question)?;
/// let restored: SecurityQuestion = serde_json::from_str(&json)?;
/// assert_eq!(question, restored);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(
    Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, Display,
)]
#[display(
    "SecurityQuestion(id: {id}, version: {version}, kind: {kind}, question: {question}, format: {expected_answer_format})"
)]
pub struct SecurityQuestion {
    /// Unique identifier for this security question.
    ///
    /// This ID allows for tracking and referencing specific questions across
    /// different versions and implementations. Questions with the same ID but
    /// different versions represent updates to the same conceptual question.
    pub id: u16, // FIXME: newtype

    /// Version number for this security question.
    ///
    /// Allows for evolution of questions over time while maintaining backwards
    /// compatibility. Higher version numbers indicate newer versions of the
    /// same question (identified by the same ID).
    pub version: u8, // FIXME: newtype

    /// The category or type of this security question.
    ///
    /// Categorizes questions by their nature (e.g., personal history,
    /// preferences, factual information) to help with question selection
    /// and validation.
    pub kind: SecurityQuestionKind,

    /// The actual question text presented to the user.
    ///
    /// This is the human-readable question that users will see and answer.
    /// Should be clear, unambiguous, and culturally appropriate.
    pub question: String,

    /// Expected format constraints for answers to this question.
    ///
    /// Defines how answers should be structured (e.g., single line, date
    /// format, numeric) to ensure consistency in answer collection and
    /// validation.
    pub expected_answer_format: SecurityQuestionExpectedAnswerFormat,
}

/// Provides access to the question text as a string reference.
///
/// This implementation allows `SecurityQuestion` to be used anywhere a string
/// reference is expected, making it convenient to access the question text.
///
/// # Examples
///
/// ```
/// use svar_core::*;
///
/// let question = SecurityQuestion::sample();
/// let text: &str = question.as_ref();
/// assert_eq!(text, &question.question);
///
/// // Can be used with functions expecting &str
/// fn print_question(q: impl AsRef<str>) {
///     println!("Question: {}", q.as_ref());
/// }
/// print_question(&question);
/// ```
impl AsRef<str> for SecurityQuestion {
    fn as_ref(&self) -> &str {
        &self.question
    }
}

impl SecurityQuestion {
    /// Creates a new security question with all details specified.
    ///
    /// This is the most comprehensive constructor, allowing full control over
    /// all aspects of the security question including ID, version, kind,
    /// question text, and expected answer format.
    ///
    /// # Parameters
    ///
    /// - `id`: Unique identifier for this question
    /// - `version`: Version number for this question
    /// - `kind`: Category/type of the question
    /// - `question`: The question text to present to users
    /// - `expected_answer_format`: Format constraints for answers
    ///
    /// # Returns
    ///
    /// A new `SecurityQuestion` instance with the specified details.
    ///
    /// # Examples
    ///
    /// ## Personal Information Question
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::with_details(
    ///     101,
    ///     1,
    ///     SecurityQuestionKind::Freeform,
    ///     "What was the name of your first pet?",
    ///     SecurityQuestionExpectedAnswerFormat::with_details(
    ///         "Pet name",
    ///         "Fluffy",
    ///         ["Dog", "Cat"],
    ///     ),
    /// );
    ///
    /// assert_eq!(question.id, 101);
    /// assert_eq!(question.version, 1);
    /// assert_eq!(question.kind, SecurityQuestionKind::Freeform);
    /// ```
    ///
    /// ## Factual Question
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::with_details(
    ///     102,
    ///     2,
    ///     SecurityQuestionKind::Freeform,
    ///     "What is your date of birth? (YYYY-MM-DD)",
    ///     SecurityQuestionExpectedAnswerFormat::with_details(
    ///         "YYYY-MM-DD",
    ///         "1990-01-01",
    ///         [],
    ///     ),
    /// );
    /// ```
    ///
    /// ## General Question
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::with_details(
    ///     103,
    ///     1,
    ///     SecurityQuestionKind::Freeform,
    ///     "What is your favorite color?",
    ///     SecurityQuestionExpectedAnswerFormat::with_details(
    ///         "Color name",
    ///         "Blue",
    ///         ["Red", "Blue", "Green"],
    ///     ),
    /// );
    ///
    /// assert_eq!(question.kind, SecurityQuestionKind::Freeform);
    /// ```
    pub fn with_details(
        id: u16,
        version: u8,
        kind: SecurityQuestionKind,
        question: impl AsRef<str>,
        expected_answer_format: SecurityQuestionExpectedAnswerFormat,
    ) -> Self {
        Self {
            id,
            version,
            kind,
            question: question.as_ref().to_owned(),
            expected_answer_format,
        }
    }

    /// Creates a freeform security question with the specified ID.
    ///
    /// This is a convenience constructor for creating freeform questions
    /// (version 1) with a specified ID. Freeform questions allow flexible
    /// answer formats.
    ///
    /// # Parameters
    ///
    /// - `id`: Unique identifier for this question
    /// - `question`: The question text to present to users
    /// - `expected_answer_format`: Format constraints for answers
    ///
    /// # Returns
    ///
    /// A new freeform `SecurityQuestion` with version 1.
    ///
    /// # Examples
    ///
    /// ```
    /// use svar_core::*;
    ///
    /// let question = SecurityQuestion::with_details(
    ///     42,
    ///     1,
    ///     SecurityQuestionKind::Freeform,
    ///     "What was the make of your first car?",
    ///     SecurityQuestionExpectedAnswerFormat::with_details(
    ///         "Car make",
    ///         "Toyota",
    ///         ["Toyota", "Honda", "Ford"],
    ///     ),
    /// );
    ///
    /// assert_eq!(question.id, 42);
    /// assert_eq!(question.version, 1);
    /// assert_eq!(question.kind, SecurityQuestionKind::Freeform);
    /// ```
    fn freeform_with_id(
        id: u16,
        question: impl AsRef<str>,
        expected_answer_format: SecurityQuestionExpectedAnswerFormat,
    ) -> Self {
        Self::with_details(
            id,
            1,
            SecurityQuestionKind::Freeform,
            question,
            expected_answer_format,
        )
    }
}

impl SecurityQuestion {
    /// An NON-entropy-analyzed security question
    ///  
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn failed_exam() -> Self {
        Self::freeform_with_id(
            0,
            "What was the first exam you failed",
            SecurityQuestionExpectedAnswerFormat::new(
                "<SCHOOL>, <SCHOOL_GRADE>, <SUBJECT>",
                "MIT, year 4, Python",
            ),
        )
    }

    pub fn q00() -> Self {
        Self::failed_exam()
    }

    /// An NON-entropy-analyzed security question
    ///  
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn parents_met() -> Self {
        Self::freeform_with_id(
            1,
            "In which city and which year did your parents meet?",
            SecurityQuestionExpectedAnswerFormat::preset_city_and_year(),
        )
    }

    pub fn q01() -> Self {
        Self::parents_met()
    }

    /// An NON-entropy-analyzed security question
    pub fn first_concert() -> Self {
        Self::freeform_with_id(
            2,
            "What was the first concert you attended?",
            SecurityQuestionExpectedAnswerFormat::new(
                "<ARTIST>, <LOCATION>, <YEAR>",
                "Jean-Michel Jarre, Paris La Défense, 1990",
            ),
        )
    }
    pub fn q02() -> Self {
        Self::first_concert()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn first_kiss_whom() -> Self {
        Self::freeform_with_id(
            3,
            "What was the name of the boy or the girl you first kissed?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q03() -> Self {
        Self::first_kiss_whom()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn first_kiss_location() -> Self {
        Self::freeform_with_id(
            4,
            "Where were you when you had your first kiss?",
            SecurityQuestionExpectedAnswerFormat::location(),
        )
    }

    pub fn q04() -> Self {
        Self::first_kiss_location()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn spouse_met() -> Self {
        Self::freeform_with_id(
            5,
            "In what city and which year did you meet your spouse/significant other?",
            SecurityQuestionExpectedAnswerFormat::preset_city_and_year(),
        )
    }

    pub fn q05() -> Self {
        Self::spouse_met()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn child_middle_name() -> Self {
        Self::freeform_with_id(
            6,
            "What is the middle name of your youngest child?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q06() -> Self {
        Self::child_middle_name()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by NordVPN][link].
    ///
    /// [link]: https://nordvpn.com/blog/security-questions/
    pub fn stuffed_animal() -> Self {
        Self::freeform_with_id(
            7,
            "What was the name of your first stuffed animal?",
            SecurityQuestionExpectedAnswerFormat::with_details(
                "<NAME>",
                "Oinky piggy pig",
                ["Teddy", "Cat", "Dog", "Winnie (the Poh)", "(Peter) Rabbit"],
            ),
        )
    }

    pub fn q07() -> Self {
        Self::stuffed_animal()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by ExpressVPN][link].
    ///
    /// [link]: https://www.expressvpn.com/blog/how-to-choose-a-security-question/
    pub fn oldest_cousin() -> Self {
        Self::freeform_with_id(
            8,
            "What is your oldest cousin's middle name?",
            SecurityQuestionExpectedAnswerFormat::with_details(
                "<NAME>",
                "Maria",
                [
                    "Don't use this one if you and your cousin are very close and have plenty of mutual friends.",
                ],
            ),
        )
    }

    pub fn q08() -> Self {
        Self::oldest_cousin()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by ExpressVPN][link].
    ///
    /// [link]: https://www.expressvpn.com/blog/how-to-choose-a-security-question/
    pub fn teacher_grade3() -> Self {
        Self::freeform_with_id(
            9,
            "What was the last name of your third grade teacher?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q09() -> Self {
        Self::teacher_grade3()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by OWASP][link].
    ///
    /// [link]:  https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html
    pub fn applied_uni_no_attend() -> Self {
        Self::freeform_with_id(
            10,
            "What is the name of a college you applied to but didn't attend?",
            SecurityQuestionExpectedAnswerFormat::new(
                "<UNIVERSITY NAME>",
                "Oxford",
            ),
        )
    }

    pub fn q10() -> Self {
        Self::applied_uni_no_attend()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by OWASP][link].
    ///
    /// [link]:  https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html
    pub fn first_school() -> Self {
        Self::freeform_with_id(
            11,
            "What was the name of the first school you remember attending?",
            SecurityQuestionExpectedAnswerFormat::new(
                "<SCHOOL NAME>",
                "Hogwartz",
            ),
        )
    }

    pub fn q11() -> Self {
        Self::first_school()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by OWASP][link].
    ///
    /// [link]:  https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html
    pub fn math_teacher_highschool() -> Self {
        Self::freeform_with_id(
            12,
            "What was your maths teacher's surname in 7th grade?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q12() -> Self {
        Self::math_teacher_highschool()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question by OWASP][link].
    ///
    /// [link]:  https://cheatsheetseries.owasp.org/cheatsheets/Choosing_and_Using_Security_Questions_Cheat_Sheet.html
    pub fn drivings_instructor() -> Self {
        Self::freeform_with_id(
            13,
            "What was your driving instructor's first name?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q13() -> Self {
        Self::drivings_instructor()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question in spreadsheet][sheet], linked to [from].
    ///
    /// [from]: https://goodsecurityquestions.com/examples/
    /// [sheet]: https://docs.google.com/spreadsheets/d/1Mzg60sJYLzUzCJhe-_brprx-KRolvLclcykf4H4hF-c/edit#gid=0
    pub fn street_friend_highschool() -> Self {
        Self::freeform_with_id(
            14,
            "What was the street name where your best friend in high school lived?",
            SecurityQuestionExpectedAnswerFormat::with_details(
                "<STREET NAME WITHOUT NUMBER>",
                "Baker Street",
                [
                    "Bad if had several different best friends during high school.",
                ],
            ),
        )
    }

    pub fn q14() -> Self {
        Self::street_friend_highschool()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question in spreadsheet][sheet], linked to [from].
    ///
    /// [from]: https://goodsecurityquestions.com/examples/
    /// [sheet]: https://docs.google.com/spreadsheets/d/1Mzg60sJYLzUzCJhe-_brprx-KRolvLclcykf4H4hF-c/edit#gid=0
    pub fn friend_kindergarten() -> Self {
        Self::freeform_with_id(
            15,
            "What was the first name of your best friend at kindergarten?",
            SecurityQuestionExpectedAnswerFormat::name(),
        )
    }

    pub fn q15() -> Self {
        Self::friend_kindergarten()
    }

    /// An NON-entropy-analyzed security question
    ///
    /// [Suggested question in spreadsheet][sheet], linked to [from].
    ///
    /// [from]: https://goodsecurityquestions.com/examples/
    /// [sheet]: https://docs.google.com/spreadsheets/d/1Mzg60sJYLzUzCJhe-_brprx-KRolvLclcykf4H4hF-c/edit#gid=0
    pub fn street_age8() -> Self {
        Self::freeform_with_id(
            16,
            "What was the name of the street where you were living when you were 8 years old?",
            SecurityQuestionExpectedAnswerFormat::with_details(
                "<STREET NAME WITHOUT NUMBER>",
                "Abbey Road",
                ["Bad if you lived in many places during that year."],
            ),
        )
    }

    pub fn q16() -> Self {
        Self::street_age8()
    }
}

impl SecurityQuestion {
    pub fn all() -> IndexSet<Self> {
        Self::freeform()
    }
    pub fn freeform() -> IndexSet<Self> {
        IndexSet::<SecurityQuestion>::from_iter([
            Self::q00(),
            Self::q01(),
            Self::q02(),
            Self::q03(),
            Self::q04(),
            Self::q05(),
            Self::q06(),
            Self::q07(),
            Self::q08(),
            Self::q09(),
            Self::q10(),
            Self::q11(),
            Self::q12(),
            Self::q13(),
            Self::q14(),
            Self::q15(),
            Self::q16(),
        ])
    }
}

impl HasSampleValues for SecurityQuestion {
    /// A sample used to facilitate unit tests.
    fn sample() -> Self {
        Self::stuffed_animal()
    }

    /// A sample used to facilitate unit tests.
    fn sample_other() -> Self {
        Self::first_kiss_location()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Sut = SecurityQuestion;

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
    fn hash() {
        let mut set = IndexSet::new();
        set.extend(Sut::all());
        set.extend(Sut::all());
        assert_eq!(set.len(), 17);
    }

    #[test]
    fn freeform_samples() {
        assert!(
            Sut::freeform()
                .iter()
                .all(|q| q.kind == SecurityQuestionKind::Freeform)
        );
    }
}

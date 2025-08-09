use crate::prelude::*;

/// A security question
#[derive(
    Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, Display,
)]
#[display(
    "SecurityQuestion(id: {id}, version: {version}, kind: {kind}, question: {question}, format: {expected_answer_format})"
)]
pub struct SecurityQuestion {
    pub id: u16,     // FIXME: newtype
    pub version: u8, // FIXME: newtype
    pub kind: SecurityQuestionKind,
    pub question: String,
    pub expected_answer_format: SecurityQuestionExpectedAnswerFormat,
}

impl AsRef<str> for SecurityQuestion {
    fn as_ref(&self) -> &str {
        &self.question
    }
}

impl SecurityQuestion {
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
}

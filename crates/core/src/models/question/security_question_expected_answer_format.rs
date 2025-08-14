use crate::prelude::*;

/// A specification of expected format for an answer to a security question.
#[derive(
    Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, Display,
)]
#[display("{answer_structure}")]
pub struct SecurityQuestionExpectedAnswerFormat {
    /// E.g. `"<CITY>, <YEAR>"`
    pub answer_structure: String,

    /// An example of a possible answer that matches `answer_structure`.
    /// E.g. `"Berlin, 1976"`
    pub example_answer: String,

    /// If user is about to select the question:
    /// `"What was the name of your first stuffed animal?"`
    ///
    /// Then we can discourage the user from selecting that question
    /// if the answer is in `["Teddy", "Peter Rabbit", "Winnie (the Poh)"]`
    pub unsafe_answers: Vec<String>,
}

impl SecurityQuestionExpectedAnswerFormat {
    pub fn with_details(
        structure: impl AsRef<str>,
        example: impl AsRef<str>,
        unsafe_answers: impl IntoIterator<Item = &'static str>,
    ) -> Self {
        Self {
            answer_structure: structure.as_ref().to_owned(),
            example_answer: example.as_ref().to_owned(),
            unsafe_answers: unsafe_answers
                .into_iter()
                .map(|x| x.to_owned())
                .collect_vec(),
        }
    }

    pub fn new(structure: impl AsRef<str>, example: impl AsRef<str>) -> Self {
        Self::with_details(structure, example, [])
    }

    pub fn name() -> Self {
        Self::new("<NAME>", "Maria")
    }

    pub fn location() -> Self {
        Self::with_details(
            "<LOCATION>",
            "At bus stop outside of Dallas",
            ["Specifying only a country as location would be unsafe"],
        )
    }

    pub fn preset_city_and_year() -> Self {
        Self::new("<CITY>, <YEAR>", "Berlin, 1976")
    }
}

impl HasSampleValues for SecurityQuestionExpectedAnswerFormat {
    fn sample() -> Self {
        Self::preset_city_and_year()
    }

    fn sample_other() -> Self {
        Self::name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    type Sut = SecurityQuestionExpectedAnswerFormat;

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

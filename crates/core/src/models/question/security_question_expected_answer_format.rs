use crate::prelude::*;

/// A specification of expected format for an answer to a security question.
#[derive(
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Display,
    getset::Getters,
)]
#[display("{answer_structure}")]
pub struct SecurityQuestionExpectedAnswerFormat {
    /// E.g. `"<CITY>, <YEAR>"`
    #[getset(get = "pub")]
    answer_structure: String,

    /// An example of a possible answer that matches `answer_structure`.
    /// E.g. `"Berlin, 1976"`
    #[getset(get = "pub")]
    example_answer: String,

    /// If user is about to select the question:
    /// `"What was the name of your first stuffed animal?"`
    ///
    /// Then we can discourage the user from selecting that question
    /// if the answer is in `["Teddy", "Peter Rabbit", "Winnie (the Poh)"]`
    #[getset(get = "pub")]
    unsafe_answers: Vec<String>,
}

#[bon::bon]
impl SecurityQuestionExpectedAnswerFormat {
    #[builder]
    pub fn new(
        #[builder(into)] answer_structure: String,
        #[builder(into)] example_answer: String,
        #[builder(
            default,
            with = |unsafe_answers: impl IntoIterator<Item = impl Into<String>>| {
                unsafe_answers.into_iter().map(Into::into).collect()
            }
        )]
        unsafe_answers: Vec<String>,
    ) -> Self {
        Self {
            answer_structure,
            example_answer,
            unsafe_answers,
        }
    }

    pub fn name() -> Self {
        Self::builder()
            .answer_structure("<NAME>")
            .example_answer("Maria")
            .build()
    }

    pub fn location() -> Self {
        Self::builder()
            .answer_structure("<LOCATION>")
            .example_answer("At bus stop outside of Dallas")
            .unsafe_answers([
                "Specifying only a country as location would be unsafe",
            ])
            .build()
    }

    pub fn preset_city_and_year() -> Self {
        Self::builder()
            .answer_structure("<CITY>, <YEAR>")
            .example_answer("Berlin, 1976")
            .build()
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

use crate::prelude::*;

use hkdf::Hkdf;
use sha2::Sha256;

/// A Key Derivation Scheme which lowercases, trims and ut8f encodes answers.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub struct SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8;

impl HasSampleValues for SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8 {
    fn sample() -> Self {
        Self
    }

    fn sample_other() -> Self {
        Self
    }
}

impl Default for SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8 {
    fn default() -> Self {
        Self
    }
}
pub(crate) const SECURITY_QUESTIONS_TRIMMED_CHARS: &[char] = &[
    ' ',  // whitespace
    '\t', // whitespace
    '\n', // whitespace
    '.', // Rationale: Might be natural for some to end answers with a dot, but at a later point in time might be omitted.
    '!', // Rationale: Same as dot
    '?', // Rationale: Same as dot (also strange for an answer to a question to contain a question mark)
    '\'', // Rationale: Feels like an unnecessary risk for differences, sometimes some might omit apostrophe (U+0027)
    '\"', // Rationale: Same as apostrophe (this is "Quotation Mark" (U+0022))
    '‘',  // Rationale: Same as apostrophe (this is "Left Single Quotation Mark" (U+2018))
    '’',  // Rationale: Same as apostrophe (this is "Right Single Quotation Mark" (U+2019))
    '＇', // Rationale: Same as apostrophe (this is "Full Width Apostrophe" (U+FF07))
];

impl SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8 {
    pub fn trim_answer(&self, answer: impl AsRef<str>) -> String {
        let mut answer = answer.as_ref().to_lowercase();
        answer.retain(|c| !SECURITY_QUESTIONS_TRIMMED_CHARS.contains(&c));
        answer
    }

    fn bytes_from_answer(&self, answer: impl AsRef<str>) -> Result<Vec<u8>> {
        let answer = answer.as_ref();
        if answer.is_empty() {
            return Err(Error::AnswersToSecurityQuestionsCannotBeEmpty);
        }

        let trimmed = self.trim_answer(answer);

        Ok(trimmed.as_bytes().to_owned())
    }

    fn bytes_from_question(&self, question: impl AsRef<str>) -> Vec<u8> {
        question.as_ref().as_bytes().to_owned()
    }
}

impl SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8 {
    pub fn derive_entropies_from_question_answer_and_salt(
        &self,
        question_answer_and_salt: &SecurityQuestionAnswerAndSalt,
    ) -> Result<Exactly32Bytes> {
        // Input Key Material: the answer, the most secret.
        let ikm = self.bytes_from_answer(&question_answer_and_salt.answer)?;

        // We use `question` as info so that two same answers give different
        // output for two different questions, silly example might be:
        // Q1: "Name of best childhood teddy" - A1: "Björn"
        // Q2: "Name of first boy/girl you kissed?" A2: "Björn"
        // Here A1 == A2, but we don't want their keys to be the same, so using
        // question as `info` => different keys.
        let info = self.bytes_from_question(&question_answer_and_salt.question);

        let hkdf = Hkdf::<Sha256>::new(Some(question_answer_and_salt.salt.as_ref()), &ikm);
        let mut okm = [0u8; 32];
        hkdf.expand(&info, &mut okm).unwrap();
        Ok(Exactly32Bytes::from(okm))
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    type Sut = SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8;

    #[test]
    fn trimming() {
        let sut = Sut::default();
        let non_trimmed = "FoO\nB.a\tR ' ! FiZz ? ‘ B ’ u＇ZZ";
        let trimmed = sut.trim_answer(non_trimmed);
        assert_eq!(trimmed, "foobarfizzbuzz".to_owned())
    }
}

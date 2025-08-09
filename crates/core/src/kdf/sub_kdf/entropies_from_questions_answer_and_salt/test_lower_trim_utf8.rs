mod tests {

    use crate::prelude::*;

    type Sut = SecurityQuestionsKeyExchangeKeysFromQandAsLowerTrimUtf8;

    #[test]
    fn trimming() {
        let sut = Sut::default();
        let non_trimmed = "FoO\nB.a\tR ' ! FiZz ? ‘ B ’ u＇ZZ";
        let trimmed = sut.trim_answer(non_trimmed);
        assert_eq!(trimmed, "foobarfizzbuzz".to_owned())
    }
}

use crate::prelude::*;

#[derive(
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    derive_more::Debug,
    derive_more::Deref,
    derive_more::DerefMut,
    derive_more::From,
)]
#[serde(transparent)]
pub struct SecurityQuestions(IndexSet<SecurityQuestion>);

impl FromIterator<SecurityQuestion> for SecurityQuestions {
    fn from_iter<T: IntoIterator<Item = SecurityQuestion>>(iter: T) -> Self {
        Self(IndexSet::from_iter(iter))
    }
}

impl HasSampleValues for SecurityQuestions {
    fn sample() -> Self {
        type Q = SecurityQuestion;
        Self::from(IndexSet::from([
            Q::q00(),
            Q::q01(),
            Q::q02(),
            Q::q03(),
            Q::q04(),
            Q::q05(),
        ]))
    }

    fn sample_other() -> Self {
        type Q = SecurityQuestion;
        Self::from(IndexSet::from([
            Q::q06(),
            Q::q07(),
            Q::q08(),
            Q::q09(),
            Q::q10(),
            Q::q11(),
        ]))
    }
}

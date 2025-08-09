use crate::prelude::*;

#[derive(
    Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug, Display,
)]
pub enum SecurityQuestionKind {
    Freeform,
}

use crate::prelude::*;

#[derive(
    Zeroize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    derive_more::Display,
    derive_more::Debug,
    Serialize,
    Deserialize,
    Hash,
)]
#[serde(transparent)]
pub struct EncryptionKey([u8; 32]);

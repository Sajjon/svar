#![deny(unsafe_code)]

//! A user-friendly encryption scheme using Security Questions and their answers
//! to protect some secret, allowing for user to later incorrectly answer some
//! of the questions and still be able to decrypt the secret.
//! 
//! Unsuitable for protection of highly sensitive data alone, but can be used
//! in applications willing to trade off some security for usability. The reason
//! for this is that it is hard to reach a high level of entropy (security) with
//! the proposed number of questions and answers. 
//! 
//! Furthermore, an adversary who knows the victim (close friend or family 
//! member) might know the answers to some of the questions.
//! 
//! ```
//! extern crate svar_core;
//! use svar_core::prelude::*;
//! 
//! let secret = "my secret".to_string();
//! ```

mod encryption;
mod kdf;
mod models;
mod security_questions_sealed;

pub mod prelude {
    pub use crate::encryption::*;
    pub use crate::kdf::*;
    pub use crate::models::*;
    pub use crate::security_questions_sealed::*;

    pub use std::str::FromStr;

    pub use derive_more::{AsRef, Display, From};
    pub use hex::{decode as hex_decode, encode as hex_encode};
    pub use indexmap::IndexSet;
    pub use itertools::Itertools;
    pub use serde::{Deserialize, Serialize};
    pub use serde_with::{DeserializeFromStr, SerializeDisplay};
    pub use zeroize::Zeroize;
}
pub use prelude::*;

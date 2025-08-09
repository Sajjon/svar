pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid questions and answers count: expected {expected}, found {found}")]
    InvalidQuestionsAndAnswersCount { expected: usize, found: usize },

    #[error("Invalid byte count: expected {expected}, found {found}")]
    InvalidByteCount { expected: usize, found: usize },

    #[error("AES Decryption failed: {underlying}")]
    AESDecryptionFailed { underlying: String },

    #[error("Invalid mnemonic phrase: {underlying}")]
    InvalidMnemonicPhrase { underlying: String },

    #[error("Failed to convert secret to bytes: {underlying}")]
    FailedToConvertSecretToBytes { underlying: String },

    #[error("Invalid hex: {underlying}")]
    InvalidHex { underlying: String },

    #[error("Failed to decrypt sealed secret")]
    FailedToDecryptSealedSecret,

    #[error("Invalid AES bytes too short: expected at least {expected_at_least}, found {found}")]
    InvalidAESBytesTooShort {
        expected_at_least: usize,
        found: usize,
    },

    #[error("Answers to security questions cannot be empty")]
    AnswersToSecurityQuestionsCannotBeEmpty,
}

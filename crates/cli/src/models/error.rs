pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum Error {
    #[error("Failed to input new secret to protect, underlying: {underlying}")]
    FailedToInputSecret { underlying: String },

    #[error(
        "Failed to create data local directory at '{dir}', underlying: {underlying}"
    )]
    FailedToCreateDataLocalDir { dir: String, underlying: String },

    #[error(
        "Failed to build answer from terminal input, underlying: {underlying}"
    )]
    InvalidAnswer { underlying: String },

    #[error("Core error: {0}")]
    CoreError(#[from] svar_core::Error),

    #[error("Serialization error: {underlying}")]
    SerializationError { underlying: String },

    #[error("Failed to find data local directory")]
    FailedToFindDataLocalDir,

    #[error(
        "Failed to write sealed secret to file: '{file_path}', underlying: {underlying}"
    )]
    FailedToWriteSealedSecretToFile {
        file_path: String,
        underlying: String,
    },
}

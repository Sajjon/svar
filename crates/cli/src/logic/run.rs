use crate::prelude::*;

/// Prompts the user for an answer to a security question and returns the answer
/// together with question and the salt used.
fn prompt_answer(
    question: SecurityQuestionAndSalt,
    question_index: usize,
    total_questions: usize,
) -> Result<SecurityQuestionAnswerAndSalt> {
    info!("{}", "~".repeat(50));
    info!(
        "Prompting for answer to question {}/{}",
        question_index + 1,
        total_questions
    );
    inquire::Text::new(&question.question.question)
        .with_help_message(&format!(
            "Expected format: \"{}\"",
            question.question.expected_answer_format
        ))
        .prompt()
        .map(|answer| SecurityQuestionAnswerAndSalt {
            question: question.question,
            answer,
            salt: question.salt,
        })
        .map_err(|e| Error::InvalidAnswer {
            underlying: e.to_string(),
        })
}

/// Returns the directory to use for storing the sealed secret,
/// if `create_if_needed` is true, it will create the directory if it does not
/// exist - if `false` is passed it will panic if the directory does not exist.
fn dir_created_if_needed(create_if_needed: bool) -> Result<PathBuf> {
    let dir = dirs_next::data_local_dir()
        .ok_or(Error::FailedToFindDataLocalDir)?
        .join(env!("CARGO_PKG_NAME"));
    if !dir.exists() {
        if create_if_needed {
            fs::create_dir_all(&dir).map_err(|e| {
                Error::FailedToCreateDataLocalDir {
                    dir: dir.display().to_string(),
                    underlying: e.to_string(),
                }
            })?;
        } else {
            panic!("Data local directory does not exist: {}", dir.display());
        }
    }

    Ok(dir)
}

const SECRET_FILE_NAME: &str = "sealed_secret.json";

/// Prompt for answers to security questions and return them as a collection.
fn get_answers_from_questions(
    questions: SecurityQuestionsAndSalts<QUESTION_COUNT>,
) -> Result<SecurityQuestionsAnswersAndSalts<QUESTION_COUNT>> {
    info!(
        "You will now be prompted to answer #{} questions",
        questions.len()
    );
    let answers = questions
        .iter()
        .cloned()
        .enumerate()
        .map(|(i, q)| prompt_answer(q, i, questions.len()))
        .collect::<Result<Vec<_>>>()?;

    let answers =
        SecurityQuestionsAnswersAndSalts::<QUESTION_COUNT>::try_from_iter(
            answers,
        )?;
    Ok(answers)
}

/// Protects a new secret by prompting the user for a secret and security
/// questions and answers.
fn protect_new_secret_at(file_path: impl AsRef<Path>) -> Result<()> {
    let secret_to_protect =
        inquire::Password::new("Enter the secret to protect:")
            .with_display_toggle_enabled()
            .with_display_mode(PasswordDisplayMode::Hidden)
            .without_confirmation()
            .with_formatter(&|_| String::from("Input received"))
            .with_help_message("Press CTRL+R to toggle reveal/hide your input.")
            .prompt()
            .map_err(|e| Error::FailedToInputSecret {
                underlying: e.to_string(),
            })?;

    info!(
        "Secret to protect received: #{} chars",
        secret_to_protect.len()
    );

    type Q = SecurityQuestionAndSalt;
    let questions =
        SecurityQuestionsAndSalts::<QUESTION_COUNT>::try_from_iter([
            Q::generate_salt(SecurityQuestion::q00()),
            Q::generate_salt(SecurityQuestion::q01()),
            Q::generate_salt(SecurityQuestion::q02()),
            Q::generate_salt(SecurityQuestion::q03()),
        ])
        .unwrap();

    let answers = get_answers_from_questions(questions)?;
    info!("All answers received, now sealing the secret...");

    debug!("Sealing the secret with questions and answers...");
    let sealed = SecurityQuestionsSealed::<
        String,
        QUESTION_COUNT,
        MIN_ANSWER_COUNT,
    >::seal(secret_to_protect, answers)?;
    info!(
        "Successfully sealed secret with questions and answers (and generated salts)."
    );

    debug!("Serializing sealed secret...");
    let sealed_json = serde_json::to_string_pretty(&sealed).map_err(|e| {
        Error::SerializationError {
            underlying: e.to_string(),
        }
    })?;
    let file_path = file_path.as_ref();
    debug!("Serialized sealed secret.");

    debug!("Saving sealed secret to file: {}", file_path.display());
    fs::write(file_path, sealed_json).map_err(|e| {
        Error::FailedToWriteSealedSecretToFile {
            file_path: file_path.display().to_string(),
            underlying: e.to_string(),
        }
    })?;
    info!("Saved sealed secret to file: {}", file_path.display());

    Ok(())
}

/// Opens a secret by prompting the user for answers to security questions.
fn open_sealed_secret_at(file_path: impl AsRef<Path>) -> Result<()> {
    let file_path = file_path.as_ref();
    info!("Opening sealed secret from file: {}", file_path.display());

    let sealed_json = fs::read_to_string(file_path).map_err(|e| {
        Error::FailedToWriteSealedSecretToFile {
            file_path: file_path.display().to_string(),
            underlying: e.to_string(),
        }
    })?;

    debug!("Deserializing sealed secret...");
    let sealed: SecurityQuestionsSealed<
        String,
        QUESTION_COUNT,
        MIN_ANSWER_COUNT,
    > = serde_json::from_str(&sealed_json).map_err(|e| {
        Error::SerializationError {
            underlying: e.to_string(),
        }
    })?;
    debug!("Deserialized sealed secret.");

    let answers = get_answers_from_questions(
        sealed.security_questions_and_salts.clone(),
    )?;

    info!("All answers received, now decrypting the sealed secret...");
    let opened = sealed.decrypt(answers)?;
    info!("Sealed secret decrypted successfully.");

    let reveal_secret =
        inquire::Confirm::new("Do you want to print it in the terminal?")
            .with_default(false)
            .prompt()
            .unwrap_or_default();

    if reveal_secret {
        info!("Secret: {}", opened);
    }

    Ok(())
}

/// Seals or opens a sealed secret based on the existence of the sealed secret
/// file.
fn seal_or_open() -> Result<()> {
    let dir = dir_created_if_needed(false)?;
    let file = dir.join(SECRET_FILE_NAME);
    if file.exists() {
        info!("Sealed secret file exists, opening it...");
        open_sealed_secret_at(file)
    } else {
        info!("Sealed secret file does not exist, creating a new one...");
        protect_new_secret_at(file)
    }
}

/// Seals or opens a sealed secret based on the existence of the sealed secret
/// file,
///
/// Logs any error that occurs during the process.
pub(crate) fn run() {
    match seal_or_open() {
        Ok(_) => {}
        Err(e) => {
            error!("Error protecting secret: {}", e);
        }
    }
}

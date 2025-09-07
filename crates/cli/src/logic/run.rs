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

fn data_local_dir() -> Result<PathBuf> {
    dirs_next::data_local_dir()
        .ok_or(Error::FailedToFindDataLocalDir)
        .map(|dir| dir.join(env!("CARGO_PKG_NAME")))
}

/// Returns the directory to use for storing the sealed secret,
/// if `create_if_needed` is true, it will create the directory if it does not
/// exist - if `false` is passed it will panic if the directory does not exist.
fn dir_created_if_needed(create_if_needed: bool) -> Result<PathBuf> {
    let dir = data_local_dir()?;
    if !dir.exists() {
        if create_if_needed {
            fs::create_dir_all(&dir).map_err(|e| {
                Error::FailedToCreateDataLocalDir {
                    dir: dir.display().to_string(),
                    underlying: e.to_string(),
                }
            })?;
        } else {
            return Err(Error::DataLocalDirectoryDoesNotExist {
                dir: dir.display().to_string(),
            });
        }
    }

    Ok(dir)
}

pub fn default_path_for_sealed_secret_without_checking_existence()
-> Result<PathBuf> {
    let dir = data_local_dir()?;
    Ok(dir.join(SECRET_FILE_NAME))
}

pub fn default_path_for_sealed_secret(
    create_if_needed: bool,
) -> Result<PathBuf> {
    let dir = dir_created_if_needed(create_if_needed)?;
    Ok(dir.join(SECRET_FILE_NAME))
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
fn protect_new_secret(
    maybe_input_path_secret: Option<PathBuf>,
    output_path_sealed: impl AsRef<Path>,
) -> Result<()> {
    let secret_to_protect = {
        if let Some(path) = maybe_input_path_secret {
            std::fs::read_to_string(path.clone()).map_err(|e| {
                Error::FailedToReadSecretFromFile {
                    file_path: path.display().to_string(),
                    underlying: e.to_string(),
                }
            })
        } else {
            inquire::Password::new("Enter the secret to protect:")
                .with_display_toggle_enabled()
                .with_display_mode(PasswordDisplayMode::Hidden)
                .without_confirmation()
                .with_formatter(&|_| String::from("Input received"))
                .with_help_message(
                    "Press CTRL+R to toggle reveal/hide your input.",
                )
                .prompt()
                .map_err(|e| Error::FailedToInputSecret {
                    underlying: e.to_string(),
                })
        }
    }?;

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

    let output_path_sealed = output_path_sealed.as_ref();
    debug!("Serialized sealed secret.");

    debug!(
        "Saving sealed secret to file: {}",
        output_path_sealed.display()
    );
    fs::write(output_path_sealed, sealed_json).map_err(|e| {
        Error::FailedToWriteSealedSecretToFile {
            file_path: output_path_sealed.display().to_string(),
            underlying: e.to_string(),
        }
    })?;
    info!(
        "Saved sealed secret to file: {}",
        output_path_sealed.display()
    );

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
    let opened = sealed.open(answers)?;
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

fn open(input: OpenInput) -> Result<()> {
    open_sealed_secret_at(input.sealed_path())
}

fn ask_if_override_existing_sealed_secret(input: &SealInput) -> Result<()> {
    let path = input.sealed_path();
    if path.exists() {
        let override_existing = inquire::Confirm::new(&format!(
            "A sealed secret already exists at '{}'. Do you want to override it?",
            path.display()
        ))
        .with_default(false)
        .prompt()
        .unwrap_or_default();

        if !override_existing {
            info!("Aborting sealing new secret.");
            std::process::exit(0);
        }
    }
    Ok(())
}

fn seal(input: SealInput) -> Result<()> {
    ask_if_override_existing_sealed_secret(&input)?;
    protect_new_secret(input.secret_path(), input.sealed_path())
}

/// Seals or opens a sealed secret based on the command line arguments.
fn seal_or_open(args: CliArgs) -> Result<()> {
    match args.command {
        CommandArgs::Open(input) => {
            if let Some(non_existing_custom_path) =
                input.non_existent_path_to_sealed_secret()
            {
                warn!(
                    "No sealed secret found at: {}",
                    non_existing_custom_path.display()
                );
                return Ok(());
            }
            let input = input.to_input()?;
            open(input)
        }
        CommandArgs::Seal(args) => {
            let input = args.to_input()?;
            seal(input)
        }
    }
}

/// Seals or opens a sealed secret based on the command line arguments.
///
/// Logs any error that occurs during the process.
pub(crate) fn run(args: CliArgs) {
    match seal_or_open(args) {
        Ok(_) => {}
        Err(e) => {
            error!("Error protecting secret: {}", e);
        }
    }
}

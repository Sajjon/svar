# Svar

A user-friendly encryption scheme using Security Questions and their answers
to protect some secret, allowing for user to later incorrectly answer some
of the questions and still be able to decrypt the secret.

Unsuitable for protection of highly sensitive data alone, but can be used
in applications willing to trade off some security for usability. The reason
for this is that it is hard to reach a high level of entropy (security) with
the proposed number of questions and answers.

Furthermore, an adversary who knows the victim (close friend or family
member) might know the answers to some of the questions.

```rust
extern crate svar_core;
use svar_core::prelude::*;

/// Number of security questions
const QUESTIONS_COUNT: usize = 4;
/// Minimum number of correct answers required to decrypt
const MIN_CORRECT_ANSWERS: usize = 3;

/// Define your security questions
///
/// ❗️ It's of the utmost importance that
/// these questions are properly constructed with thorough entropy
/// analysis. This is hard, requires expert knowledge and takes time.
/// The questions below are examples, do not assume they're secure ❗️
let q0 = SecurityQuestion {
    id: 0,
    version: 1,
    kind: SecurityQuestionKind::Freeform,
    question: "What was the first concert you attended?".to_owned(),
    expected_answer_format: SecurityQuestionExpectedAnswerFormat {
        answer_structure: "<ARTIST>, <LOCATION>, <YEAR>".to_owned(),
        example_answer: "Jean-Michel Jarre, Paris La Défense, 1990".to_owned(),
        unsafe_answers: vec![],
    },
};
let q1 = SecurityQuestion {
    id: 1,
    version: 1,
    kind: SecurityQuestionKind::Freeform,
    question: "What was the name of the boy or the girl you first kissed?".to_owned(),
    expected_answer_format: SecurityQuestionExpectedAnswerFormat {
        answer_structure: "<LAST_NAME>, <FIRST_NAME>>".to_owned(),
        example_answer: "Doe, Jane".to_owned(),
        unsafe_answers: vec![]
    },
};
let q2 = SecurityQuestion {
    id: 2,
    version: 1,
    kind: SecurityQuestionKind::Freeform,
    question: "What was the name of your first stuffed animal?".to_owned(),
    expected_answer_format: SecurityQuestionExpectedAnswerFormat {
        answer_structure: "<NAME>".to_owned(),
        example_answer: "Oinky piggy pig".to_owned(),
        unsafe_answers: vec![
            "Teddy".to_owned(),
            "Cat".to_owned(),
            "Dog".to_owned(),
            "Winnie".to_owned(), // Winnie the Poh
            "Rabbit".to_owned(), // Peter Rabbit
        ],
    },
};
let q3 = SecurityQuestion {
    id: 3,
    version: 1,
    kind: SecurityQuestionKind::Freeform,
    question: "What was the last name of your third grade teacher?".to_owned(),
    expected_answer_format: SecurityQuestionExpectedAnswerFormat {
        answer_structure: "<LAST_NAME>, <FIRST_NAME>>".to_owned(),
        example_answer: "Parker, Elisabeth".to_owned(),
        unsafe_answers: vec![],
    },
};

/// The secret the user wants to protect
let user_secret = "user's super sensitive secret".to_owned();

/// Prompt user for answers to the questions
let qas0 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    q0.clone(),
    |_q, _format| "Queen, Wembly Stadium, 1985".to_owned()
).unwrap();

let qas1 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    q1.clone(),
    |_q, _format| "Smith, Sara".to_owned()
).unwrap();

let qas2 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
   q2.clone(),
  |_q, _format| "Fluffy McSnuggles".to_owned()
).unwrap();

let qas3 = SecurityQuestionAnswerAndSalt::by_answering_freeform(
   q3.clone(),
  |_q, _format| "Thompson, Margot".to_owned()
).unwrap();

/// Create the security questions answers and salts
/// (We clone so that we can use them later for decryption)
let qas = SecurityQuestionsAnswersAndSalts::<QUESTIONS_COUNT>::from([qas0.clone(), qas1.clone(), qas2.clone(), qas3.clone()]);

/// Encrypt secret with the security questions answers and salts
/// The generic argument 0: the type of secret - just a String in this case
/// The generic argument 1: the number of questions - 4 in this case
/// The generic argument 2: the minimum number of correct answers required to decrypt - 3 in this case
///
/// Later, when the user wants to decrypt the secret, they can answer the questions
/// with some of the answers being incorrect
let sealed_secret = SecurityQuestionsSealed::<String, QUESTIONS_COUNT, MIN_CORRECT_ANSWERS>::seal(user_secret.clone(), qas).unwrap();

/// Define incorrect answer for question 0 - we will use it later to demonstrate
/// that we can still decrypt the secret with 3 correct answers and 1 incorrect answer
let qas0_incorrect = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    q0.clone(),
    |_q, _format| "Incorrect answer for Q0".to_owned()
).unwrap();

let qas_q0_incorrect = SecurityQuestionsAnswersAndSalts::<QUESTIONS_COUNT>::from([qas0_incorrect.clone(), qas1.clone(), qas2.clone(), qas3.clone()]);

/// Decrypt the secret with the security questions answers and salts - this
/// works even thought we provided one incorrect answer
let decrypted_secret = sealed_secret.decrypt(qas_q0_incorrect).unwrap();

assert_eq!(decrypted_secret, user_secret);

/// We can also provide incorrect answer for question 1... or any other question.
let qas1_incorrect = SecurityQuestionAnswerAndSalt::by_answering_freeform(
    q1.clone(),
    |_q, _format| "Incorrect answer for Q1".to_owned()
).unwrap();

let qas_q1_incorrect = SecurityQuestionsAnswersAndSalts::<QUESTIONS_COUNT>::from([qas0.clone(), qas1_incorrect.clone(), qas2.clone(), qas3.clone()]);

/// Also works with second question being incorrectly answered (or any question)
let decrypted_secret = sealed_secret.decrypt(qas_q1_incorrect.clone()).unwrap();

assert_eq!(decrypted_secret, user_secret);

/// But since we require at least 3 correct answers, if we answer 2 questions
/// incorrectly, we will not be able to decrypt the secret
let qas_two_incorrect_answers = SecurityQuestionsAnswersAndSalts::<QUESTIONS_COUNT>::from([qas0_incorrect.clone(), qas1_incorrect.clone(), qas2.clone(), qas3.clone()]);
let decryption_result = sealed_secret.decrypt(qas_two_incorrect_answers);
assert_eq!(decryption_result, Err(Error::FailedToDecryptSealedSecret));

# Etymology

The noun "svar" is 🇸🇪 Swedish for "answer".

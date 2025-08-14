# svar

This is a simple CLI application that allows you to protect a secret
using security questions and answers.

The program is powered by the `svar_core` crate, which provides the
underlying encryption mechanism.

> [!CAUTION]
> Do not pass real-world secrets to this program, it is just a demo. Proper
> secure prompt handling and production ready security questions would be
> required for production use.

## Installation
Installation requires [Rust](https://www.rust-lang.org/tools/install).

Install the `svar` CLI by running
```sh,no_run
cargo install --git https://github.com/sajjon/svar
```

## Usage
Simply run the `svar` command in your terminal after installation:
```sh,no_run
svar
```

If run for the first time this will prompt you to enter a secret to protect
and then prompt you to answer a set of security questions. The secret will
be encrypted using the answers to the security questions.

The sealed secret - which does not contain any secrets - will be saved
as a JSON file in the local data directory, which on macOS is
`~/Library/Application Support/svar/sealed_secret.json`, on Linux:
`$HOME/.local/share/svar/sealed_secret.json` and on Windows:
`C:\Users\<YOUR_USER>\AppData\Local\svar\sealed_secret.json`.

On subsequent runs the program will try to read the sealed secret from
the file and prompt you to answer the security questions again. If you
answer enough questions correctly, the secret will be decrypted and the
program will ask you if you want to print the secret in the terminal.

If you which to change the secret, simply delete the sealed secret file
and run the program again. It will then prompt you to enter a new secret
and answer the security questions again.

> [!TIP]
> When decrypting a sealed secret, try inputting an incorrect answer to any
> of the questions and it will still decrypt the secret. You can also notice
> that uppercase letters, spaces, and delimiters like commas and periods
> need not match the answers you provided when sealing the secret.

Later we might make this example CLI application more advanced by
allowing you to specify the number of questions and answers, and the
minimum number of correct answers required to decrypt the secret.
We might also allow you to pass a path allowing you to have multiple
sealed secrets.

# Etymology

The noun "svar" is 🇸🇪 Swedish for "answer".

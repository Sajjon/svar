[![codecov](https://codecov.io/gh/Sajjon/svar/graph/badge.svg?token=J1hjUUQDtR)](https://codecov.io/gh/Sajjon/svar)

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

### Seal (Encrypt)
Simply run the `svar` command in your terminal after installation:
```sh,no_run
svar seal
```

This will prompt you to enter a secret to protect
and then prompt you to answer a set of security questions. The secret will
be encrypted using the answers to the security questions.

The sealed secret - which does not contain any secrets - will be saved
as a JSON file in the local data directory, which on macOS is
`~/Library/Application Support/svar/sealed_secret.json`, on Linux:
`$HOME/.local/share/svar/sealed_secret.json` and on Windows:
`C:\Users\<YOUR_USER>\AppData\Local\svar\sealed_secret.json`.

#### Custom paths
Alternatively you can specify a custom path to read the secret from
and a custom path to save the sealed secret to using the `-i` and
`-o` flags respectively:
```sh,no_run
svar seal -i /path/to/your/secret.txt -o /path/to/save/sealed_secret.json
```

When the `-i` flag is provided, the program will not prompt you to input
the secret, but will read it from the specified file instead. The sealed
secret will be written to the path specified by the `-o` flag.

### Open (Decrypt)
You can open a sealed secret using the `open` command:
```sh,no_run
svar open
```

This will try to read the a sealed secret at the default path and prompt you
to answer the security questions again. If you answer enough questions
correctly, the secret will be decrypted and the program will ask you if you
want to print the secret in the terminal.

If you which to change the secret, simply delete the sealed secret file
and run the program again. It will then prompt you to enter a new secret
and answer the security questions again.

#### Custom path
You can also specify a custom path to read the sealed secret from
using the `-i` flag:
```sh,no_run
svar open -i /path/to/sealed_secret.json
```

> [!TIP]
> When decrypting a sealed secret, try inputting an incorrect answer to any
> of the questions and it will still decrypt the secret. You can also notice
> that uppercase letters, spaces, and delimiters like commas and periods
> need not match the answers you provided when sealing the secret.

Later we might make this example CLI application more advanced by
allowing you to specify the number of questions and answers, and the
minimum number of correct answers required to decrypt the secret.

# Etymology

The noun "svar" is 🇸🇪 Swedish for "answer".

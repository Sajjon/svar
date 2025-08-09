#!/bin/bash
# Ensure cargo-readme is installed, then run cargo_readme.sh

set -e

if ! cargo-readme --version >/dev/null 2>&1; then
  echo "cargo-readme not found, installing..." >&2
  cargo install cargo-readme
fi

# Run the script (which also handles marker replacement and error output)
"$(dirname "$0")/cargo_readme.sh" "$@"

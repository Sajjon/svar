#!/bin/bash

# Check for --check flag
CHECK_MODE=false
if [ "$2" = "--check" ]; then
  CHECK_MODE=true
fi

# Generate the new README content
if ! new_readme=$(cargo readme -r crates/$1 -t ../../cargo_readme_template.tpl 2>&1); then
  echo "$new_readme" >&2
  exit 1
fi

# Compare with the existing README.md
if [ -f crates/$1/README.md ]; then
  old_readme=$(cat crates/$1/README.md)
else
  old_readme=""
fi

if [ "$new_readme" != "$old_readme" ]; then
  if ! $CHECK_MODE; then
    echo "$new_readme" > crates/$1/README.md
  fi
  echo "README.md was changed. Overwritten with new content." >&2
  exit 1
else
  echo "README.md is up to date."
  exit 0
fi
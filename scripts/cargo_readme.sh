#!/bin/bash

# Check for --check flag
CHECK_MODE=false
if [ "$1" = "--check" ]; then
  CHECK_MODE=true
fi

# Generate the new README content
new_readme=$(cargo readme -r crates/core -t cargo_readme_template.tpl)

# Compare with the existing README.md
if [ -f crates/core/README.md ]; then
  old_readme=$(cat crates/core/README.md)
else
  old_readme=""
fi

if [ "$new_readme" != "$old_readme" ]; then
  if ! $CHECK_MODE; then
    echo "$new_readme" > crates/core/README.md
  fi
  echo "README.md was changed. Overwritten with new content." >&2
  exit 1
else
  echo "README.md is up to date."
  exit 0
fi
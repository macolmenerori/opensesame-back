#!/bin/sh

if ! command -v gitleaks &> /dev/null; then
  echo "gitleaks not installed. Install it with: brew install gitleaks"
  exit 1
fi

gitleaks protect --staged --redact
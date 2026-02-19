#!/bin/bash
cd /home/kavia/workspace/code-generation/event-ticketing-platform-224135-224149/tickety_backend
source venv/bin/activate
flake8 .
LINT_EXIT_CODE=$?
if [ $LINT_EXIT_CODE -ne 0 ]; then
  exit 1
fi


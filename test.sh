#!/bin/bash

# Navigate to the script's directory
cd "$(dirname "$0")"

# Activate the virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

# Set PYTHONPATH to the current directory so modules can be imported
export PYTHONPATH=.

# Run tests with coverage
echo "Running tests with coverage reporting..."
pytest --cov=. --cov-report=term-missing tests/

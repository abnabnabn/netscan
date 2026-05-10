#!/bin/bash

# Navigate to the script's directory to ensure relative paths work
cd "$(dirname "$0")"

# Activate the virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "Error: Virtual environment not found in venv/"
    exit 1
fi

# Set default Router IP if not provided in environment
if [ -z "$ROUTER_IP" ]; then
    echo "Notice: ROUTER_IP environment variable not set. Using default: 192.168.1.1"
    export ROUTER_IP="192.168.1.1"
fi

# Run the network scanner, passing all script arguments through
python3 network_scanner.py "$@"

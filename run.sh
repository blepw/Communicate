#!/bin/bash

VENV_DIR="communicate_venv"
SCRIPT="communicate.py"


if [[ ! -d "$VENV_DIR" ]]; then
    echo "Virtual environment '$VENV_DIR' not found. Creating..."
    python3 -m venv "$VENV_DIR"
    if [[ $? -ne 0 ]]; then
        echo "Error: Failed to create virtual environment."
        exit 1
    fi
    echo "Virtual environment created."
fi


if [[ ! -f "$SCRIPT" ]]; then
    echo "Error: Script '$SCRIPT' not found."
    exit 1
fi

echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"


if [[ -z "$VIRTUAL_ENV" ]]; then
    echo "Failed to activate the virtual environment."
    exit 1
fi


echo "Installing dependencies..."
pip install --upgrade pip
pip install pycryptodome colorama


echo "Running $SCRIPT..."
python3 "$SCRIPT"



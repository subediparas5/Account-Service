#!/usr/bin/env fish
set DIRECTORY virtualenvs/.py3
# Deactivate any active virtual environment
if functions -q deactivate
    deactivate
end

# Check if the directory exists and activate the virtual environment
if test -d "$DIRECTORY"
    source "$DIRECTORY/bin/activate.fish"
else
    virtualenv -p (which python3) $DIRECTORY
    echo "Virtualenv created and activated"
    source "$DIRECTORY/bin/activate.fish"
end

# Install pre-commit hooks
pre-commit install
echo "Virtualenv activated"

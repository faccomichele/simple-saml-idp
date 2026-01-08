#!/bin/bash
# Script to build Lambda layer with dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAYER_DIR="$SCRIPT_DIR/../lambda/layer"

echo "Building Lambda layer..."

# Create python directory if it doesn't exist
mkdir -p "$LAYER_DIR/python"

# Install dependencies
if [ -f "$LAYER_DIR/requirements.txt" ]; then
    pip install -r "$LAYER_DIR/requirements.txt" -t "$LAYER_DIR/python" --upgrade
    echo "Dependencies installed successfully"
else
    echo "No requirements.txt found in $LAYER_DIR"
fi

echo "Lambda layer build complete!"

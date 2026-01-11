#!/bin/bash
# Script to build Lambda functions with dependencies

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAMBDA_DIR="$SCRIPT_DIR/../lambda"

echo "Building Lambda functions..."

# Build saml_processor function
SAML_PROCESSOR_DIR="$LAMBDA_DIR/saml_processor"
if [ -f "$SAML_PROCESSOR_DIR/requirements.txt" ]; then
    echo "Installing dependencies for saml_processor..."
    pip install -r "$SAML_PROCESSOR_DIR/requirements.txt" -t "$SAML_PROCESSOR_DIR" --upgrade
    echo "saml_processor dependencies installed successfully"
else
    echo "No requirements.txt found in $SAML_PROCESSOR_DIR"
fi

# Build manage_users_roles function
MANAGE_USERS_ROLES_DIR="$LAMBDA_DIR/manage_users_roles"
if [ -f "$MANAGE_USERS_ROLES_DIR/requirements.txt" ]; then
    echo "Installing dependencies for manage_users_roles..."
    pip install -r "$MANAGE_USERS_ROLES_DIR/requirements.txt" -t "$MANAGE_USERS_ROLES_DIR" --upgrade
    echo "manage_users_roles dependencies installed successfully"
else
    echo "No requirements.txt found in $MANAGE_USERS_ROLES_DIR"
fi

# Build Lambda layer (for backward compatibility)
LAYER_DIR="$LAMBDA_DIR/layer"
if [ -f "$LAYER_DIR/requirements.txt" ]; then
    echo "Building Lambda layer..."
    mkdir -p "$LAYER_DIR/python"
    pip install -r "$LAYER_DIR/requirements.txt" -t "$LAYER_DIR/python" --upgrade
    echo "Lambda layer dependencies installed successfully"
fi

echo "Lambda functions build complete!"

#!/bin/bash
# Helper script to add a user to DynamoDB

set -e

if [ $# -lt 3 ]; then
    echo "Usage: $0 <table-name> <username> <password>"
    echo "Example: $0 simple-saml-idp-users-dev john.doe mypassword"
    exit 1
fi

TABLE_NAME=$1
USERNAME=$2
PASSWORD=$3

# Generate password hash (SHA256)
# WARNING: SHA256 is NOT SECURE for password hashing in production!
# For production use, implement bcrypt, Argon2, or scrypt with proper salt.
# This is provided as a simple example for demonstration purposes only.
PASSWORD_HASH=$(echo -n "$PASSWORD" | sha256sum | awk '{print $1}')

# Create user item
USER_ITEM=$(cat <<EOF
{
  "username": {"S": "$USERNAME"},
  "email": {"S": "$USERNAME@example.com"},
  "password_hash": {"S": "$PASSWORD_HASH"},
  "first_name": {"S": "$(echo $USERNAME | cut -d. -f1 | sed 's/\b\(.\)/\u\1/g')"},
  "last_name": {"S": "$(echo $USERNAME | cut -d. -f2 | sed 's/\b\(.\)/\u\1/g')"},
  "enabled": {"BOOL": true},
  "created_at": {"S": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
}
EOF
)

echo "Adding user $USERNAME to table $TABLE_NAME..."
aws dynamodb put-item --table-name "$TABLE_NAME" --item "$USER_ITEM"

echo "User added successfully!"
echo "Password hash: $PASSWORD_HASH"

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

# Generate password hash using bcrypt via Python
# bcrypt is a secure password hashing algorithm with automatic salting
PASSWORD_HASH=$(python3 -c "import bcrypt; print(bcrypt.hashpw('$PASSWORD'.encode('utf-8'), bcrypt.gensalt()).decode('utf-8'))")

# Create user item
# Extract first and last name safely (handle usernames with or without dots)
if [[ "$USERNAME" == *.* ]]; then
    FIRST_NAME=$(echo "$USERNAME" | cut -d. -f1 | sed 's/\b\(.\)/\u\1/g')
    LAST_NAME=$(echo "$USERNAME" | cut -d. -f2 | sed 's/\b\(.\)/\u\1/g')
else
    FIRST_NAME=$(echo "$USERNAME" | sed 's/\b\(.\)/\u\1/g')
    LAST_NAME="User"
fi

USER_ITEM=$(cat <<EOF
{
  "username": {"S": "$USERNAME"},
  "email": {"S": "$USERNAME@example.com"},
  "password_hash": {"S": "$PASSWORD_HASH"},
  "first_name": {"S": "$FIRST_NAME"},
  "last_name": {"S": "$LAST_NAME"},
  "enabled": {"BOOL": true},
  "created_at": {"S": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
}
EOF
)

echo "Adding user $USERNAME to table $TABLE_NAME..."
aws dynamodb put-item --table-name "$TABLE_NAME" --item "$USER_ITEM"

echo "User added successfully!"
echo "Password hash: $PASSWORD_HASH"

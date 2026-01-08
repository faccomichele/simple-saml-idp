#!/bin/bash
# Helper script to add a role mapping to DynamoDB

set -e

if [ $# -lt 4 ]; then
    echo "Usage: $0 <table-name> <username> <role-arn> <account-name>"
    echo "Example: $0 simple-saml-idp-roles-dev john.doe arn:aws:iam::123456789012:role/AdminRole 'Production Account'"
    exit 1
fi

TABLE_NAME=$1
USERNAME=$2
ROLE_ARN=$3
ACCOUNT_NAME=$4

# Extract account ID from ARN
ACCOUNT_ID=$(echo "$ROLE_ARN" | cut -d: -f5)

# Create role item
ROLE_ITEM=$(cat <<EOF
{
  "username": {"S": "$USERNAME"},
  "role_arn": {"S": "$ROLE_ARN"},
  "account_name": {"S": "$ACCOUNT_NAME"},
  "account_id": {"S": "$ACCOUNT_ID"},
  "description": {"S": "Role access for $USERNAME"},
  "created_at": {"S": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
}
EOF
)

echo "Adding role $ROLE_ARN for user $USERNAME to table $TABLE_NAME..."
aws dynamodb put-item --table-name "$TABLE_NAME" --item "$ROLE_ITEM"

echo "Role mapping added successfully!"

#!/bin/bash
# Script to generate SAML signing certificate and private key

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/../certs"

mkdir -p "$CERTS_DIR"

echo "Generating SAML signing certificate..."

# Generate private key
openssl genrsa -out "$CERTS_DIR/saml-private-key.pem" 2048

# Generate self-signed certificate valid for 10 years
openssl req -new -x509 -key "$CERTS_DIR/saml-private-key.pem" \
    -out "$CERTS_DIR/saml-certificate.pem" \
    -days 3650 \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=simple-saml-idp"

echo ""
echo "Certificate and key generated successfully!"
echo "Private key: $CERTS_DIR/saml-private-key.pem"
echo "Certificate: $CERTS_DIR/saml-certificate.pem"
echo ""
echo "Store these securely in AWS SSM Parameter Store:"
echo "  aws ssm put-parameter --name '/<project>/<env>/saml/private_key' \\"
echo "    --value \"\$(cat $CERTS_DIR/saml-private-key.pem)\" \\"
echo "    --type SecureString --overwrite"
echo ""
echo "  aws ssm put-parameter --name '/<project>/<env>/saml/certificate' \\"
echo "    --value \"\$(cat $CERTS_DIR/saml-certificate.pem)\" \\"
echo "    --type String --overwrite"

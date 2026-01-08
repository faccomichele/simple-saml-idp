# SSM Parameters for SAML Configuration
# These are created with placeholder values and must be updated manually after deployment
# The lifecycle ignore_changes prevents Terraform from overwriting the actual values
resource "aws_ssm_parameter" "saml_private_key" {
  name        = "/${var.project_name}/${var.environment}/saml/private_key"
  description = "SAML signing private key (RSA) - MUST be replaced with actual key after deployment"
  type        = "SecureString"
  value       = "PLACEHOLDER_REPLACE_WITH_ACTUAL_KEY"

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "${var.project_name}-saml-private-key-${var.environment}"
  }
}

resource "aws_ssm_parameter" "saml_certificate" {
  name        = "/${var.project_name}/${var.environment}/saml/certificate"
  description = "SAML signing certificate (X.509) - MUST be replaced with actual cert after deployment"
  type        = "String"
  value       = "PLACEHOLDER_REPLACE_WITH_ACTUAL_CERT"

  lifecycle {
    ignore_changes = [value]
  }

  tags = {
    Name = "${var.project_name}-saml-certificate-${var.environment}"
  }
}

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "simple-saml-idp"
}

variable "idp_entity_id" {
  description = "SAML Identity Provider Entity ID (must be a valid URL)"
  type        = string
}

variable "idp_base_url" {
  description = "Base URL for the IdP (used for ACS URL and SSO endpoints)"
  type        = string
}

variable "session_duration_seconds" {
  description = "AWS session duration in seconds (900-43200)"
  type        = number
  default     = 3600
}

variable "allowed_aws_accounts" {
  description = "List of AWS account IDs allowed for SSO"
  type        = list(string)
  default     = []
}

variable "enable_cloudfront" {
  description = "Enable CloudFront distribution for login page"
  type        = bool
  default     = true
}

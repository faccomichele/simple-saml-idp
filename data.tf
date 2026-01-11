# Data Sources
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "archive_file" "saml_processor_function" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/saml_processor"
  output_path = "${path.module}/lambda/saml_processor/lambda_function.zip"
}

data "archive_file" "manage_users_roles_function" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/manage_users_roles"
  output_path = "${path.module}/lambda/manage_users_roles/lambda_function.zip"
}

data "archive_file" "lambda_layer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/layer"
  output_path = "${path.module}/.terraform/lambda_layer.zip"
}

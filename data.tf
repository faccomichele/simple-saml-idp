# Data Sources
data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "archive_file" "lambda_function" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/function"
  output_path = "${path.module}/.terraform/lambda_function.zip"
}

data "archive_file" "lambda_layer" {
  type        = "zip"
  source_dir  = "${path.module}/lambda/layer"
  output_path = "${path.module}/.terraform/lambda_layer.zip"
}

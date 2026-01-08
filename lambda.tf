# Lambda Layer for dependencies
resource "aws_lambda_layer_version" "saml_dependencies" {
  filename            = data.archive_file.lambda_layer.output_path
  layer_name          = "${var.project_name}-dependencies-${var.environment}"
  compatible_runtimes = ["python3.11", "python3.12"]
  source_code_hash    = data.archive_file.lambda_layer.output_base64sha256

  description = "SAML and cryptography dependencies"
}

# Lambda Function for SAML Processing
resource "aws_lambda_function" "saml_processor" {
  filename         = data.archive_file.lambda_function.output_path
  function_name    = "${var.project_name}-processor-${var.environment}"
  role             = aws_iam_role.lambda_execution.arn
  handler          = "index.lambda_handler"
  source_code_hash = data.archive_file.lambda_function.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 512

  layers = [aws_lambda_layer_version.saml_dependencies.arn]

  environment {
    variables = {
      USERS_TABLE           = aws_dynamodb_table.users.name
      ROLES_TABLE           = aws_dynamodb_table.roles.name
      IDP_ENTITY_ID         = var.idp_entity_id
      IDP_BASE_URL          = var.idp_base_url
      SESSION_DURATION      = var.session_duration_seconds
      SSM_PARAMETER_PREFIX  = "/${var.project_name}/${var.environment}"
      ALLOWED_AWS_ACCOUNTS  = jsonencode(var.allowed_aws_accounts)
      SAML_PROVIDER_NAME    = var.saml_provider_name
    }
  }

  tags = {
    Name = "${var.project_name}-processor-${var.environment}"
  }
}

# Lambda Permission for API Gateway
resource "aws_lambda_permission" "api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.saml_processor.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.saml.execution_arn}/*/*"
}
